#pragma once
// Blocking WinSock clients for the server tests. Deliberately independent of
// wc_net so the tests exercise the servers from the outside.

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace wc::benchsrv::test {

class RawSocket {
public:
    RawSocket() = default;
    explicit RawSocket(SOCKET s) : s_(s) {}
    ~RawSocket() { reset(); }
    RawSocket(const RawSocket&) = delete;
    RawSocket& operator=(const RawSocket&) = delete;
    RawSocket(RawSocket&& o) noexcept : s_(o.s_) { o.s_ = INVALID_SOCKET; }

    SOCKET get() const { return s_; }
    void reset() {
        if (s_ != INVALID_SOCKET) closesocket(s_);
        s_ = INVALID_SOCKET;
    }

private:
    SOCKET s_ = INVALID_SOCKET;
};

inline void set_timeout(SOCKET s, DWORD ms) {
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
}

inline sockaddr_in loopback(uint16_t port_host_order) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port_host_order);
    return a;
}

// --- DNS -----------------------------------------------------------------

inline std::string make_query(uint16_t id, std::string_view name, uint16_t qtype) {
    std::string q;
    q.push_back(static_cast<char>(id >> 8));
    q.push_back(static_cast<char>(id & 0xFF));
    q += std::string("\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);  // RD, QDCOUNT=1
    size_t pos = 0;
    while (pos < name.size()) {
        size_t dot = name.find('.', pos);
        if (dot == std::string_view::npos) dot = name.size();
        q.push_back(static_cast<char>(dot - pos));
        q.append(name.substr(pos, dot - pos));
        pos = dot + 1;
    }
    q.push_back('\0');
    q.push_back(static_cast<char>(qtype >> 8));
    q.push_back(static_cast<char>(qtype & 0xFF));
    q += std::string("\x00\x01", 2);
    return q;
}

struct DnsReply {
    bool ok = false;  // a reply arrived
    uint16_t id = 0;
    uint16_t flags = 0;
    uint16_t ancount = 0;
    uint32_t ipv4_be = 0;  // first A record
    int rcode() const { return flags & 0xF; }
};

inline uint16_t be16(const char* p) {
    return static_cast<uint16_t>((static_cast<unsigned char>(p[0]) << 8) | static_cast<unsigned char>(p[1]));
}

inline DnsReply parse_reply(const char* p, size_t n) {
    DnsReply r;
    if (n < 12) return r;
    r.ok = true;
    r.id = be16(p);
    r.flags = be16(p + 2);
    r.ancount = be16(p + 6);
    // Skip the question (uncompressed name) then read the answer's RDATA.
    size_t pos = 12;
    while (pos < n && p[pos] != 0) pos += static_cast<unsigned char>(p[pos]) + 1;
    pos += 5;
    if (r.ancount > 0 && pos + 16 <= n) {
        std::memcpy(&r.ipv4_be, p + pos + 12, 4);
    }
    return r;
}

class UdpClient {
public:
    explicit UdpClient(DWORD timeout_ms = 2000) : s_(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) {
        set_timeout(s_.get(), timeout_ms);
    }
    bool send(const sockaddr_in& to, const std::string& data) {
        return sendto(s_.get(), data.data(), static_cast<int>(data.size()), 0, reinterpret_cast<const sockaddr*>(&to),
                      sizeof(to)) == static_cast<int>(data.size());
    }
    DnsReply receive() {
        char buf[1500];
        const int n = recv(s_.get(), buf, sizeof(buf), 0);
        if (n <= 0) return {};
        return parse_reply(buf, static_cast<size_t>(n));
    }

private:
    RawSocket s_;
};

// --- HTTP ----------------------------------------------------------------

inline RawSocket tcp_connect(const sockaddr_in& to, DWORD timeout_ms = 3000) {
    RawSocket s(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    set_timeout(s.get(), timeout_ms);
    if (::connect(s.get(), reinterpret_cast<const sockaddr*>(&to), sizeof(to)) != 0) s.reset();
    return s;
}

inline bool send_all(SOCKET s, std::string_view data) {
    while (!data.empty()) {
        const int n = ::send(s, data.data(), static_cast<int>(data.size()), 0);
        if (n <= 0) return false;
        data.remove_prefix(static_cast<size_t>(n));
    }
    return true;
}

struct HttpReply {
    bool ok = false;
    int status = 0;
    std::string head;   // status line + headers
    std::string body;   // decoded
    bool chunked = false;
    bool framing_error = false;

    std::string header(std::string_view name) const {
        size_t pos = head.find("\r\n");
        while (pos != std::string::npos && pos + 2 < head.size()) {
            const size_t start = pos + 2;
            const size_t eol = head.find("\r\n", start);
            std::string_view line(head.data() + start, (eol == std::string::npos ? head.size() : eol) - start);
            const size_t colon = line.find(':');
            if (colon == name.size() && _strnicmp(line.data(), name.data(), name.size()) == 0) {
                std::string_view v = line.substr(colon + 1);
                while (!v.empty() && v.front() == ' ') v.remove_prefix(1);
                return std::string(v);
            }
            pos = eol;
        }
        return {};
    }
};

// Reads responses from a connection, keeping leftover bytes between calls so
// pipelined responses split correctly.
class HttpReader {
public:
    explicit HttpReader(SOCKET s) : s_(s) {}

    // Reads one response. `head_request` = the request was HEAD (no body).
    HttpReply read(bool head_request = false) {
        HttpReply r;
        size_t end;
        while ((end = buf_.find("\r\n\r\n")) == std::string::npos) {
            if (!fill()) return r;
        }
        r.head = buf_.substr(0, end + 2);
        buf_.erase(0, end + 4);
        if (r.head.size() < 12 || r.head.compare(0, 7, "HTTP/1.") != 0) return r;
        r.status = std::stoi(r.head.substr(9, 3));
        r.ok = true;
        if (head_request) return r;
        const std::string te = r.header("Transfer-Encoding");
        if (te == "chunked") {
            r.chunked = true;
            for (;;) {
                size_t eol;
                while ((eol = buf_.find("\r\n")) == std::string::npos) {
                    if (!fill()) return fail(r);
                }
                const size_t n = std::stoul(buf_.substr(0, eol), nullptr, 16);
                buf_.erase(0, eol + 2);
                while (buf_.size() < n + 2) {
                    if (!fill()) return fail(r);
                }
                if (buf_.compare(n, 2, "\r\n") != 0) return fail(r);
                r.body.append(buf_, 0, n);
                buf_.erase(0, n + 2);
                if (n == 0) return r;
            }
        }
        const std::string cl = r.header("Content-Length");
        if (!cl.empty()) {
            const size_t n = std::stoul(cl);
            while (buf_.size() < n) {
                if (!fill()) return fail(r);
            }
            r.body = buf_.substr(0, n);
            buf_.erase(0, n);
            return r;
        }
        while (fill()) {
        }
        r.body = std::move(buf_);
        buf_.clear();
        return r;
    }

    // True when the peer closed (FIN or RST) with no further data within the timeout.
    bool at_eof() {
        if (!buf_.empty()) return false;
        char c;
        const int n = recv(s_, &c, 1, 0);
        if (n == 0) return true;
        if (n < 0) return WSAGetLastError() == WSAECONNRESET;
        buf_.push_back(c);
        return false;
    }

    // True only for an orderly FIN (recv == 0), not a reset.
    bool clean_eof() {
        if (!buf_.empty()) return false;
        char c;
        return recv(s_, &c, 1, 0) == 0;
    }

    size_t buffered() const { return buf_.size(); }

private:
    bool fill() {
        char tmp[16384];
        const int n = recv(s_, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;
        buf_.append(tmp, static_cast<size_t>(n));
        return true;
    }
    static HttpReply fail(HttpReply& r) {
        r.framing_error = true;
        r.ok = false;
        return r;
    }

    SOCKET s_;
    std::string buf_;
};

}  // namespace wc::benchsrv::test
