#include "crawl/tests/fake_servers.h"

#include "net/addr.h"

#include <windows.h>

#include <future>

namespace wc::crawl::test {

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c + ('a' - 'A'));
        }
    }
    return out;
}

const char* reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    default: return "Status";
    }
}

}  // namespace

uint32_t loopback_ip(uint8_t n) {
    return htonl(0x7f000000u | n);
}

bool run_until(net::Loop& loop, const std::function<bool()>& done, uint32_t timeout_ms) {
    bool timed_out = false;
    net::TimerId poll_id = 0;
    const net::TimerId watchdog = loop.add_timer(timeout_ms, [&] {
        timed_out = true;
        loop.stop();
    });
    std::function<void()> poll = [&] {
        if (done()) {
            loop.stop();
        } else {
            poll_id = loop.add_timer(1, poll);
        }
    };
    poll_id = loop.add_timer(0, poll);
    loop.run();
    loop.cancel_timer(watchdog);
    loop.cancel_timer(poll_id);
    return !timed_out;
}

// ---------------------------------------------------------------- ServerThread

ServerThread::ServerThread() : thread_([this] { loop_.run(); }) {}

ServerThread::~ServerThread() {
    loop_.stop();
    thread_.join();
}

void ServerThread::call(const std::function<void()>& fn) {
    std::promise<void> done;
    loop_.post([&] {
        fn();
        done.set_value();
    });
    done.get_future().wait();
}

void ServerThread::wait_idle(const std::function<bool()>& busy) {
    for (;;) {
        bool b = false;
        call([&] { b = busy(); });
        if (!b) {
            return;
        }
        Sleep(1);
    }
}

// ---------------------------------------------------------------- FakeDns

FakeDns::FakeDns(ServerThread& thread) : thread_(thread) {}

FakeDns::~FakeDns() {
    if (!socket_) {
        return;
    }
    thread_.call([this] { socket_->close(); });
    thread_.wait_idle([this] { return socket_->busy(); });
    thread_.call([this] { socket_.reset(); });
}

void FakeDns::add(const std::string& host, uint32_t ipv4_be) {
    records_[lower(host)] = ipv4_be;
}

void FakeDns::add_https(const std::string& host, std::string rdata) {
    https_[lower(host)] = std::move(rdata);
}

uint16_t FakeDns::start() {
    uint16_t port = 0;
    thread_.call([&] {
        net::UdpHandler& handler = *this;
        socket_ = std::make_unique<net::UdpSocket>(thread_.loop(), handler);
        if (socket_->open(net::make_addr(loopback_ip(1), 0)) == 0) {
            port = ntohs(socket_->local_address().sin_port);
        }
    });
    return port;
}

void FakeDns::on_datagram(net::UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) {
    if (len < 12) {
        return;
    }
    const auto* p = reinterpret_cast<const uint8_t*>(data);
    size_t pos = 12;
    std::string name;
    while (pos < len && p[pos] != 0) {
        const size_t label = p[pos];
        if (label > 63 || pos + 1 + label > len) {
            return;
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        name.append(data + pos + 1, label);
        pos += 1 + label;
    }
    if (pos + 5 > len) {
        return;
    }
    pos += 1;  // root label
    const uint16_t qtype = static_cast<uint16_t>(p[pos] << 8 | p[pos + 1]);
    pos += 4;
    ++queries_;

    std::string out(data, pos);  // header + question
    const std::string key = lower(name);
    const auto it = records_.find(key);
    const auto https = https_.find(key);
    const bool a_answer = it != records_.end() && qtype == 1;
    const bool https_answer = it != records_.end() && qtype == 65 && https != https_.end();
    out[2] = static_cast<char>(0x80 | (p[2] & 0x78) | 0x04 | (p[2] & 0x01));  // QR, opcode, AA, RD
    out[3] = static_cast<char>(0x80 | (it == records_.end() ? 3 : 0));       // RA, NXDOMAIN/NOERROR
    out[4] = 0;
    out[5] = 1;
    out[6] = 0;
    out[7] = a_answer || https_answer ? 1 : 0;
    out[8] = out[9] = out[10] = out[11] = 0;
    if (a_answer) {
        const char rr[] = {'\xc0', '\x0c', 0, 1, 0, 1, 0, 0, 0, 60, 0, 4};
        out.append(rr, sizeof(rr));
        out.append(reinterpret_cast<const char*>(&it->second), 4);
    } else if (https_answer) {
        const std::string& rdata = https->second;
        const char rr[] = {'\xc0', '\x0c', 0, 65, 0, 1, 0, 0, 0, 60};
        out.append(rr, sizeof(rr));
        out.push_back(static_cast<char>(rdata.size() >> 8));
        out.push_back(static_cast<char>(rdata.size() & 0xff));
        out.append(rdata);
    }
    socket.send_to(from, out.data(), out.size());
}

// ---------------------------------------------------------------- HTTP replies

std::string reply(int status, std::string_view body, std::string_view extra_headers, bool close) {
    std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason(status) + "\r\n";
    out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    out.append(extra_headers);
    if (close) {
        out += "Connection: close\r\n";
    }
    out += "\r\n";
    out.append(body);
    return out;
}

std::string chunked_reply(int status, const std::vector<std::string>& chunks, std::string_view extra_headers) {
    std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason(status) + "\r\n";
    out += "Transfer-Encoding: chunked\r\n";
    out.append(extra_headers);
    out += "\r\n";
    char size[32];
    for (const std::string& c : chunks) {
        std::snprintf(size, sizeof(size), "%zx\r\n", c.size());
        out += size;
        out += c;
        out += "\r\n";
    }
    out += "0\r\n\r\n";
    return out;
}

// ---------------------------------------------------------------- FakeHttp

struct FakeHttp::Listener {
    uint32_t ip = 0;
    std::unique_ptr<net::TcpListener> listener;
    std::atomic<uint64_t> accepts{0};
};

class FakeHttp::Conn final : private net::TcpHandler {
public:
    Conn(FakeHttp& server, net::Loop& loop) : server_(server), loop_(loop), socket_(loop, *this) {}

    void adopt(SOCKET s) {
        if (socket_.adopt(s) == 0) {
            recv();
        }
    }
    void abort() {
        if (timer_ != 0) {
            loop_.cancel_timer(timer_);
            timer_ = 0;
        }
        if (socket_.is_open()) {
            socket_.close(true);
        }
    }
    bool busy() const { return socket_.busy(); }

private:
    void recv() {
        if (!receiving_) {
            receiving_ = true;
            socket_.recv(buf_, sizeof(buf_));
        }
    }

    void on_connect(net::TcpSocket&, DWORD) override {}

    void on_recv(net::TcpSocket&, size_t bytes, DWORD error) override {
        receiving_ = false;
        if (error != 0 || bytes == 0) {
            abort();
            return;
        }
        if (half_closed_) {
            return;  // nothing more is served after a close
        }
        in_.append(buf_, bytes);
        process();
        if (socket_.is_open() && !receiving_) {
            recv();
        }
    }

    void process() {
        if (busy_reply_ || !socket_.is_open()) {
            return;
        }
        const size_t end = in_.find("\r\n\r\n");
        if (end == std::string::npos) {
            return;
        }
        const std::string head = in_.substr(0, end + 2);
        in_.erase(0, end + 4);

        const size_t sp1 = head.find(' ');
        const size_t sp2 = head.find(' ', sp1 + 1);
        const size_t eol = head.find("\r\n");
        const std::string method = head.substr(0, sp1);
        const std::string path = head.substr(sp1 + 1, sp2 - sp1 - 1);
        const std::string version = head.substr(sp2 + 1, eol - sp2 - 1);
        std::string host;
        bool client_close = version == "HTTP/1.0";
        size_t line = eol + 2;
        while (line < head.size()) {
            const size_t next = head.find("\r\n", line);
            const std::string field = lower(head.substr(line, next - line));
            if (field.rfind("host:", 0) == 0) {
                host = field.substr(5);
                host.erase(0, host.find_first_not_of(' '));
                host = host.substr(0, host.find(':'));
            } else if (field.rfind("connection:", 0) == 0) {
                client_close = field.find("close") != std::string::npos;
            }
            line = next + 2;
        }
        server_.count(host, path);

        static const Route not_found{reply(404, "")};
        const Route* route = server_.find(host, path);
        if (route == nullptr) {
            route = &not_found;
        }
        if (route->hang) {
            busy_reply_ = true;  // never answer; the client times out and resets
            return;
        }
        out_ = route->response;
        if (method == "HEAD") {
            const size_t h = out_.find("\r\n\r\n");
            if (h != std::string::npos) {
                out_.resize(h + 4);
            }
        }
        close_after_ = route->close_after || client_close;
        busy_reply_ = true;
        if (route->delay_ms > 0) {
            timer_ = loop_.add_timer(route->delay_ms, [this] {
                timer_ = 0;
                socket_.send(out_.data(), out_.size());
            });
        } else {
            socket_.send(out_.data(), out_.size());
        }
    }

    void on_send(net::TcpSocket&, DWORD error) override {
        busy_reply_ = false;
        if (error != 0) {
            abort();
            return;
        }
        if (close_after_) {
            // Half-close: FIN now, full close once the client closes. Closing
            // outright with a receive pending would reset the connection.
            ::shutdown(socket_.native_handle(), SD_SEND);
            half_closed_ = true;
            return;
        }
        process();  // a pipelined or next keep-alive request
    }

    FakeHttp& server_;
    net::Loop& loop_;
    net::TcpSocket socket_;
    char buf_[4096];
    std::string in_;
    std::string out_;
    bool receiving_ = false;
    bool busy_reply_ = false;
    bool close_after_ = false;
    bool half_closed_ = false;
    net::TimerId timer_ = 0;
};

FakeHttp::FakeHttp(ServerThread& thread) : thread_(thread) {}

FakeHttp::~FakeHttp() {
    thread_.call([this] {
        for (auto& l : listeners_) {
            l->listener->close();
        }
        for (auto& c : conns_) {
            c->abort();
        }
    });
    thread_.wait_idle([this] {
        for (auto& l : listeners_) {
            if (l->listener->busy()) {
                return true;
            }
        }
        for (auto& c : conns_) {
            if (c->busy()) {
                return true;
            }
        }
        return false;
    });
    thread_.call([this] {
        conns_.clear();
        listeners_.clear();
    });
}

uint16_t FakeHttp::listen(uint32_t ipv4_be) {
    uint16_t port = 0;
    thread_.call([&] {
        auto l = std::make_unique<Listener>();
        Listener* raw = l.get();
        l->ip = ipv4_be;
        l->listener = std::make_unique<net::TcpListener>(thread_.loop(), [this, raw](SOCKET s) {
            ++raw->accepts;
            conns_.push_back(std::make_unique<Conn>(*this, thread_.loop()));
            conns_.back()->adopt(s);
        });
        if (l->listener->listen(net::make_addr(ipv4_be, 0), SOMAXCONN, 8) == 0) {
            port = ntohs(l->listener->local_address().sin_port);
        }
        listeners_.push_back(std::move(l));
    });
    return port;
}

void FakeHttp::route(const std::string& host, const std::string& path, Route r) {
    routes_[lower(host) + " " + path] = std::move(r);
}

const Route* FakeHttp::find(const std::string& host, const std::string& path) const {
    const auto it = routes_.find(host + " " + path);
    return it == routes_.end() ? nullptr : &it->second;
}

void FakeHttp::count(const std::string& host, const std::string& path) {
    ++total_requests_;
    std::lock_guard<std::mutex> lock(mutex_);
    ++hits_[host + " " + path];
}

uint64_t FakeHttp::accepts(uint32_t ipv4_be) const {
    uint64_t n = 0;
    for (const auto& l : listeners_) {
        if (l->ip == ipv4_be) {
            n += l->accepts.load();
        }
    }
    return n;
}

uint64_t FakeHttp::requests(const std::string& host, const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = hits_.find(lower(host) + " " + path);
    return it == hits_.end() ? 0 : it->second;
}

}  // namespace wc::crawl::test
