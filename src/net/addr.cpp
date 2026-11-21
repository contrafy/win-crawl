#include "net/addr.h"

#include <charconv>

namespace wc::net {

sockaddr_in make_addr(uint32_t ipv4_be, uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ipv4_be;
    return addr;
}

namespace {

// Strict decimal: no signs, no whitespace, at least one digit, value <= max.
bool parse_uint(std::string_view text, uint32_t max, uint32_t& out) {
    if (text.empty() || text.size() > 5) {
        return false;
    }
    uint32_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size() || value > max) {
        return false;
    }
    out = value;
    return true;
}

}  // namespace

bool parse_addr(std::string_view text, uint16_t default_port, sockaddr_in& out) {
    uint32_t port = default_port;
    if (const size_t colon = text.find(':'); colon != std::string_view::npos) {
        if (!parse_uint(text.substr(colon + 1), 65535, port)) {
            return false;
        }
        text = text.substr(0, colon);
    }
    uint32_t host = 0;  // host byte order while assembling
    for (int i = 0; i < 4; ++i) {
        const size_t dot = text.find('.');
        if ((i < 3) != (dot != std::string_view::npos)) {
            return false;
        }
        uint32_t octet = 0;
        if (!parse_uint(text.substr(0, dot), 255, octet)) {
            return false;
        }
        host = (host << 8) | octet;
        text = dot == std::string_view::npos ? std::string_view{} : text.substr(dot + 1);
    }
    out = make_addr(htonl(host), static_cast<uint16_t>(port));
    return true;
}

std::string ipv4_to_string(uint32_t ipv4_be) {
    const uint32_t host = ntohl(ipv4_be);
    char buf[16];
    char* p = buf;
    char* const end = buf + sizeof(buf);
    for (int shift = 24; shift >= 0; shift -= 8) {
        p = std::to_chars(p, end, (host >> shift) & 0xff).ptr;
        if (shift != 0) {
            *p++ = '.';
        }
    }
    return std::string(buf, p);
}

std::string to_string(const sockaddr_in& addr) {
    std::string out = ipv4_to_string(addr.sin_addr.s_addr);
    out += ':';
    char buf[6];
    out.append(buf, std::to_chars(buf, buf + sizeof(buf), ntohs(addr.sin_port)).ptr);
    return out;
}

}  // namespace wc::net
