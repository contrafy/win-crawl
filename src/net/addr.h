#pragma once
// IPv4 address helpers. Convention across wincrawl: a bare IPv4 address is a
// uint32_t in network byte order (the value of in_addr::s_addr).

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace wc::net {

sockaddr_in make_addr(uint32_t ipv4_be, uint16_t port);

// Parses "a.b.c.d" or "a.b.c.d:port" (port defaults to `default_port`).
bool parse_addr(std::string_view text, uint16_t default_port, sockaddr_in& out);

std::string to_string(const sockaddr_in& addr);  // "a.b.c.d:port"
std::string ipv4_to_string(uint32_t ipv4_be);    // "a.b.c.d"

}  // namespace wc::net
