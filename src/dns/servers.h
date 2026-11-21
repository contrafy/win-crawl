#pragma once
// Discovery of the system's configured DNS servers.

#include <winsock2.h>
#include <ws2tcpip.h>

#include <vector>

namespace wc::dns {

// IPv4 DNS servers (port 53) of every adapter that is operationally up, in
// adapter order, deduplicated. Empty on failure.
std::vector<sockaddr_in> system_dns_servers();

}  // namespace wc::dns
