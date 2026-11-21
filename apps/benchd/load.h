#pragma once
// Closed-loop HTTP load generator used to measure the fake server's capacity
// (`wincrawl-benchd load`). Each connection sends one request, waits for the
// complete response, then sends the next (keep-alive) or resets and reconnects
// (--close).

#include <winsock2.h>

#include <cstdint>
#include <string>

namespace wc::benchd {

struct LoadOptions {
    sockaddr_in target{};  // port is used; the address too unless spread_ips
    uint32_t threads = 4;
    uint32_t connections = 256;  // total across threads
    uint32_t duration_s = 10;
    uint32_t stats_interval_ms = 1000;
    bool close = false;  // Connection: close + reconnect per request
    bool head = false;
    std::string path = "/robots.txt";
    uint64_t hosts = 100000;  // Host header h<N> cycles over this many hosts
    bool spread_ips = true;   // connect to host_unique_ip(N) (needs a 0.0.0.0 server)
    std::string zone = "bench.test";
};

int run_load(const LoadOptions& options);

}  // namespace wc::benchd
