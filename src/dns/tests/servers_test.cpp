#include "dns/servers.h"

#include "doctest/doctest.h"

TEST_CASE("system_dns_servers returns unique IPv4 port-53 endpoints") {
    const auto servers = wc::dns::system_dns_servers();
    for (size_t i = 0; i < servers.size(); ++i) {
        CHECK(servers[i].sin_family == AF_INET);
        CHECK(servers[i].sin_port == htons(53));
        CHECK(servers[i].sin_addr.s_addr != INADDR_ANY);
        for (size_t j = 0; j < i; ++j) CHECK(servers[i].sin_addr.s_addr != servers[j].sin_addr.s_addr);
    }
}
