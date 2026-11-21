#include "dns/servers.h"

#include <iphlpapi.h>

#include <memory>

namespace wc::dns {

std::vector<sockaddr_in> system_dns_servers() {
    std::vector<sockaddr_in> servers;
    constexpr ULONG kFlags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                             GAA_FLAG_SKIP_FRIENDLY_NAME;

    // The adapter list can grow between the sizing call and the real one.
    ULONG size = 16 * 1024;
    std::unique_ptr<unsigned char[]> buffer;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer = std::make_unique<unsigned char[]>(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()),
                                  &size);
    }
    if (rc != NO_ERROR) return servers;

    for (auto* adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.get()); adapter != nullptr;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        for (auto* dns = adapter->FirstDnsServerAddress; dns != nullptr; dns = dns->Next) {
            const SOCKADDR* sa = dns->Address.lpSockaddr;
            if (sa == nullptr || sa->sa_family != AF_INET ||
                dns->Address.iSockaddrLength < static_cast<int>(sizeof(sockaddr_in)))
                continue;
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr = reinterpret_cast<const sockaddr_in*>(sa)->sin_addr;
            if (addr.sin_addr.s_addr == INADDR_ANY) continue;
            addr.sin_port = htons(53);
            bool seen = false;
            for (const auto& s : servers) seen = seen || s.sin_addr.s_addr == addr.sin_addr.s_addr;
            if (!seen) servers.push_back(addr);
        }
    }
    return servers;
}

}  // namespace wc::dns
