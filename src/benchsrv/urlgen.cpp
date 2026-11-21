#include "benchsrv/urlgen.h"

#include "benchsrv/behavior.h"

#include <winsock2.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace wc::benchsrv {

namespace {
constexpr uint64_t kSaltDup = 0x6475706C686F7374ULL;
constexpr uint64_t kSaltPick = 0x7069636B686F7374ULL;
constexpr uint64_t kSaltPath = 0x7061746870617468ULL;
}  // namespace

void append_url(const UrlGenOptions& options, uint64_t index, uint64_t& next_host, std::string& out) {
    uint64_t host;
    if (next_host > 0 && unit(options.seed, index, kSaltDup) < options.dup_hosts) {
        host = mix64(mix64(options.seed ^ kSaltPick) ^ index) % next_host;
    } else {
        host = next_host++;
    }
    const unsigned page = static_cast<unsigned>(mix64(mix64(options.seed ^ kSaltPath) ^ index) % 1000000);
    char buf[160];
    int n;
    if (options.ip_literal) {
        const uint32_t ip = ntohl(host_unique_ip(host));
        n = std::snprintf(buf, sizeof(buf), "http://%u.%u.%u.%u:%u/p/%u\n", ip >> 24, (ip >> 16) & 0xFF,
                          (ip >> 8) & 0xFF, ip & 0xFF, options.port, page);
    } else {
        n = std::snprintf(buf, sizeof(buf), "http://h%llu.%s:%u/p/%u\n", static_cast<unsigned long long>(host),
                          options.zone.c_str(), options.port, page);
    }
    if (n > 0) out.append(buf, static_cast<size_t>(n) < sizeof(buf) ? static_cast<size_t>(n) : sizeof(buf) - 1);
}

bool write_url_file(const UrlGenOptions& options, const std::string& path, std::string* error,
                    uint64_t* unique_hosts) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (f == nullptr) {
        if (error) *error = "cannot open " + path + ": " + std::strerror(errno);
        return false;
    }
    std::string block;
    block.reserve(1 << 20);
    uint64_t next_host = 0;
    bool ok = true;
    for (uint64_t i = 0; i < options.count && ok; ++i) {
        append_url(options, i, next_host, block);
        if (block.size() >= (1 << 20) - 256 || i + 1 == options.count) {
            ok = std::fwrite(block.data(), 1, block.size(), f) == block.size();
            block.clear();
        }
    }
    ok = (std::fclose(f) == 0) && ok;
    if (!ok && error) *error = "write failed: " + path;
    if (unique_hosts) *unique_hosts = next_host;
    return ok;
}

}  // namespace wc::benchsrv
