#pragma once
// Benchmark input generator: "http://h<N>.<zone>:<port>/p/<k>" lines, or with
// ip_literal "http://127.a.b.c:<port>/p/<k>" (host_unique_ip(N)) for crawlers
// that can only use system DNS. A `dup_hosts` fraction of lines repeats an
// earlier host so host-dedupe does real work. Deterministic per seed.

#include <cstdint>
#include <string>

namespace wc::benchsrv {

struct UrlGenOptions {
    uint64_t count = 0;
    double dup_hosts = 0.1;
    uint16_t port = 8080;
    bool ip_literal = false;
    std::string zone = "bench.test";
    uint64_t seed = 0;
};

// Appends URL number `index` (0-based) plus '\n' to `out`. `next_host` is the
// generator state: the number of distinct hosts emitted so far (start at 0).
void append_url(const UrlGenOptions& options, uint64_t index, uint64_t& next_host, std::string& out);

// Writes options.count lines to `path`. Returns false and fills `error` on I/O failure.
bool write_url_file(const UrlGenOptions& options, const std::string& path, std::string* error,
                    uint64_t* unique_hosts = nullptr);

}  // namespace wc::benchsrv
