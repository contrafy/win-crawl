#pragma once
// Crawler configuration and its command line. Parsing is pure (no I/O, no
// process exit) so it is unit-testable; main() decides what to print.

#include <cstdint>
#include <string>
#include <vector>

namespace wc::crawl {

enum class Mode { Classic, Real };

const char* mode_name(Mode mode);  // "classic" | "real"

struct DnsServer {
    uint32_t ipv4_be = 0;  // network byte order
    uint16_t port = 53;    // host byte order
};

struct Config {
    Mode mode = Mode::Classic;
    std::string input_path;

    unsigned threads = 0;        // event loops; 0 until parse_args fills in logical CPUs
    unsigned concurrency = 4000; // max in-flight URL tasks, all loops together

    std::vector<DnsServer> dns_servers;  // empty: system DNS servers
    unsigned dns_inflight = 512;         // max outstanding DNS queries, all loops together
    unsigned dns_timeout_ms = 2000;      // per attempt
    unsigned dns_attempts = 3;

    unsigned connect_timeout_ms = 5000;
    unsigned timeout_ms = 10000;  // per fetch, connect included
    uint64_t robots_limit = 0;    // 0 until parse_args applies the mode default
    uint64_t page_limit = 2097152;
    bool keepalive = true;  // classic only: false = HTTP/1.0 + fresh connection per request
    bool insecure = false;  // real only: skip certificate verification
    unsigned max_redirects = 5;

    unsigned stats_interval_ms = 2000;
    std::string json_path;
    bool quiet = false;
};

// Robots body caps when --robots-limit is not given.
constexpr uint64_t kClassicRobotsLimit = 16384;
constexpr uint64_t kRealRobotsLimit = 512 * 1024;

enum class ParseStatus { Ok, Help, Error };

struct ParseResult {
    ParseStatus status = ParseStatus::Ok;
    std::string message;  // the problem when status == Error
};

// Parses argv[1..argc). On Ok every field of `out` is final (defaults resolved:
// threads = logical CPUs, robots_limit per mode). Help: -h/--help was given.
ParseResult parse_args(int argc, const char* const* argv, Config& out);

// Full --help text, ending with a newline.
std::string usage_text();

// Logical processors available to this process (at least 1).
unsigned logical_cpu_count();

}  // namespace wc::crawl
