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

    // Public resolvers by default: the OS-configured server is often a home
    // router that collapses under crawl-rate query load.
    std::vector<DnsServer> dns_servers = {DnsServer{0x01010101u, 53}, DnsServer{0x01000001u, 53}};
    bool dns_system = false;              // --dns system: the OS-configured servers instead
    unsigned dns_inflight = 2048;         // max outstanding DNS queries, all loops together
    unsigned dns_timeout_ms = 1500;       // per attempt
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
    std::string record_path;  // --record: one JSON line per unique host (record.h)
    bool https_rr = false;    // --https-rr: also query each resolved host's HTTPS RR (needs --record)
    bool post_quantum = true; // real only: offer the hybrid post-quantum TLS group (--no-pq disables)
    bool quiet = false;
};

// Robots body caps when --robots-limit is not given.
constexpr uint64_t kClassicRobotsLimit = 16384;
constexpr uint64_t kRealRobotsLimit = 512 * 1024;

enum class ParseStatus { Ok, Help, Error };

struct ParseResult {
    ParseStatus status = ParseStatus::Ok;
    std::string message;              // the problem when status == Error
    std::vector<std::string> notes;   // adjustments worth telling the user on Ok
};

// Total DNS in-flight cap applied with --dns system unless --dns-inflight is given.
constexpr unsigned kSystemDnsInflight = 64;

// Parses argv[1..argc). On Ok every field of `out` is final (defaults resolved:
// threads = logical CPUs, robots_limit per mode). Help: -h/--help was given.
ParseResult parse_args(int argc, const char* const* argv, Config& out);

// Full --help text, ending with a newline.
std::string usage_text();

// Logical processors available to this process (at least 1).
unsigned logical_cpu_count();

}  // namespace wc::crawl
