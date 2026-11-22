#pragma once
// Deterministic behaviour model shared by the fake DNS server, the fake HTTP
// server and the URL generator. Every decision is a pure function of
// (seed, host number N, request path), so two runs with the same options see
// exactly the same world and the crawler's counters are reproducible.
//
// Host naming: host N is "h<N>.<zone>". Its unique address is 127.0.0.0/8
// offset by N + 1 (so N = 0 -> 127.0.0.1), which lets the HTTP server recover
// N from an IP-literal Host header or from the local address a client hit.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace wc::benchsrv {

// Uniform delay in [mean - jitter, mean + jitter] milliseconds (clamped at 0).
struct Delay {
    uint32_t mean_ms = 0;
    uint32_t jitter_ms = 0;

    bool enabled() const { return mean_ms != 0 || jitter_ms != 0; }
    uint32_t pick(uint64_t hash) const;
};

// Parses "mean" or "mean,jitter".
bool parse_delay(std::string_view text, Delay& out);

struct Behavior {
    std::string zone = "bench.test";  // lowercase, no trailing dot
    uint64_t seed = 0;

    // DNS
    double ip_share = 0.2;   // fraction of hosts whose A record repeats an earlier host's
    double nxdomain = 0.1;   // fraction of hosts answered NXDOMAIN
    Delay dns_delay;

    // HTTP
    double robots_404 = 0.6;    // fraction of hosts without robots.txt (crawlable in classic mode)
    uint32_t page_kb = 32;      // mean page body size
    uint32_t links = 30;        // links per page body
    double redirect = 0.05;     // page fractions answered 301 / 404 / 503
    double not_found = 0.05;
    double server_error = 0.02;
    double chunked = 0.1;       // fraction of 200 pages sent with chunked encoding
    Delay http_delay;

    // Politeness (docs/politeness.md): worlds with many hosts per IP,
    // Crawl-delays and rate limiting.
    uint32_t ip_pool = 0;        // > 0: host N resolves to host_unique_ip(N % ip_pool) (overrides ip_share)
    double crawl_delay = 0;      // fraction of hosts whose robots.txt (when present) has a Crawl-delay
    uint32_t crawl_delay_s = 1;  // its value, seconds
    double throttle = 0;         // fraction of hosts whose first page request gets 429
    uint32_t retry_after_s = 1;  // the Retry-After of that 429
};

// Number of pre-generated page templates; template sizes average page_kb.
inline constexpr uint32_t kPageTemplates = 8;

// splitmix64 finaliser: a cheap, well-mixed 64-bit hash.
uint64_t mix64(uint64_t x);
// Uniform double in [0, 1) for the decision `salt` about item `n`.
double unit(uint64_t seed, uint64_t n, uint64_t salt);
uint64_t fnv1a(std::string_view text);

// 127.0.0.0/8 address for host N (network byte order); wraps every 2^24 - 2 hosts.
uint32_t host_unique_ip(uint64_t n);
// Inverse of host_unique_ip for 127/8 addresses; nullopt for anything else.
std::optional<uint64_t> ip_host_number(uint32_t ipv4_be);

// "h<N>.<zone>" (case-insensitive, optional trailing dot) -> N.
std::optional<uint64_t> parse_host_name(std::string_view name, std::string_view zone);
// Host header value ("h7.bench.test:8080", "127.0.0.8", ...) -> N. IP literals
// map through ip_host_number; unrecognised names fall back to a hash of the name.
std::optional<uint64_t> host_header_number(std::string_view host, std::string_view zone);

// --- DNS decisions -------------------------------------------------------
bool host_nxdomain(const Behavior& b, uint64_t n);
bool host_shares_ip(const Behavior& b, uint64_t n);
// A record for host N: shared hosts reuse the address of the nearest lower,
// non-sharing host, so about `ip_share` of hosts duplicate an existing IP.
uint32_t host_ip(const Behavior& b, uint64_t n);
uint32_t dns_delay_ms(const Behavior& b, uint64_t key);

// --- HTTP decisions ------------------------------------------------------
bool robots_missing(const Behavior& b, uint64_t n);
// The host's robots.txt (when present) asks for Crawl-delay: crawl_delay_s.
bool host_crawl_delay(const Behavior& b, uint64_t n);
// The host answers its first page request 429 with Retry-After: retry_after_s.
bool host_throttled(const Behavior& b, uint64_t n);

enum class PageKind : uint8_t { Ok, Redirect, NotFound, ServerError };

struct PagePlan {
    PageKind kind = PageKind::Ok;
    uint32_t template_index = 0;
    bool chunked = false;
};

// Paths under /r/ (redirect targets) are always 200 so redirects terminate.
PagePlan page_plan(const Behavior& b, uint64_t n, std::string_view target);
uint32_t http_delay_ms(const Behavior& b, uint64_t n, std::string_view target);

}  // namespace wc::benchsrv
