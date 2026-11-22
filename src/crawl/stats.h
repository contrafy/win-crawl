#pragma once
// Crawl statistics: one counter block per event loop, written only by that
// loop's thread and read by a reporter thread.
//
// Single writer per block means increments need no lock prefix: a relaxed
// load + relaxed store of a std::atomic compiles to plain movs on x64 while
// still being a data-race-free read for the reporter. Blocks are cache-line
// aligned so loops never share a line.

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace wc::crawl {

// Order matches the --json schema (new keys are appended before the gauges).
// Gauges (set, not added) come last and are not in the JSON.
enum class Counter : uint32_t {
    UrlsRead,          // E: URLs taken from the input
    UrlsParsed,        // URLs that parsed (and match the mode's schemes)
    UniqueHosts,       // H: passed the host-uniqueness check
    DnsOk,             // D
    DnsFail,
    UniqueIps,         // I: the first host of each IP
    RobotsAttempted,
    RobotsPassed,      // R: robots allowed the page fetch
    PagesAttempted,
    PagesOk,           // C: page fetch produced a valid HTTP reply
    Http2xx,
    Http3xx,
    Http4xx,
    Http5xx,
    HttpOther,
    Links,             // L
    BytesReceived,     // every byte read from sockets (headers included)
    ConnectFail,
    Timeouts,
    TlsFail,           // every TLS failure, certificate rejections included
    TlsCertFail,       // certificate rejected by Verify::Chain (extra JSON key)
    PortExhaustion,    // connects deferred for lack of ephemeral ports (extra JSON key)
    OtherFail,         // fetches lost to resets, bad replies or the size cap (extra JSON key)
    RedirectsFollowed,
    DnsQueriesSent,    // mirrored from the loop's resolver counters
    DnsRetries,
    DnsTimeouts,
    // Politeness (docs/politeness.md).
    IpExtraHosts,      // hosts fetched beyond the first of their IP (--hosts-per-ip)
    IpBudgetSkips,     // hosts skipped by the per-IP host budget (the IP dedupe at --hosts-per-ip 1)
    IpUnreachable,     // hosts skipped because their IP stopped answering (--ip-fail-limit)
    IpBusy,            // redirects given up at an IP that is unreachable or has too many sites waiting
    CdnHosts,          // hosts fetched from IPs under the CDN limits
    PoliteWaits,       // waits for an IP: its queue or its connection spacing
    PoliteWaitMs,      // their total, ms
    CrawlDelayWaits,   // requests held back by a robots.txt Crawl-delay
    CrawlDelayMs,      // their total, ms
    CrawlDelaySkips,   // pages skipped: Crawl-delay above --max-crawl-delay
    Throttled,         // 429 and 503 replies
    RetryAfterRetries, // requests repeated after waiting out a Retry-After
    Inflight,          // gauge: live URL tasks on the loop, politeness waits included
    PoliteWaiting,     // gauge: of those, sites waiting on politeness
    Count
};

constexpr size_t kCounterCount = static_cast<size_t>(Counter::Count);

// Gauges are sampled, never summed into the JSON.
constexpr bool is_gauge(Counter c) {
    return c == Counter::Inflight || c == Counter::PoliteWaiting;
}

// JSON key for a counter ("urls_read", ...).
const char* counter_name(Counter c);

struct alignas(64) CounterBlock {
    // Rounded up to whole cache lines so the alignment needs no padding.
    static constexpr size_t kSlots = (kCounterCount + 7) / 8 * 8;
    std::atomic<uint64_t> values[kSlots] = {};

    // Owner thread only.
    void add(Counter c, uint64_t n = 1) {
        std::atomic<uint64_t>& v = values[static_cast<size_t>(c)];
        v.store(v.load(std::memory_order_relaxed) + n, std::memory_order_relaxed);
    }
    // Owner thread only.
    void set(Counter c, uint64_t n) { values[static_cast<size_t>(c)].store(n, std::memory_order_relaxed); }
    // Any thread.
    uint64_t get(Counter c) const { return values[static_cast<size_t>(c)].load(std::memory_order_relaxed); }
};

struct Snapshot {
    uint64_t values[kCounterCount] = {};
    uint64_t operator[](Counter c) const { return values[static_cast<size_t>(c)]; }
    uint64_t& operator[](Counter c) { return values[static_cast<size_t>(c)]; }
};

class Stats {
public:
    explicit Stats(size_t blocks);
    CounterBlock& block(size_t i) { return blocks_[i]; }
    size_t block_count() const { return count_; }
    // Sums every block (gauges included). Any thread.
    Snapshot snapshot() const;

private:
    std::unique_ptr<CounterBlock[]> blocks_;
    size_t count_;
};

// Facts about a finished (or interrupted) run that are not counters.
struct RunInfo {
    std::string mode;  // "classic" | "real"
    unsigned threads = 0;
    unsigned concurrency = 0;
    double elapsed_s = 0;
    uint64_t peak_inflight = 0;
    // Real mode only (unset in classic): post-quantum key exchange requested
    // (not --no-pq), and whether this process's ClientHello actually offers a
    // post-quantum group (Schannel enables them machine-wide).
    std::optional<bool> pq_requested;
    std::optional<bool> pq_offered;
};

// "[%3d] %6d Q %7d E %7d H %6d D %6d I %5d R %5d C %5d L %4dK" (no newline).
// `queued` = URLs not yet taken from the input.
std::string format_status(const Snapshot& s, double elapsed_s, uint64_t queued);
// "      *** crawling %.1f pps @ %.1f Mbps" (no newline).
// ", N waiting on politeness" is appended when sites wait on per-IP limits.
std::string format_rate(double pps, double mbps, uint64_t waiting = 0);
// Course-format summary plus the engine's extra counters; ends with '\n'.
std::string format_summary(const Snapshot& s, const RunInfo& info);
// Flat JSON object per the shared schema; ends with '\n'.
std::string format_json(const Snapshot& s, const RunInfo& info);

// Background thread that prints a status + rate line every interval and
// samples the total in-flight count often enough to report a peak.
class Reporter {
public:
    // `total_urls` is the input size (for Q). `out` == nullptr or quiet: no
    // periodic lines, peak sampling still runs.
    Reporter(const Stats& stats, uint64_t total_urls, uint32_t interval_ms, FILE* out);
    ~Reporter();
    Reporter(const Reporter&) = delete;
    Reporter& operator=(const Reporter&) = delete;

    void start();  // starts the clock and the thread
    void stop();   // joins; idempotent; freezes elapsed_s()

    double elapsed_s() const;
    uint64_t peak_inflight() const { return peak_.load(std::memory_order_relaxed); }

private:
    void run();
    double seconds_since_start() const;
    void sample_peak(const Snapshot& s);

    const Stats& stats_;
    const uint64_t total_urls_;
    const uint32_t interval_ms_;
    FILE* const out_;
    int64_t start_ticks_ = 0;
    int64_t stop_ticks_ = 0;
    int64_t freq_ = 1;
    std::atomic<uint64_t> peak_{0};
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stopping_ = false;
    std::thread thread_;
};

}  // namespace wc::crawl
