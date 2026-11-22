#include "crawl/stats.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdarg>

namespace wc::crawl {

namespace {

constexpr const char* kCounterNames[kCounterCount] = {
    "urls_read",       "urls_parsed",        "unique_hosts",     "dns_ok",      "dns_fail",
    "unique_ips",      "robots_attempted",   "robots_passed",    "pages_attempted", "pages_ok",
    "http_2xx",        "http_3xx",           "http_4xx",         "http_5xx",    "http_other",
    "links",           "bytes_received",     "connect_fail",     "timeouts",    "tls_fail",
    "tls_cert_fail",   "port_exhaustion",    "other_fail",       "redirects_followed", "dns_queries_sent",
    "dns_retries",     "dns_timeouts",
    "ip_extra_hosts",  "ip_budget_skips",    "ip_unreachable",   "ip_busy",     "cdn_hosts",
    "polite_waits",    "polite_wait_ms",     "crawl_delay_waits", "crawl_delay_ms", "crawl_delay_skips",
    "throttled",       "retry_after_retries",
    "inflight",        "polite_waiting",
};

void appendf(std::string& out, const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    const int n = std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) {
        out.append(buf, std::min(static_cast<size_t>(n), sizeof(buf) - 1));
    }
}

unsigned long long per_second(uint64_t count, double elapsed_s) {
    return elapsed_s > 0 ? static_cast<unsigned long long>(static_cast<double>(count) / elapsed_s) : 0ull;
}

int64_t ticks() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t.QuadPart;
}

}  // namespace

const char* counter_name(Counter c) {
    return kCounterNames[static_cast<size_t>(c)];
}

Stats::Stats(size_t blocks) : blocks_(new CounterBlock[blocks]), count_(blocks) {}

Snapshot Stats::snapshot() const {
    Snapshot s;
    for (size_t b = 0; b < count_; ++b) {
        for (size_t i = 0; i < kCounterCount; ++i) {
            s.values[i] += blocks_[b].values[i].load(std::memory_order_relaxed);
        }
    }
    return s;
}

std::string format_status(const Snapshot& s, double elapsed_s, uint64_t queued) {
    std::string out;
    appendf(out, "[%3d] %6llu Q %7llu E %7llu H %6llu D %6llu I %5llu R %5llu C %5llu L %4lluK",
            static_cast<int>(elapsed_s), static_cast<unsigned long long>(s[Counter::Inflight]),
            static_cast<unsigned long long>(queued), static_cast<unsigned long long>(s[Counter::UrlsRead]),
            static_cast<unsigned long long>(s[Counter::UniqueHosts]), static_cast<unsigned long long>(s[Counter::DnsOk]),
            static_cast<unsigned long long>(s[Counter::UniqueIps]),
            static_cast<unsigned long long>(s[Counter::RobotsPassed]),
            static_cast<unsigned long long>(s[Counter::PagesOk]),
            static_cast<unsigned long long>(s[Counter::Links] / 1000));
    return out;
}

std::string format_rate(double pps, double mbps, uint64_t waiting) {
    std::string out;
    appendf(out, "      *** crawling %.1f pps @ %.1f Mbps", pps, mbps);
    if (waiting != 0) {
        appendf(out, ", %llu waiting on politeness", static_cast<unsigned long long>(waiting));
    }
    return out;
}

std::string format_summary(const Snapshot& s, const RunInfo& info) {
    const double t = info.elapsed_s;
    auto u = [](uint64_t v) { return static_cast<unsigned long long>(v); };
    std::string out;
    // Wording of the first six lines follows the original assignment output.
    appendf(out, "Extracted %llu URLs @ %llu/s\n", u(s[Counter::UrlsRead]), per_second(s[Counter::UrlsRead], t));
    appendf(out, "Looked up %llu DNS names @ %llu/s\n", u(s[Counter::UniqueHosts]),
            per_second(s[Counter::UniqueHosts], t));
    appendf(out, "Attempted %llu site robots @ %llu/s\n", u(s[Counter::RobotsAttempted]),
            per_second(s[Counter::RobotsAttempted], t));
    appendf(out, "Crawled %llu pages @ %llu/s (%.2f MB)\n", u(s[Counter::PagesOk]), per_second(s[Counter::PagesOk], t),
            static_cast<double>(s[Counter::BytesReceived]) / (1024.0 * 1024.0));
    appendf(out, "Parsed %llu links @ %llu/s\n", u(s[Counter::Links]), per_second(s[Counter::Links], t));
    appendf(out, "HTTP codes: 2xx = %llu, 3xx = %llu, 4xx = %llu, 5xx = %llu, other = %llu\n", u(s[Counter::Http2xx]),
            u(s[Counter::Http3xx]), u(s[Counter::Http4xx]), u(s[Counter::Http5xx]), u(s[Counter::HttpOther]));

    const uint64_t dns_done = s[Counter::DnsOk] + s[Counter::DnsFail];
    const double dns_pct = dns_done > 0 ? 100.0 * static_cast<double>(s[Counter::DnsOk]) / static_cast<double>(dns_done) : 0.0;
    appendf(out, "\n");
    appendf(out, "Mode %s, %u threads, concurrency %u, %.1f s\n", info.mode.c_str(), info.threads, info.concurrency, t);
    appendf(out, "DNS: %llu ok, %llu failed (%.1f%% success), %llu queries sent, %llu retries, %llu timed out\n",
            u(s[Counter::DnsOk]), u(s[Counter::DnsFail]), dns_pct, u(s[Counter::DnsQueriesSent]),
            u(s[Counter::DnsRetries]), u(s[Counter::DnsTimeouts]));
    appendf(out, "Unique IPs %llu, robots passed %llu, pages attempted %llu\n", u(s[Counter::UniqueIps]),
            u(s[Counter::RobotsPassed]), u(s[Counter::PagesAttempted]));
    appendf(out, "Connect failures %llu, timeouts %llu, TLS failures %llu (%llu certificate), redirects followed %llu\n",
            u(s[Counter::ConnectFail]), u(s[Counter::Timeouts]), u(s[Counter::TlsFail]), u(s[Counter::TlsCertFail]),
            u(s[Counter::RedirectsFollowed]));
    appendf(out, "Other fetch failures (reset, bad reply, too large) %llu, port exhaustion retries %llu\n",
            u(s[Counter::OtherFail]), u(s[Counter::PortExhaustion]));
    appendf(out, "Peak in-flight %llu\n", u(info.peak_inflight));
    appendf(out,
            "Politeness: %llu hosts beyond the first per IP, %llu skipped by the per-IP budget, %llu on unreachable "
            "IPs, %llu redirects refused (busy or unreachable IP); %llu waits (%.1f s)\n",
            u(s[Counter::IpExtraHosts]), u(s[Counter::IpBudgetSkips]), u(s[Counter::IpUnreachable]),
            u(s[Counter::IpBusy]), u(s[Counter::PoliteWaits]), static_cast<double>(s[Counter::PoliteWaitMs]) / 1000.0);
    appendf(out, "Crawl-delay: %llu waits (%.1f s), %llu pages skipped; 429/503 replies %llu, Retry-After retries %llu\n",
            u(s[Counter::CrawlDelayWaits]), static_cast<double>(s[Counter::CrawlDelayMs]) / 1000.0,
            u(s[Counter::CrawlDelaySkips]), u(s[Counter::Throttled]), u(s[Counter::RetryAfterRetries]));
    if (info.pq_requested) {
        appendf(out, "Post-quantum key exchange: %s, %s\n", *info.pq_requested ? "requested" : "disabled (--no-pq)",
                info.pq_offered.value_or(false) ? "offered in the ClientHello" : "not offered in the ClientHello");
    }
    return out;
}

std::string format_json(const Snapshot& s, const RunInfo& info) {
    std::string out = "{";
    // Mode is one of two fixed identifiers, so no escaping is needed.
    appendf(out, "\"mode\":\"%s\",\"threads\":%u,\"concurrency\":%u,\"elapsed_s\":%.3f", info.mode.c_str(), info.threads,
            info.concurrency, info.elapsed_s);
    for (size_t i = 0; i < kCounterCount; ++i) {
        if (is_gauge(static_cast<Counter>(i))) {
            continue;  // the schema carries peak_inflight instead
        }
        appendf(out, ",\"%s\":%llu", kCounterNames[i], static_cast<unsigned long long>(s.values[i]));
    }
    appendf(out, ",\"peak_inflight\":%llu", static_cast<unsigned long long>(info.peak_inflight));
    const auto opt = [](const std::optional<bool>& v) { return !v ? "null" : *v ? "true" : "false"; };
    appendf(out, ",\"pq_requested\":%s,\"pq_offered\":%s,\"bot_auth\":%s}\n", opt(info.pq_requested),
            opt(info.pq_offered), info.bot_auth ? "true" : "false");
    return out;
}

Reporter::Reporter(const Stats& stats, uint64_t total_urls, uint32_t interval_ms, FILE* out)
    : stats_(stats), total_urls_(total_urls), interval_ms_(interval_ms == 0 ? 1 : interval_ms), out_(out) {
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    freq_ = f.QuadPart;
}

Reporter::~Reporter() {
    stop();
}

void Reporter::start() {
    start_ticks_ = ticks();
    stop_ticks_ = 0;
    thread_ = std::thread([this] { run(); });
}

void Reporter::stop() {
    if (!thread_.joinable()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
    }
    cv_.notify_all();
    thread_.join();
    stop_ticks_ = ticks();
    sample_peak(stats_.snapshot());
}

double Reporter::seconds_since_start() const {
    return static_cast<double>(ticks() - start_ticks_) / static_cast<double>(freq_);
}

double Reporter::elapsed_s() const {
    if (stop_ticks_ != 0) {
        return static_cast<double>(stop_ticks_ - start_ticks_) / static_cast<double>(freq_);
    }
    return start_ticks_ != 0 ? seconds_since_start() : 0.0;
}

void Reporter::sample_peak(const Snapshot& s) {
    const uint64_t inflight = s[Counter::Inflight];
    if (inflight > peak_.load(std::memory_order_relaxed)) {
        peak_.store(inflight, std::memory_order_relaxed);
    }
}

void Reporter::run() {
    // Peak in-flight is sampled every 50 ms; printing happens on interval
    // boundaries measured from start, so lines do not drift.
    const uint32_t sample_ms = std::min<uint32_t>(50, interval_ms_);
    const double interval_s = static_cast<double>(interval_ms_) / 1000.0;
    double next_print = interval_s;
    double last_print = 0.0;
    uint64_t last_pages = 0;
    uint64_t last_bytes = 0;
    std::unique_lock<std::mutex> lock(mutex_);
    while (!cv_.wait_for(lock, std::chrono::milliseconds(sample_ms), [this] { return stopping_; })) {
        const Snapshot s = stats_.snapshot();
        sample_peak(s);
        const double now = seconds_since_start();
        if (now < next_print || out_ == nullptr) {
            continue;
        }
        next_print += interval_s;
        if (next_print <= now) {
            next_print = now + interval_s;  // the thread was starved; resynchronise
        }
        const double dt = now - last_print;
        const uint64_t pages = s[Counter::PagesOk];
        const uint64_t bytes = s[Counter::BytesReceived];
        const double pps = static_cast<double>(pages - last_pages) / dt;
        const double mbps = static_cast<double>(bytes - last_bytes) * 8.0 / 1e6 / dt;
        const uint64_t taken = s[Counter::UrlsRead];
        const uint64_t queued = taken < total_urls_ ? total_urls_ - taken : 0;
        const std::string line =
            format_status(s, now, queued) + "\n" + format_rate(pps, mbps, s[Counter::PoliteWaiting]) + "\n";
        std::fwrite(line.data(), 1, line.size(), out_);
        std::fflush(out_);
        last_print = now;
        last_pages = pages;
        last_bytes = bytes;
    }
}

}  // namespace wc::crawl
