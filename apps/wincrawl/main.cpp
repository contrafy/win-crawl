// wincrawl: command-line front end of the crawl engine.
// Exit codes: 0 run completed, 1 fatal error, 2 usage error, 130 interrupted.

#include "crawl/config.h"
#include "crawl/engine.h"
#include "crawl/input.h"
#include "crawl/stats.h"
#include "net/addr.h"
#include "tls/tls.h"

#include <windows.h>

#include <atomic>
#include <mutex>
#include <cstdio>
#include <string>

using namespace wc::crawl;

namespace {

// The handler runs on a system thread that SetConsoleCtrlHandler(..., FALSE) does
// not wait for, so main clears g_engine under the same lock before the Engine dies.
std::mutex g_engine_mutex;
Engine* g_engine = nullptr;
std::atomic<int> g_interrupts{0};

// Runs on a system-created thread. The first Ctrl+C drains the crawl and still
// prints the summary; a second one falls through to the default handler,
// which terminates the process.
BOOL WINAPI on_console_ctrl(DWORD type) {
    if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT) {
        return FALSE;
    }
    if (g_interrupts.fetch_add(1) > 0) {
        return FALSE;
    }
    std::lock_guard lock(g_engine_mutex);
    if (g_engine != nullptr) {
        g_engine->request_stop();
    }
    return TRUE;
}

bool write_file(const std::string& path, const std::string& text) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (f == nullptr) {
        return false;
    }
    const bool ok = std::fwrite(text.data(), 1, text.size(), f) == text.size();
    return std::fclose(f) == 0 && ok;
}

std::string limit(uint32_t v, const char* unit) {
    return v == 0 ? "unlimited " + std::string(unit) : std::to_string(v) + " " + unit;
}

// What --hosts-per-ip and friends resolved to, per IP class.
void print_politeness(const Config& cfg) {
    const GatePolicy p = gate_policy(cfg);
    std::printf("Politeness: %s, %s per IP, %u ms apart", limit(p.ip.hosts, "hosts").c_str(),
                limit(p.ip.concurrency, "connections").c_str(), p.ip.interval_ms);
    if (p.cdn_ranges != nullptr) {
        std::printf("; Cloudflare IPs: %s, %s, %u ms apart", limit(p.cdn.hosts, "hosts").c_str(),
                    limit(p.cdn.concurrency, "connections").c_str(), p.cdn.interval_ms);
    }
    std::printf("\n            ");
    if (p.fail_limit != 0) {
        std::printf("IPs skipped after %u failed connections in a row", p.fail_limit);
    } else {
        std::printf("IPs never skipped for failing");
    }
    if (cfg.mode == Mode::Real) {
        std::printf("; Crawl-delay honoured up to %u s, Retry-After up to %u s", cfg.max_crawl_delay_s,
                    cfg.max_retry_after_s);
    }
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    Config cfg;
    const ParseResult parsed = parse_args(argc, argv, cfg);
    if (parsed.status == ParseStatus::Help) {
        std::fputs(usage_text().c_str(), stdout);
        return 0;
    }
    if (parsed.status == ParseStatus::Error) {
        std::fprintf(stderr, "wincrawl: %s\nRun 'wincrawl --help' for usage.\n", parsed.message.c_str());
        return 2;
    }
    for (const std::string& note : parsed.notes) {
        std::printf("%s\n", note.c_str());
    }

    UrlInput input;
    std::string error;
    if (!input.open(cfg.input_path, error)) {
        std::fprintf(stderr, "wincrawl: %s\n", error.c_str());
        return 1;
    }
    std::printf("Opened %s with %zu URLs\n", cfg.input_path.c_str(), input.total());
    std::printf("Mode %s, %u threads, concurrency %u\n", mode_name(cfg.mode), cfg.threads, cfg.concurrency);
    std::string dns = cfg.dns_system ? "system" : "";
    for (const DnsServer& s : cfg.dns_servers) {
        dns += (dns.empty() ? "" : ",") + wc::net::to_string(wc::net::make_addr(s.ipv4_be, s.port));
    }
    std::printf("DNS %s, %u in flight, %u ms x %u attempts\n", dns.c_str(), cfg.dns_inflight, cfg.dns_timeout_ms,
                cfg.dns_attempts);
    print_politeness(cfg);
    if (cfg.mode == Mode::Real) {
        // Started here (the engine's later call is a no-op) so the header can
        // say what the ClientHello really offers: Schannel enables
        // post-quantum groups machine-wide; --no-pq only removes them.
        wc::tls::StartupOptions tls_options;
        tls_options.post_quantum = cfg.post_quantum;
        const bool tls_ok = wc::tls::startup(tls_options);
        std::printf("TLS %s; post-quantum key exchange %s, %s\n", tls_ok ? "ready" : "unavailable (https fetches fail)",
                    cfg.post_quantum ? "requested" : "disabled (--no-pq)",
                    wc::tls::post_quantum_available() ? "offered" : "not offered");
    }
    std::fflush(stdout);

    Stats stats(cfg.threads);
    Engine engine(cfg, input, stats);
    {
        std::lock_guard lock(g_engine_mutex);
        g_engine = &engine;
    }
    SetConsoleCtrlHandler(on_console_ctrl, TRUE);

    Reporter reporter(stats, input.total(), cfg.stats_interval_ms, cfg.quiet ? nullptr : stdout);
    reporter.start();
    const bool ok = engine.run(error);
    reporter.stop();

    SetConsoleCtrlHandler(on_console_ctrl, FALSE);
    {
        std::lock_guard lock(g_engine_mutex);
        g_engine = nullptr;
    }
    if (!ok) {
        std::fprintf(stderr, "wincrawl: %s\n", error.c_str());
        return 1;
    }

    const bool interrupted = g_interrupts.load() > 0;
    if (interrupted) {
        std::printf("Interrupted: stopped after %llu of %zu URLs\n",
                    static_cast<unsigned long long>(stats.snapshot()[Counter::UrlsRead]), input.total());
    }
    const Snapshot totals = stats.snapshot();
    RunInfo info;
    info.mode = mode_name(cfg.mode);
    info.threads = cfg.threads;
    info.concurrency = cfg.concurrency;
    info.elapsed_s = reporter.elapsed_s();
    info.peak_inflight = reporter.peak_inflight();
    if (cfg.mode == Mode::Real) {
        info.pq_requested = cfg.post_quantum;
        info.pq_offered = wc::tls::post_quantum_available();
    }
    std::fputs(format_summary(totals, info).c_str(), stdout);
    if (!cfg.record_path.empty()) {
        std::printf("Records: %llu sites written to %s\n", static_cast<unsigned long long>(engine.records_written()),
                    cfg.record_path.c_str());
    }
    std::fflush(stdout);

    if (!cfg.json_path.empty() && !write_file(cfg.json_path, format_json(totals, info))) {
        std::fprintf(stderr, "wincrawl: cannot write %s\n", cfg.json_path.c_str());
        return 1;
    }
    return interrupted ? 130 : 0;
}
