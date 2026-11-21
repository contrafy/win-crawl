// wincrawl-benchd: local benchmark rig for wincrawl.
//   serve  fake authoritative DNS + fake HTTP origin until Ctrl+C
//   gen    benchmark URL files
//   load   closed-loop HTTP load generator (server capacity measurements)

#include "benchsrv/behavior.h"
#include "benchsrv/dns_server.h"
#include "benchsrv/http_server.h"
#include "benchsrv/urlgen.h"
#include "cpu_meter.h"
#include "load.h"
#include "net/addr.h"
#include "net/loop.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

using namespace wc;
using namespace wc::benchsrv;

namespace {

HANDLE g_quit = nullptr;

BOOL WINAPI on_console_ctrl(DWORD) {
    SetEvent(g_quit);
    return TRUE;
}

const char kUsage[] =
    "usage:\n"
    "  wincrawl-benchd serve [options]     fake DNS + HTTP servers until Ctrl+C (or --duration)\n"
    "  wincrawl-benchd gen --count N --out FILE [gen options]\n"
    "  wincrawl-benchd load [load options] HTTP load generator against a running server\n"
    "\n"
    "serve options:\n"
    "  --dns ADDR[:PORT]        DNS listen address (default 127.0.0.1:5353)\n"
    "  --http ADDR[:PORT]       HTTP listen address (default 0.0.0.0:8080; 0.0.0.0 lets\n"
    "                           clients reach every 127.0.0.0/8 address the DNS hands out)\n"
    "  --no-dns | --no-http     run only one of the servers\n"
    "  -t, --threads K          HTTP worker loops (default 4)\n"
    "  --profile lan|wan        lan: no injected latency (default); wan: DNS 30,10 ms and\n"
    "                           HTTP 80,40 ms (explicit delay options override)\n"
    "  --zone NAME              served zone (default bench.test)\n"
    "  --seed N                 world seed (default 0)\n"
    "  --ip-share F             fraction of hosts sharing an earlier host's IP (0.2)\n"
    "  --nxdomain F             fraction of hosts answered NXDOMAIN (0.1)\n"
    "  --dns-delay-ms M[,J]     DNS reply delay, uniform M +/- J ms per name (0)\n"
    "  --robots-404 F           fraction of hosts without robots.txt (0.6)\n"
    "  --page-kb KB             mean page size (32)\n"
    "  --links N                links per page (30)\n"
    "  --redirect F             page fraction answered 301 (0.05)\n"
    "  --not-found F            page fraction answered 404 (0.05)\n"
    "  --server-error F         page fraction answered 503 (0.02)\n"
    "  --chunked F              fraction of 200 pages sent chunked (0.1)\n"
    "  --http-delay-ms M[,J]    per-request response delay, M +/- J ms (0)\n"
    "  --idle-timeout-ms MS     reset idle connections after MS (30000)\n"
    "  --graceful-close         plain close after Connection: close responses (leaves\n"
    "                           TIME_WAIT on the server) instead of FIN + wait + reset\n"
    "  --duration S             exit after S seconds (default: run until Ctrl+C)\n"
    "  --stats-interval MS      periodic stats line period (2000)\n"
    "  --quiet                  no periodic lines\n"
    "\n"
    "gen options:\n"
    "  --count N                number of URLs (required)\n"
    "  --out FILE               output file (required)\n"
    "  --dup-hosts F            fraction of lines repeating an earlier host (0.1)\n"
    "  --port P                 URL port (8080)\n"
    "  --ip-literal             http://127.a.b.c:P/... URLs (no DNS needed)\n"
    "  --zone NAME, --seed N    as for serve\n"
    "\n"
    "load options:\n"
    "  --http ADDR[:PORT]       server (default 127.0.0.1:8080)\n"
    "  -t, --threads K          client loops (4)\n"
    "  -c, --connections N      concurrent connections (256)\n"
    "  --duration S             seconds (10)\n"
    "  --close                  Connection: close + reconnect per request\n"
    "  --head                   HEAD instead of GET\n"
    "  --path P                 request path (/robots.txt)\n"
    "  --hosts N                Host header cycles over h0..h<N-1> (100000)\n"
    "  --no-spread              connect to the --http address instead of each host's 127/8 IP\n"
    "  --zone NAME              as for serve\n";

class Args {
public:
    Args(int argc, char** argv, int first) : argc_(argc), argv_(argv), i_(first) {}

    bool next(std::string_view& out) {
        if (i_ >= argc_) return false;
        out = argv_[i_++];
        return true;
    }
    // Value of the option just read; exits with an error when missing.
    const char* value(std::string_view option) {
        if (i_ >= argc_) die(std::string("missing value for ") + std::string(option));
        return argv_[i_++];
    }
    double number(std::string_view option) {
        const char* v = value(option);
        char* end = nullptr;
        const double d = std::strtod(v, &end);
        if (end == v || *end != '\0' || d < 0) die(std::string("bad value for ") + std::string(option) + ": " + v);
        return d;
    }
    double fraction(std::string_view option) {
        const double d = number(option);
        if (d > 1) die(std::string(option) + " must be within [0, 1]");
        return d;
    }
    uint64_t integer(std::string_view option) {
        const char* v = value(option);
        char* end = nullptr;
        const unsigned long long n = std::strtoull(v, &end, 10);
        if (end == v || *end != '\0') die(std::string("bad value for ") + std::string(option) + ": " + v);
        return n;
    }
    sockaddr_in address(std::string_view option, uint16_t default_port) {
        sockaddr_in a{};
        const char* v = value(option);
        if (!net::parse_addr(v, default_port, a)) die(std::string("bad address for ") + std::string(option) + ": " + v);
        return a;
    }
    Delay delay(std::string_view option) {
        Delay d;
        const char* v = value(option);
        if (!parse_delay(v, d)) die(std::string("bad delay for ") + std::string(option) + ": " + v + " (want MEAN[,JITTER])");
        return d;
    }

    [[noreturn]] static void die(const std::string& message) {
        std::fprintf(stderr, "wincrawl-benchd: %s\n(see wincrawl-benchd --help)\n", message.c_str());
        std::exit(2);
    }

private:
    int argc_;
    char** argv_;
    int i_;
};

std::string win_error(DWORD err) {
    char buf[256] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err, 0, buf, sizeof(buf), nullptr);
    std::string s(buf);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == '.')) s.pop_back();
    return std::to_string(err) + " (" + s + ")";
}

int cmd_serve(Args& args) {
    Behavior b;
    HttpServerConfig http_cfg;
    sockaddr_in dns_addr{};
    sockaddr_in http_addr{};
    net::parse_addr("127.0.0.1", 5353, dns_addr);
    net::parse_addr("0.0.0.0", 8080, http_addr);
    bool run_dns = true, run_http = true, quiet = false;
    std::optional<Delay> dns_delay, http_delay;
    std::string profile = "lan";
    uint64_t duration_s = 0;
    uint64_t interval_ms = 2000;

    std::string_view a;
    while (args.next(a)) {
        if (a == "--dns") dns_addr = args.address(a, 5353);
        else if (a == "--http") http_addr = args.address(a, 8080);
        else if (a == "--no-dns") run_dns = false;
        else if (a == "--no-http") run_http = false;
        else if (a == "-t" || a == "--threads") http_cfg.threads = static_cast<uint32_t>(args.integer(a));
        else if (a == "--profile") profile = args.value(a);
        else if (a == "--zone") b.zone = args.value(a);
        else if (a == "--seed") b.seed = args.integer(a);
        else if (a == "--ip-share") b.ip_share = args.fraction(a);
        else if (a == "--nxdomain") b.nxdomain = args.fraction(a);
        else if (a == "--dns-delay-ms") dns_delay = args.delay(a);
        else if (a == "--robots-404") b.robots_404 = args.fraction(a);
        else if (a == "--page-kb") b.page_kb = static_cast<uint32_t>(args.integer(a));
        else if (a == "--links") b.links = static_cast<uint32_t>(args.integer(a));
        else if (a == "--redirect") b.redirect = args.fraction(a);
        else if (a == "--not-found") b.not_found = args.fraction(a);
        else if (a == "--server-error") b.server_error = args.fraction(a);
        else if (a == "--chunked") b.chunked = args.fraction(a);
        else if (a == "--http-delay-ms") http_delay = args.delay(a);
        else if (a == "--idle-timeout-ms") http_cfg.idle_timeout_ms = static_cast<uint32_t>(args.integer(a));
        else if (a == "--graceful-close") http_cfg.graceful_close = true;
        else if (a == "--duration") duration_s = args.integer(a);
        else if (a == "--stats-interval") interval_ms = args.integer(a);
        else if (a == "--quiet") quiet = true;
        else Args::die("unknown serve option " + std::string(a));
    }
    if (profile == "wan") {
        b.dns_delay = Delay{30, 10};
        b.http_delay = Delay{80, 40};
    } else if (profile != "lan") {
        Args::die("unknown profile " + profile + " (lan|wan)");
    }
    if (dns_delay) b.dns_delay = *dns_delay;
    if (http_delay) b.http_delay = *http_delay;
    for (char& c : b.zone) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    if (!b.zone.empty() && b.zone.back() == '.') b.zone.pop_back();
    if (b.redirect + b.not_found + b.server_error > 1) Args::die("--redirect + --not-found + --server-error exceed 1");
    if (http_cfg.threads == 0) http_cfg.threads = 1;
    if (interval_ms == 0) interval_ms = 2000;
    if (!run_dns && !run_http) Args::die("nothing to serve");

    net::startup();
    g_quit = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE);

    std::optional<DnsServer> dns;
    std::optional<HttpServer> http;
    if (run_dns) {
        dns.emplace(b);
        if (const DWORD err = dns->start(dns_addr)) {
            std::fprintf(stderr, "wincrawl-benchd: DNS bind %s failed: %s\n", net::to_string(dns_addr).c_str(),
                         win_error(err).c_str());
            return 1;
        }
    }
    if (run_http) {
        http.emplace(b, http_cfg);
        if (const DWORD err = http->start(http_addr)) {
            std::fprintf(stderr, "wincrawl-benchd: HTTP listen %s failed: %s\n", net::to_string(http_addr).c_str(),
                         win_error(err).c_str());
            return 1;
        }
    }
    std::printf("wincrawl-benchd serving zone %s (seed %llu, profile %s)\n", b.zone.c_str(),
                static_cast<unsigned long long>(b.seed), profile.c_str());
    if (dns) {
        std::printf("  dns  udp %s  ip-share %.2f nxdomain %.2f delay %u+-%u ms\n",
                    net::to_string(dns->local_address()).c_str(), b.ip_share, b.nxdomain, b.dns_delay.mean_ms,
                    b.dns_delay.jitter_ms);
    }
    if (http) {
        std::printf("  http tcp %s  %u workers  robots-404 %.2f page %u KB links %u 3xx %.2f 404 %.2f 5xx %.2f "
                    "chunked %.2f delay %u+-%u ms%s\n",
                    net::to_string(http->local_address()).c_str(), http_cfg.threads, b.robots_404, b.page_kb, b.links,
                    b.redirect, b.not_found, b.server_error, b.chunked, b.http_delay.mean_ms, b.http_delay.jitter_ms,
                    http_cfg.graceful_close ? " graceful-close" : "");
    }
    std::printf("ready\n");
    std::fflush(stdout);

    benchd::CpuMeter cpu;
    const auto t0 = std::chrono::steady_clock::now();
    const auto deadline = duration_s ? t0 + std::chrono::seconds(duration_s) : std::chrono::steady_clock::time_point::max();
    auto last = t0;
    HttpCounters hprev;
    DnsCounters dprev;
    for (;;) {
        DWORD wait = static_cast<DWORD>(interval_ms);
        if (duration_s) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) break;
            if (static_cast<uint64_t>(left) < wait) wait = static_cast<DWORD>(left);
        }
        if (WaitForSingleObject(g_quit, wait) == WAIT_OBJECT_0) break;
        if (quiet) continue;
        const auto now = std::chrono::steady_clock::now();
        const double dt = std::chrono::duration<double>(now - last).count();
        const HttpCounters h = http ? http->counters() : HttpCounters{};
        const DnsCounters d = dns ? dns->counters() : DnsCounters{};
        std::printf("[%6.1fs] http %8.0f req/s %7.0f conn/s active %6llu %7.1f Mbit/s | dns %7.0f q/s | cpu %4.0f%%\n",
                    std::chrono::duration<double>(now - t0).count(), (h.requests - hprev.requests) / dt,
                    (h.accepted - hprev.accepted) / dt, static_cast<unsigned long long>(h.active),
                    (h.bytes_sent - hprev.bytes_sent) * 8.0 / dt / 1e6, (d.queries - dprev.queries) / dt,
                    cpu.sample_percent());
        std::fflush(stdout);
        hprev = h;
        dprev = d;
        last = now;
    }
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (http) http->stop();
    if (dns) dns->stop();
    const HttpCounters h = http ? http->counters() : HttpCounters{};
    const DnsCounters d = dns ? dns->counters() : DnsCounters{};
    std::printf("served %.1f s: http %llu requests (robots %llu; 2xx %llu 3xx %llu 4xx %llu 5xx %llu) %llu connections "
                "%.1f MB | dns %llu queries (A %llu nodata %llu nxdomain %llu refused %llu errors %llu) | cpu %.1f s\n",
                elapsed, static_cast<unsigned long long>(h.requests), static_cast<unsigned long long>(h.robots),
                static_cast<unsigned long long>(h.status_2xx), static_cast<unsigned long long>(h.status_3xx),
                static_cast<unsigned long long>(h.status_4xx), static_cast<unsigned long long>(h.status_5xx),
                static_cast<unsigned long long>(h.accepted), h.bytes_sent / 1e6,
                static_cast<unsigned long long>(d.queries), static_cast<unsigned long long>(d.answered),
                static_cast<unsigned long long>(d.nodata), static_cast<unsigned long long>(d.nxdomain),
                static_cast<unsigned long long>(d.refused), static_cast<unsigned long long>(d.errors),
                benchd::CpuMeter::total_seconds());
    return 0;
}

int cmd_gen(Args& args) {
    UrlGenOptions o;
    std::string out;
    bool have_count = false;
    std::string_view a;
    while (args.next(a)) {
        if (a == "--count") {
            o.count = args.integer(a);
            have_count = true;
        } else if (a == "--out") out = args.value(a);
        else if (a == "--dup-hosts") o.dup_hosts = args.fraction(a);
        else if (a == "--port") {
            const uint64_t p = args.integer(a);
            if (p == 0 || p > 65535) Args::die("bad --port");
            o.port = static_cast<uint16_t>(p);
        } else if (a == "--ip-literal") o.ip_literal = true;
        else if (a == "--zone") o.zone = args.value(a);
        else if (a == "--seed") o.seed = args.integer(a);
        else Args::die("unknown gen option " + std::string(a));
    }
    if (!have_count || out.empty()) Args::die("gen needs --count N and --out FILE");
    std::string error;
    uint64_t hosts = 0;
    if (!write_url_file(o, out, &error, &hosts)) {
        std::fprintf(stderr, "wincrawl-benchd: %s\n", error.c_str());
        return 1;
    }
    std::printf("wrote %llu URLs (%llu unique hosts) to %s\n", static_cast<unsigned long long>(o.count),
                static_cast<unsigned long long>(hosts), out.c_str());
    return 0;
}

int cmd_load(Args& args) {
    benchd::LoadOptions o;
    net::parse_addr("127.0.0.1", 8080, o.target);
    std::string_view a;
    while (args.next(a)) {
        if (a == "--http") o.target = args.address(a, 8080);
        else if (a == "-t" || a == "--threads") o.threads = static_cast<uint32_t>(args.integer(a));
        else if (a == "-c" || a == "--connections") o.connections = static_cast<uint32_t>(args.integer(a));
        else if (a == "--duration") o.duration_s = static_cast<uint32_t>(args.integer(a));
        else if (a == "--close") o.close = true;
        else if (a == "--head") o.head = true;
        else if (a == "--path") o.path = args.value(a);
        else if (a == "--hosts") o.hosts = std::max<uint64_t>(1, args.integer(a));
        else if (a == "--no-spread") o.spread_ips = false;
        else if (a == "--zone") o.zone = args.value(a);
        else Args::die("unknown load option " + std::string(a));
    }
    if (o.connections == 0) Args::die("--connections must be > 0");
    return benchd::run_load(o);
}

}  // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 1 << 14);
    if (argc < 2) {
        std::fputs(kUsage, stderr);
        return 2;
    }
    const std::string_view cmd = argv[1];
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        std::fputs(kUsage, stdout);
        return 0;
    }
    Args args(argc, argv, 2);
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            std::fputs(kUsage, stdout);
            return 0;
        }
    }
    if (cmd == "serve") return cmd_serve(args);
    if (cmd == "gen") return cmd_gen(args);
    if (cmd == "load") return cmd_load(args);
    std::fprintf(stderr, "wincrawl-benchd: unknown command %s\n\n%s", argv[1], kUsage);
    return 2;
}
