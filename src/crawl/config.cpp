#include "crawl/config.h"

#include "crawl/ipranges.h"
#include "sig/signer.h"

#include <windows.h>

#include <charconv>
#include <string_view>

namespace wc::crawl {

namespace {

constexpr uint64_t kKiB = 1024;
constexpr uint64_t kGiB = 1024 * 1024 * 1024;

enum class Opt {
    Mode,
    Threads,
    Concurrency,
    Dns,
    DnsInflight,
    DnsTimeout,
    DnsAttempts,
    ConnectTimeout,
    Timeout,
    RobotsLimit,
    PageLimit,
    NoKeepalive,
    Insecure,
    NoPq,
    MaxRedirects,
    StatsInterval,
    Json,
    Record,
    HttpsRr,
    Quiet,
    HostsPerIp,
    NoIpDedupe,
    IpConcurrency,
    IpInterval,
    MaxCrawlDelay,
    MaxRetryAfter,
    IpFailLimit,
    MaxIpPenalty,
    NoCdnPolicy,
    CdnHostsPerIp,
    CdnIpConcurrency,
    CdnIpInterval,
    BotAuthKey,
    SignatureAgent,
    Help,
};

struct OptSpec {
    Opt opt;
    std::string_view long_name;
    char short_name;  // 0 = none
    bool takes_value;
};

constexpr OptSpec kOptions[] = {
    {Opt::Mode, "mode", 0, true},
    {Opt::Threads, "threads", 't', true},
    {Opt::Concurrency, "concurrency", 'c', true},
    {Opt::Dns, "dns", 0, true},
    {Opt::DnsInflight, "dns-inflight", 0, true},
    {Opt::DnsTimeout, "dns-timeout", 0, true},
    {Opt::DnsAttempts, "dns-attempts", 0, true},
    {Opt::ConnectTimeout, "connect-timeout", 0, true},
    {Opt::Timeout, "timeout", 0, true},
    {Opt::RobotsLimit, "robots-limit", 0, true},
    {Opt::PageLimit, "page-limit", 0, true},
    {Opt::NoKeepalive, "no-keepalive", 0, false},
    {Opt::Insecure, "insecure", 0, false},
    {Opt::NoPq, "no-pq", 0, false},
    {Opt::MaxRedirects, "max-redirects", 0, true},
    {Opt::StatsInterval, "stats-interval", 0, true},
    {Opt::Json, "json", 0, true},
    {Opt::Record, "record", 0, true},
    {Opt::HttpsRr, "https-rr", 0, false},
    {Opt::Quiet, "quiet", 'q', false},
    {Opt::HostsPerIp, "hosts-per-ip", 0, true},
    {Opt::NoIpDedupe, "no-ip-dedupe", 0, false},
    {Opt::IpConcurrency, "ip-concurrency", 0, true},
    {Opt::IpInterval, "ip-interval", 0, true},
    {Opt::MaxCrawlDelay, "max-crawl-delay", 0, true},
    {Opt::MaxRetryAfter, "max-retry-after", 0, true},
    {Opt::IpFailLimit, "ip-fail-limit", 0, true},
    {Opt::MaxIpPenalty, "max-ip-penalty", 0, true},
    {Opt::NoCdnPolicy, "no-cdn-policy", 0, false},
    {Opt::CdnHostsPerIp, "cdn-hosts-per-ip", 0, true},
    {Opt::CdnIpConcurrency, "cdn-ip-concurrency", 0, true},
    {Opt::CdnIpInterval, "cdn-ip-interval", 0, true},
    {Opt::BotAuthKey, "bot-auth-key", 0, true},
    {Opt::SignatureAgent, "signature-agent", 0, true},
    {Opt::Help, "help", 'h', false},
};

const OptSpec* find_long(std::string_view name) {
    for (const OptSpec& spec : kOptions) {
        if (spec.long_name == name) {
            return &spec;
        }
    }
    return nullptr;
}

const OptSpec* find_short(char name) {
    for (const OptSpec& spec : kOptions) {
        if (spec.short_name != 0 && spec.short_name == name) {
            return &spec;
        }
    }
    return nullptr;
}

std::string display(const OptSpec& spec) {
    return "--" + std::string(spec.long_name);
}

bool parse_u64(std::string_view text, uint64_t& out) {
    if (text.empty()) {
        return false;
    }
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
    return ec == std::errc() && ptr == text.data() + text.size();
}

// Integer in [lo, hi].
bool parse_range(std::string_view text, uint64_t lo, uint64_t hi, uint64_t& out) {
    return parse_u64(text, out) && out >= lo && out <= hi;
}

// Byte count with an optional binary suffix: 16384, 16K, 2M, 1G.
bool parse_bytes(std::string_view text, uint64_t lo, uint64_t hi, uint64_t& out) {
    uint64_t scale = 1;
    if (!text.empty()) {
        switch (text.back()) {
        case 'k': case 'K': scale = kKiB; break;
        case 'm': case 'M': scale = kKiB * kKiB; break;
        case 'g': case 'G': scale = kGiB; break;
        default: break;
        }
        if (scale != 1) {
            text.remove_suffix(1);
        }
    }
    uint64_t v = 0;
    if (!parse_u64(text, v) || v > hi / scale) {
        return false;
    }
    out = v * scale;
    return out >= lo && out <= hi;
}

bool parse_ipv4(std::string_view text, uint32_t& out_be) {
    uint8_t octets[4];
    for (int i = 0; i < 4; ++i) {
        const size_t dot = i < 3 ? text.find('.') : text.size();
        if (dot == std::string_view::npos || dot == 0 || dot > 3) {
            return false;
        }
        uint64_t v = 0;
        if (!parse_range(text.substr(0, dot), 0, 255, v)) {
            return false;
        }
        octets[i] = static_cast<uint8_t>(v);
        text.remove_prefix(i < 3 ? dot + 1 : dot);
    }
    // Network byte order: first octet in the lowest-addressed byte.
    out_be = static_cast<uint32_t>(octets[0]) | static_cast<uint32_t>(octets[1]) << 8 |
             static_cast<uint32_t>(octets[2]) << 16 | static_cast<uint32_t>(octets[3]) << 24;
    return true;
}

// "ADDR[:PORT][,ADDR[:PORT]...]"
bool parse_dns_list(std::string_view text, std::vector<DnsServer>& out) {
    std::vector<DnsServer> servers;
    while (true) {
        const size_t comma = text.find(',');
        std::string_view item = text.substr(0, comma);
        DnsServer server;
        const size_t colon = item.find(':');
        if (colon != std::string_view::npos) {
            uint64_t port = 0;
            if (!parse_range(item.substr(colon + 1), 1, 65535, port)) {
                return false;
            }
            server.port = static_cast<uint16_t>(port);
            item = item.substr(0, colon);
        }
        if (!parse_ipv4(item, server.ipv4_be)) {
            return false;
        }
        servers.push_back(server);
        if (comma == std::string_view::npos) {
            break;
        }
        text.remove_prefix(comma + 1);
    }
    out = std::move(servers);
    return true;
}

ParseResult error(std::string message) {
    return ParseResult{ParseStatus::Error, std::move(message), {}};
}

// Options whose defaults depend on whether they were given explicitly.
struct Given {
    bool robots_limit = false;
    bool dns_inflight = false;
};

// Applies one option. `value` is empty for flags.
ParseResult apply(const OptSpec& spec, std::string_view value, Config& cfg, Given& given) {
    uint64_t v = 0;
    auto bad = [&](const char* expected) {
        return error("invalid value '" + std::string(value) + "' for " + display(spec) + ": expected " + expected);
    };
    switch (spec.opt) {
    case Opt::Mode:
        if (value == "classic") {
            cfg.mode = Mode::Classic;
        } else if (value == "real") {
            cfg.mode = Mode::Real;
        } else {
            return bad("classic or real");
        }
        break;
    case Opt::Threads:
        if (!parse_range(value, 1, 1024, v)) return bad("an integer in 1..1024");
        cfg.threads = static_cast<unsigned>(v);
        break;
    case Opt::Concurrency:
        if (!parse_range(value, 1, 1000000, v)) return bad("an integer in 1..1000000");
        cfg.concurrency = static_cast<unsigned>(v);
        break;
    case Opt::Dns:
        if (value == "system") {
            cfg.dns_system = true;
            cfg.dns_servers.clear();
            break;
        }
        if (!parse_dns_list(value, cfg.dns_servers)) return bad("system or IPv4[:port][,IPv4[:port]...]");
        cfg.dns_system = false;
        break;
    case Opt::DnsInflight:
        if (!parse_range(value, 1, 65535, v)) return bad("an integer in 1..65535");
        cfg.dns_inflight = static_cast<unsigned>(v);
        given.dns_inflight = true;
        break;
    case Opt::DnsTimeout:
        if (!parse_range(value, 1, 60000, v)) return bad("milliseconds in 1..60000");
        cfg.dns_timeout_ms = static_cast<unsigned>(v);
        break;
    case Opt::DnsAttempts:
        if (!parse_range(value, 1, 10, v)) return bad("an integer in 1..10");
        cfg.dns_attempts = static_cast<unsigned>(v);
        break;
    case Opt::ConnectTimeout:
        if (!parse_range(value, 1, 600000, v)) return bad("milliseconds in 1..600000");
        cfg.connect_timeout_ms = static_cast<unsigned>(v);
        break;
    case Opt::Timeout:
        if (!parse_range(value, 1, 3600000, v)) return bad("milliseconds in 1..3600000");
        cfg.timeout_ms = static_cast<unsigned>(v);
        break;
    case Opt::RobotsLimit:
        if (!parse_bytes(value, 1, kGiB, v)) return bad("bytes in 1..1G (K/M/G suffixes allowed)");
        cfg.robots_limit = v;
        given.robots_limit = true;
        break;
    case Opt::PageLimit:
        if (!parse_bytes(value, 1, kGiB, v)) return bad("bytes in 1..1G (K/M/G suffixes allowed)");
        cfg.page_limit = v;
        break;
    case Opt::NoKeepalive:
        cfg.keepalive = false;
        break;
    case Opt::Insecure:
        cfg.insecure = true;
        break;
    case Opt::NoPq:
        cfg.post_quantum = false;
        break;
    case Opt::MaxRedirects:
        if (!parse_range(value, 0, 20, v)) return bad("an integer in 0..20");
        cfg.max_redirects = static_cast<unsigned>(v);
        break;
    case Opt::StatsInterval:
        if (!parse_range(value, 100, 3600000, v)) return bad("milliseconds in 100..3600000");
        cfg.stats_interval_ms = static_cast<unsigned>(v);
        break;
    case Opt::Json:
        if (value.empty()) return bad("a file path");
        cfg.json_path = std::string(value);
        break;
    case Opt::Record:
        if (value.empty()) return bad("a file path");
        cfg.record_path = std::string(value);
        break;
    case Opt::HttpsRr:
        cfg.https_rr = true;
        break;
    case Opt::Quiet:
        cfg.quiet = true;
        break;
    case Opt::HostsPerIp:
        if (!parse_range(value, 0, 10000000, v)) return bad("an integer in 0..10000000 (0 = unlimited)");
        cfg.hosts_per_ip = static_cast<unsigned>(v);
        break;
    case Opt::NoIpDedupe:
        cfg.hosts_per_ip = 0;
        break;
    case Opt::IpConcurrency:
        if (!parse_range(value, 0, 100000, v)) return bad("an integer in 0..100000 (0 = unlimited)");
        cfg.ip_concurrency = static_cast<unsigned>(v);
        break;
    case Opt::IpInterval:
        if (!parse_range(value, 0, 600000, v)) return bad("milliseconds in 0..600000");
        cfg.ip_interval_ms = static_cast<unsigned>(v);
        break;
    case Opt::MaxCrawlDelay:
        if (!parse_range(value, 0, 3600, v)) return bad("seconds in 0..3600");
        cfg.max_crawl_delay_s = static_cast<unsigned>(v);
        break;
    case Opt::MaxRetryAfter:
        if (!parse_range(value, 0, 3600, v)) return bad("seconds in 0..3600");
        cfg.max_retry_after_s = static_cast<unsigned>(v);
        break;
    case Opt::IpFailLimit:
        if (!parse_range(value, 0, 1000, v)) return bad("an integer in 0..1000 (0 = never)");
        cfg.ip_fail_limit = static_cast<unsigned>(v);
        break;
    case Opt::MaxIpPenalty:
        if (!parse_range(value, 0, 600000, v)) return bad("milliseconds in 0..600000");
        cfg.max_ip_penalty_ms = static_cast<unsigned>(v);
        break;
    case Opt::NoCdnPolicy:
        cfg.cdn_policy = false;
        break;
    case Opt::CdnHostsPerIp:
        if (!parse_range(value, 0, 10000000, v)) return bad("an integer in 0..10000000 (0 = unlimited)");
        cfg.cdn_hosts_per_ip = static_cast<unsigned>(v);
        break;
    case Opt::CdnIpConcurrency:
        if (!parse_range(value, 0, 100000, v)) return bad("an integer in 0..100000 (0 = unlimited)");
        cfg.cdn_ip_concurrency = static_cast<unsigned>(v);
        break;
    case Opt::CdnIpInterval:
        if (!parse_range(value, 0, 600000, v)) return bad("milliseconds in 0..600000");
        cfg.cdn_ip_interval_ms = static_cast<unsigned>(v);
        break;
    case Opt::BotAuthKey:
        cfg.bot_auth_key_path = std::string(value);
        break;
    case Opt::SignatureAgent:
        if (!sig::valid_signature_agent(value)) return bad("an https:// URL in printable ASCII");
        cfg.signature_agent = std::string(value);
        break;
    case Opt::Help:
        return ParseResult{ParseStatus::Help, {}, {}};
    }
    return {};
}

}  // namespace

const char* mode_name(Mode mode) {
    return mode == Mode::Real ? "real" : "classic";
}

GatePolicy gate_policy(const Config& cfg) {
    GatePolicy p;
    p.ip.hosts = cfg.hosts_per_ip;
    p.ip.concurrency = cfg.ip_concurrency;
    p.ip.interval_ms = cfg.ip_interval_ms;
    p.ip.backoff = true;
    // With the assignment's IP dedupe (the default) CDN IPs are deduped too,
    // so a default run keeps its published semantics; a measurement run that
    // lifts the budget lifts it for CDN edges entirely.
    p.cdn.hosts = cfg.cdn_hosts_per_ip.value_or(cfg.hosts_per_ip == 1 ? 1u : 0u);
    p.cdn.concurrency = cfg.cdn_ip_concurrency;
    p.cdn.interval_ms = cfg.cdn_ip_interval_ms;
    p.cdn.backoff = false;  // one origin's 429 says nothing about the edge's other origins
    if (cfg.cdn_policy) {
        p.cdn_ranges = cfg.cdn_ranges != nullptr ? cfg.cdn_ranges : &cloudflare_ipv4();
    }
    p.fail_limit = cfg.ip_fail_limit;
    p.max_penalty_ms = cfg.max_ip_penalty_ms;
    return p;
}

unsigned logical_cpu_count() {
    const DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return n == 0 ? 1u : static_cast<unsigned>(n);
}

ParseResult parse_args(int argc, const char* const* argv, Config& out) {
    Config cfg;
    Given given;
    bool options_done = false;
    std::vector<std::string_view> positional;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (options_done || arg.size() < 2 || arg[0] != '-') {
            positional.push_back(arg);
            continue;
        }
        if (arg == "--") {
            options_done = true;
            continue;
        }

        const OptSpec* spec = nullptr;
        std::string_view value;
        bool has_inline_value = false;
        if (arg[1] == '-') {
            std::string_view name = arg.substr(2);
            const size_t eq = name.find('=');
            if (eq != std::string_view::npos) {
                value = name.substr(eq + 1);
                name = name.substr(0, eq);
                has_inline_value = true;
            }
            spec = find_long(name);
            if (spec == nullptr) {
                return error("unknown option --" + std::string(name));
            }
        } else {
            spec = find_short(arg[1]);
            if (spec == nullptr) {
                return error("unknown option " + std::string(arg));
            }
            if (arg.size() > 2) {
                if (!spec->takes_value) {
                    return error("unknown option " + std::string(arg));
                }
                value = arg.substr(2);  // -t8
                has_inline_value = true;
            }
        }

        if (spec->takes_value && !has_inline_value) {
            if (i + 1 >= argc) {
                return error("option " + display(*spec) + " needs a value");
            }
            value = argv[++i];
        } else if (!spec->takes_value && has_inline_value) {
            return error("option " + display(*spec) + " takes no value");
        }

        ParseResult r = apply(*spec, value, cfg, given);
        if (r.status != ParseStatus::Ok) {
            return r;
        }
    }

    if (positional.empty()) {
        return error("missing <url-file>");
    }
    if (positional.size() > 1) {
        return error("unexpected argument '" + std::string(positional[1]) + "' (only one <url-file> is accepted)");
    }
    cfg.input_path = std::string(positional[0]);
    if (cfg.https_rr && cfg.record_path.empty()) {
        return error("--https-rr needs --record FILE (the answers are only recorded there)");
    }
    if (cfg.bot_auth_key_path.empty() != cfg.signature_agent.empty()) {
        return error("--bot-auth-key and --signature-agent go together (the key signs; the URL says where to find it)");
    }

    if (cfg.threads == 0) {
        cfg.threads = logical_cpu_count();
    }
    // A loop without a single task slot would only burn a core.
    if (cfg.threads > cfg.concurrency) {
        cfg.threads = cfg.concurrency;
    }
    if (!given.robots_limit) {
        cfg.robots_limit = cfg.mode == Mode::Real ? kRealRobotsLimit : kClassicRobotsLimit;
    }
    ParseResult result;
    if (cfg.dns_system && !given.dns_inflight && cfg.dns_inflight > kSystemDnsInflight) {
        // OS-configured resolvers (typically a home router) drop most queries
        // beyond a few dozen in flight.
        cfg.dns_inflight = kSystemDnsInflight;
        result.notes.push_back("note: --dns system caps DNS in-flight queries at " +
                               std::to_string(kSystemDnsInflight) + " (raise with --dns-inflight)");
    }
    out = std::move(cfg);
    return result;
}

std::string usage_text() {
    return R"(usage: wincrawl [options] <url-file>

Crawls every URL in <url-file> (one per line) with per-core IOCP event loops.

Modes:
  --mode classic|real     classic (default): the CSCE 463 pipeline: http only,
                          unique host -> DNS -> unique IP -> HEAD /robots.txt,
                          GET the page only when robots answers 4xx.
                          real: http + https, GET /robots.txt honoured per
                          RFC 9309, redirects followed, TLS via Schannel.

Engine:
  -t, --threads N         event loops (default: logical CPUs; capped at -c)
  -c, --concurrency N     max in-flight URL tasks across all loops (default 4000);
                          sites waiting on politeness hold no socket and do
                          not count

DNS:
  --dns ADDR[:PORT][,...] DNS servers (default 1.1.1.1,1.0.0.1); use --dns system
                          for the OS-configured servers (in-flight then capped
                          at 64 unless --dns-inflight is given)
  --dns-inflight N        max outstanding DNS queries in total (default 2048)
  --dns-timeout MS        per-attempt timeout (default 1500)
  --dns-attempts N        attempts per name (default 3)

HTTP:
  --connect-timeout MS    TCP connect timeout (default 5000)
  --timeout MS            total time per fetch, connect included (default 10000)
  --robots-limit BYTES    robots.txt reply cap (default 16K classic, 512K real)
  --page-limit BYTES      page reply cap (default 2M); K/M/G suffixes allowed
  --no-keepalive          fresh connection per request; in classic mode also
                          HTTP/1.0 requests like the original crawler
  --insecure              real mode: skip TLS certificate verification
  --no-pq                 real mode: do not offer the hybrid post-quantum key
                          exchange (X25519MLKEM768); it is offered by default
  --max-redirects N       real mode: redirects followed per page (default 5)

Politeness (per target; see docs/politeness.md):
  --hosts-per-ip N        hosts fetched per IP (default 1: the assignment's IP
                          dedupe); 0 = unlimited. Hosts past it are skipped
  --no-ip-dedupe          same as --hosts-per-ip 0
  --ip-concurrency N      connections open at once to one IP (default 2; 0 = no cap)
  --ip-interval MS        minimum time between connection starts to one IP
                          (default 250); 429/503 replies lengthen it
  --max-crawl-delay S     real mode: honour robots.txt Crawl-delay up to S
                          seconds between requests to a host; a longer delay
                          skips the page (default 30)
  --max-retry-after S     real mode: wait out a 429/503 Retry-After of up to S
                          seconds and retry once (default 30)
  --ip-fail-limit N       skip an IP's other hosts after N failed connections in
                          a row on an IP that never answered (refused,
                          unreachable, timed out), or after N 429/503 replies
                          in a row (default 5; 0 = never; not for Cloudflare IPs)
  --max-ip-penalty MS     cap on the extra spacing 429/503 replies add to an
                          IP (default 10000)
  --cdn-hosts-per-ip N    hosts per IP inside Cloudflare's ranges (default:
                          1 with --hosts-per-ip 1, else unlimited)
  --cdn-ip-concurrency N  connections per Cloudflare IP (default 16)
  --cdn-ip-interval MS    spacing per Cloudflare IP (default 0)
  --no-cdn-policy         treat Cloudflare IPs like any other IP

Web Bot Auth (signed requests; see docs/web-bot-auth.md):
  --bot-auth-key FILE     sign every request (RFC 9421, Ed25519) with this
                          private key: a JWK from wincrawl-botauth keygen, or
                          PKCS#8 PEM; needs --signature-agent
  --signature-agent URL   https URL of the key directory, sent (and signed) as
                          Signature-Agent; each signature is valid for 60 s

Output:
  --stats-interval MS     periodic status interval (default 2000)
  --json FILE             write the final statistics as JSON to FILE
  --record FILE           write one JSON line per unique host attempted (DNS,
                          robots, status, redirects, TLS, Alt-Svc, HSTS, ...;
                          see docs/study-method.md)
  --https-rr              also query each resolved host's HTTPS DNS record and
                          record it (needs --record)
  -q, --quiet             no periodic status lines
  -h, --help              this text

Ctrl+C stops taking URLs, aborts what is in flight and prints the summary.
Exit codes: 0 run completed, 1 fatal error (e.g. unreadable input), 2 usage error,
130 interrupted by Ctrl+C.
)";
}

}  // namespace wc::crawl
