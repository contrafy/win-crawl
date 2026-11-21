#include "crawl/config.h"

#include "doctest/doctest.h"

#include <initializer_list>
#include <string>
#include <vector>

using namespace wc::crawl;

namespace {

ParseResult parse(std::initializer_list<const char*> args, Config& cfg) {
    std::vector<const char*> argv{"wincrawl"};
    argv.insert(argv.end(), args.begin(), args.end());
    return parse_args(static_cast<int>(argv.size()), argv.data(), cfg);
}

bool fails(std::initializer_list<const char*> args, const char* needle) {
    Config cfg;
    const ParseResult r = parse(args, cfg);
    if (r.status != ParseStatus::Error) {
        return false;
    }
    if (r.message.find(needle) == std::string::npos) {
        MESSAGE("message was: " << r.message);
        return false;
    }
    return true;
}

}  // namespace

TEST_CASE("config: defaults") {
    Config cfg;
    REQUIRE(parse({"urls.txt"}, cfg).status == ParseStatus::Ok);
    CHECK(cfg.input_path == "urls.txt");
    CHECK(cfg.mode == Mode::Classic);
    CHECK(cfg.threads == std::min(logical_cpu_count(), cfg.concurrency));
    CHECK(cfg.threads >= 1);
    CHECK(cfg.robots_limit == kClassicRobotsLimit);
    CHECK(cfg.page_limit == 2097152);
    CHECK(cfg.timeout_ms == 10000);
    CHECK(cfg.keepalive);
    CHECK_FALSE(cfg.insecure);
    CHECK(cfg.max_redirects == 5);
    CHECK(cfg.stats_interval_ms == 2000);
    REQUIRE(cfg.dns_servers.size() == 2);
    CHECK(cfg.dns_servers[0].ipv4_be == 0x01010101u);  // 1.1.1.1
    CHECK(cfg.dns_servers[0].port == 53);
    CHECK(cfg.dns_servers[1].ipv4_be == 0x01000001u);  // 1.0.0.1
    CHECK_FALSE(cfg.dns_system);
    CHECK(cfg.dns_inflight == 2048);
    CHECK(cfg.dns_timeout_ms == 1500);
    CHECK(cfg.dns_attempts == 3);
    CHECK(cfg.json_path.empty());
    CHECK_FALSE(cfg.quiet);

    Config real;
    REQUIRE(parse({"--mode", "real", "urls.txt"}, real).status == ParseStatus::Ok);
    CHECK(real.mode == Mode::Real);
    CHECK(real.robots_limit == kRealRobotsLimit);
    CHECK(std::string(mode_name(real.mode)) == "real");
}

TEST_CASE("config: --dns system") {
    Config cfg;
    ParseResult r = parse({"--dns", "system", "urls.txt"}, cfg);
    REQUIRE(r.status == ParseStatus::Ok);
    CHECK(cfg.dns_system);
    CHECK(cfg.dns_servers.empty());
    CHECK(cfg.dns_inflight == kSystemDnsInflight);
    REQUIRE(r.notes.size() == 1);
    CHECK(r.notes[0].find("64") != std::string::npos);

    // An explicit --dns-inflight wins, in either order.
    Config explicit_cfg;
    r = parse({"--dns-inflight", "300", "--dns=system", "urls.txt"}, explicit_cfg);
    REQUIRE(r.status == ParseStatus::Ok);
    CHECK(explicit_cfg.dns_inflight == 300);
    CHECK(r.notes.empty());

    // A later explicit list replaces "system".
    Config later;
    r = parse({"--dns", "system", "--dns", "9.9.9.9", "urls.txt"}, later);
    REQUIRE(r.status == ParseStatus::Ok);
    CHECK_FALSE(later.dns_system);
    REQUIRE(later.dns_servers.size() == 1);
    CHECK(later.dns_inflight == 2048);
}

TEST_CASE("config: every option, both spellings") {
    Config cfg;
    const ParseResult r = parse({"--mode=real", "-t", "4", "--concurrency=800", "--dns", "127.0.0.1:5300,8.8.8.8",
                                 "--dns-inflight", "64", "--dns-timeout", "750", "--dns-attempts=2",
                                 "--connect-timeout", "3000", "--timeout", "8000", "--robots-limit", "32K",
                                 "--page-limit=1M", "--no-keepalive", "--insecure", "--max-redirects", "3",
                                 "--stats-interval", "500", "--json", "out.json", "--quiet", "in.txt"},
                                cfg);
    REQUIRE(r.status == ParseStatus::Ok);
    CHECK(cfg.mode == Mode::Real);
    CHECK(cfg.threads == 4);
    CHECK(cfg.concurrency == 800);
    REQUIRE(cfg.dns_servers.size() == 2);
    CHECK(cfg.dns_servers[0].ipv4_be == 0x0100007fu);
    CHECK(cfg.dns_servers[0].port == 5300);
    CHECK(cfg.dns_servers[1].ipv4_be == 0x08080808u);
    CHECK(cfg.dns_servers[1].port == 53);
    CHECK(cfg.dns_inflight == 64);
    CHECK(cfg.dns_timeout_ms == 750);
    CHECK(cfg.dns_attempts == 2);
    CHECK(cfg.connect_timeout_ms == 3000);
    CHECK(cfg.timeout_ms == 8000);
    CHECK(cfg.robots_limit == 32 * 1024);
    CHECK(cfg.page_limit == 1024 * 1024);
    CHECK_FALSE(cfg.keepalive);
    CHECK(cfg.insecure);
    CHECK(cfg.max_redirects == 3);
    CHECK(cfg.stats_interval_ms == 500);
    CHECK(cfg.json_path == "out.json");
    CHECK(cfg.quiet);
    CHECK(cfg.input_path == "in.txt");

    Config c2;
    REQUIRE(parse({"-t8", "-c", "16", "-q", "--", "-weird-name.txt"}, c2).status == ParseStatus::Ok);
    CHECK(c2.threads == 8);
    CHECK(c2.concurrency == 16);
    CHECK(c2.quiet);
    CHECK(c2.input_path == "-weird-name.txt");
}

TEST_CASE("config: threads are capped by concurrency") {
    Config cfg;
    REQUIRE(parse({"-t", "16", "-c", "3", "u.txt"}, cfg).status == ParseStatus::Ok);
    CHECK(cfg.threads == 3);
}

TEST_CASE("config: help") {
    Config cfg;
    CHECK(parse({"-h"}, cfg).status == ParseStatus::Help);
    CHECK(parse({"urls.txt", "--help"}, cfg).status == ParseStatus::Help);
    const std::string text = usage_text();
    for (const char* opt : {"--mode", "--threads", "--concurrency", "--dns", "--dns-inflight", "--dns-timeout",
                            "--dns-attempts", "--connect-timeout", "--timeout", "--robots-limit", "--page-limit",
                            "--no-keepalive", "--insecure", "--max-redirects", "--stats-interval", "--json",
                            "--quiet", "--help"}) {
        CHECK_MESSAGE(text.find(opt) != std::string::npos, opt);
    }
}

TEST_CASE("config: errors") {
    CHECK(fails({}, "missing <url-file>"));
    CHECK(fails({"a.txt", "b.txt"}, "unexpected argument 'b.txt'"));
    CHECK(fails({"--bogus", "a.txt"}, "unknown option --bogus"));
    CHECK(fails({"-x", "a.txt"}, "unknown option -x"));
    CHECK(fails({"a.txt", "--threads"}, "needs a value"));
    CHECK(fails({"--threads", "0", "a.txt"}, "--threads"));
    CHECK(fails({"--threads", "abc", "a.txt"}, "invalid value 'abc'"));
    CHECK(fails({"--threads", "-1", "a.txt"}, "invalid value"));
    CHECK(fails({"--concurrency", "4x", "a.txt"}, "--concurrency"));
    CHECK(fails({"--mode", "fast", "a.txt"}, "classic or real"));
    CHECK(fails({"--dns", "1.2.3", "a.txt"}, "--dns"));
    CHECK(fails({"--dns", "1.2.3.256", "a.txt"}, "--dns"));
    CHECK(fails({"--dns", "1.2.3.4:0", "a.txt"}, "--dns"));
    CHECK(fails({"--dns", "1.2.3.4:5300,", "a.txt"}, "--dns"));
    CHECK(fails({"--dns", "example.com", "a.txt"}, "--dns"));
    CHECK(fails({"--dns", "system,1.2.3.4", "a.txt"}, "--dns"));
    CHECK(fails({"--dns-attempts", "11", "a.txt"}, "--dns-attempts"));
    CHECK(fails({"--page-limit", "2T", "a.txt"}, "--page-limit"));
    CHECK(fails({"--page-limit", "2G", "a.txt"}, "--page-limit"));
    CHECK(fails({"--robots-limit", "0", "a.txt"}, "--robots-limit"));
    CHECK(fails({"--max-redirects", "21", "a.txt"}, "--max-redirects"));
    CHECK(fails({"--stats-interval", "10", "a.txt"}, "--stats-interval"));
    CHECK(fails({"--quiet=yes", "a.txt"}, "takes no value"));
    CHECK(fails({"-qq", "a.txt"}, "unknown option -qq"));
    CHECK(fails({"--json=", "a.txt"}, "--json"));
}
