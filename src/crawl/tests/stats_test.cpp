#include "crawl/stats.h"

#include "doctest/doctest.h"

#include <cstdio>
#include <string>
#include <thread>

using namespace wc::crawl;

TEST_CASE("stats: blocks are cache-line sized and snapshots sum them") {
    static_assert(alignof(CounterBlock) == 64);
    static_assert(sizeof(CounterBlock) % 64 == 0);
    Stats stats(3);
    stats.block(0).add(Counter::UrlsRead, 5);
    stats.block(1).add(Counter::UrlsRead);
    stats.block(2).add(Counter::Links, 1500);
    stats.block(2).set(Counter::Inflight, 7);
    stats.block(1).set(Counter::Inflight, 3);
    const Snapshot s = stats.snapshot();
    CHECK(s[Counter::UrlsRead] == 6);
    CHECK(s[Counter::Links] == 1500);
    CHECK(s[Counter::Inflight] == 10);
    CHECK(s[Counter::PagesOk] == 0);
}

TEST_CASE("stats: status and rate lines use the course format") {
    Snapshot s;
    s[Counter::Inflight] = 512;
    s[Counter::UrlsRead] = 12345;
    s[Counter::UniqueHosts] = 10000;
    s[Counter::DnsOk] = 7000;
    s[Counter::UniqueIps] = 6000;
    s[Counter::RobotsPassed] = 3000;
    s[Counter::PagesOk] = 2500;
    s[Counter::Links] = 123456;
    CHECK(format_status(s, 4.9, 987655) ==
          "[  4]    512 Q  987655 E   12345 H  10000 D   7000 I  6000 R  3000 C  2500 L  123K");
    CHECK(format_rate(123.45, 9.87) == "      *** crawling 123.5 pps @ 9.9 Mbps");
}

TEST_CASE("stats: summary keeps the original wording") {
    Snapshot s;
    s[Counter::UrlsRead] = 1000;
    s[Counter::UniqueHosts] = 800;
    s[Counter::RobotsAttempted] = 500;
    s[Counter::PagesOk] = 200;
    s[Counter::BytesReceived] = 3 * 1024 * 1024 / 2;
    s[Counter::Links] = 4000;
    s[Counter::Http2xx] = 150;
    s[Counter::Http3xx] = 30;
    s[Counter::Http4xx] = 15;
    s[Counter::Http5xx] = 4;
    s[Counter::HttpOther] = 1;
    s[Counter::DnsOk] = 600;
    s[Counter::DnsFail] = 200;
    RunInfo info{"classic", 8, 4000, 10.0, 321};
    const std::string text = format_summary(s, info);
    CHECK(text.find("Extracted 1000 URLs @ 100/s\n") == 0);
    CHECK(text.find("Looked up 800 DNS names @ 80/s\n") != std::string::npos);
    CHECK(text.find("Attempted 500 site robots @ 50/s\n") != std::string::npos);
    CHECK(text.find("Crawled 200 pages @ 20/s (1.50 MB)\n") != std::string::npos);
    CHECK(text.find("Parsed 4000 links @ 400/s\n") != std::string::npos);
    CHECK(text.find("HTTP codes: 2xx = 150, 3xx = 30, 4xx = 15, 5xx = 4, other = 1\n") != std::string::npos);
    CHECK(text.find("75.0% success") != std::string::npos);
    CHECK(text.find("Peak in-flight 321") != std::string::npos);
}

TEST_CASE("stats: json carries every schema key in order") {
    Snapshot s;
    s[Counter::UrlsRead] = 42;
    s[Counter::DnsTimeouts] = 3;
    s[Counter::Inflight] = 9;  // gauge, not part of the schema
    RunInfo info{"real", 2, 100, 1.5, 77};
    const std::string json = format_json(s, info);
    CHECK(json.front() == '{');
    CHECK(json.substr(json.size() - 2) == "}\n");
    CHECK(json.find("\"mode\":\"real\",\"threads\":2,\"concurrency\":100,\"elapsed_s\":1.500,\"urls_read\":42,") == 1);
    CHECK(json.find("\"dns_timeouts\":3,\"peak_inflight\":77}") != std::string::npos);
    CHECK(json.find("inflight\":9") == std::string::npos);
    size_t prev = 0;
    for (const char* key :
         {"mode", "threads", "concurrency", "elapsed_s", "urls_read", "urls_parsed", "unique_hosts", "dns_ok",
          "dns_fail", "unique_ips", "robots_attempted", "robots_passed", "pages_attempted", "pages_ok", "http_2xx",
          "http_3xx", "http_4xx", "http_5xx", "http_other", "links", "bytes_received", "connect_fail", "timeouts",
          "tls_fail", "tls_cert_fail", "port_exhaustion", "other_fail", "redirects_followed", "dns_queries_sent",
          "dns_retries", "dns_timeouts", "peak_inflight"}) {
        const size_t at = json.find("\"" + std::string(key) + "\":");
        CHECK_MESSAGE(at != std::string::npos, key);
        CHECK_MESSAGE(at >= prev, key);
        prev = at;
    }
}

TEST_CASE("stats: reporter prints periodic lines and tracks peak in-flight") {
    Stats stats(2);
    FILE* out = std::tmpfile();
    REQUIRE(out != nullptr);
    Reporter reporter(stats, 10, 100, out);
    reporter.start();
    stats.block(0).set(Counter::Inflight, 5);
    stats.block(1).set(Counter::Inflight, 6);
    stats.block(0).add(Counter::UrlsRead, 4);
    std::this_thread::sleep_for(std::chrono::milliseconds(350));
    stats.block(0).set(Counter::Inflight, 0);
    stats.block(1).set(Counter::Inflight, 1);
    reporter.stop();
    CHECK(reporter.peak_inflight() == 11);
    CHECK(reporter.elapsed_s() >= 0.3);
    const double frozen = reporter.elapsed_s();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(reporter.elapsed_s() == frozen);

    std::rewind(out);
    std::string text;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), out)) > 0) {
        text.append(buf, n);
    }
    std::fclose(out);
    CHECK(text.find("Q       6 E       4 H") != std::string::npos);
    CHECK(text.find("*** crawling") != std::string::npos);
}
