// Politeness end to end: the engine crawls the benchmark rig's fake DNS and
// HTTP servers, which record per destination IP how many connections were
// open at once and the gap between connection starts, and per host when each
// request arrived (docs/politeness.md).

#include "crawl/engine.h"

#include "benchsrv/behavior.h"
#include "benchsrv/dns_server.h"
#include "benchsrv/http_server.h"
#include "crawl/ipranges.h"
#include "doctest/doctest.h"
#include "net/addr.h"
#include "net/loop.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace wc;
namespace bs = wc::benchsrv;
using crawl::Counter;

namespace {

// Loop timers tick every ~15.6 ms; the gates use a finer clock and re-arm
// when a timer fires early, but the server's accept times carry a little
// scheduling noise of their own.
constexpr double kClockSlackMs = 16;

uint32_t loopback_ip(uint8_t last) {
    return htonl(0x7F000000u | last);
}

// The rig's servers: HTTP on 127.0.0.1..ips (one port), DNS on 127.0.0.1.
struct Rig {
    Rig(const bs::Behavior& behavior, uint8_t ips) : dns(behavior) {
        net::startup();
        bs::HttpServerConfig hc;
        hc.threads = 4;
        hc.track = true;
        for (int attempt = 0; attempt < 5 && !http; ++attempt) {
            auto server = std::make_unique<bs::HttpServer>(behavior, hc);
            std::vector<sockaddr_in> locals;
            for (uint8_t i = 1; i <= ips; ++i) {
                locals.push_back(net::make_addr(loopback_ip(i), 0));  // 0 after the first: same port
            }
            if (server->start(locals) == 0) {
                http = std::move(server);
            }
        }
        REQUIRE(http);
        port = ntohs(http->local_address().sin_port);
        REQUIRE(dns.start(net::make_addr(loopback_ip(1), 0)) == 0);
        dns_port = ntohs(dns.local_address().sin_port);
    }

    std::string url(uint64_t host) const {
        return "http://h" + std::to_string(host) + ".bench.test:" + std::to_string(port) + "/p/1\n";
    }

    // Connections count once the server has seen them closed; the crawler
    // resets them on its way out, so wait for those resets to land.
    const bs::IpTrack& track(uint8_t last) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (http->counters().active != 0 && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        tracks = http->ip_tracks();
        for (const bs::IpTrack& t : tracks) {
            if (t.ip == loopback_ip(last)) {
                return t;
            }
        }
        static const bs::IpTrack none;
        return none;
    }
    bs::DnsServer dns;
    std::unique_ptr<bs::HttpServer> http;
    std::vector<bs::IpTrack> tracks;
    uint16_t port = 0;
    uint16_t dns_port = 0;
};

// A world with every host present and well-behaved unless a test says
// otherwise.
bs::Behavior world() {
    bs::Behavior b;
    b.ip_share = 0;
    b.nxdomain = 0;
    b.robots_404 = 1;
    b.page_kb = 2;
    b.links = 4;
    b.redirect = 0;
    b.not_found = 0;
    b.server_error = 0;
    b.chunked = 0;
    return b;
}

crawl::Config config(const Rig& rig) {
    crawl::Config cfg;
    cfg.threads = 4;
    cfg.concurrency = 512;
    cfg.dns_servers = {crawl::DnsServer{loopback_ip(1), rig.dns_port}};
    cfg.dns_inflight = 256;
    cfg.dns_timeout_ms = 1000;
    cfg.dns_attempts = 2;
    cfg.connect_timeout_ms = 1000;
    cfg.timeout_ms = 5000;
    cfg.robots_limit = crawl::kClassicRobotsLimit;
    cfg.page_limit = 256 * 1024;
    cfg.quiet = true;
    cfg.hosts_per_ip = 0;
    cfg.cdn_policy = false;
    return cfg;
}

std::string temp_record_path(const char* tag) {
    char dir[MAX_PATH];
    REQUIRE(GetTempPathA(MAX_PATH, dir) != 0);
    return std::string(dir) + "wc_polite_" + tag + "_" + std::to_string(GetCurrentProcessId()) + ".jsonl";
}

struct Result {
    crawl::Snapshot s;
    double secs = 0;
    std::map<std::string, std::string> records;  // by host
};

Result crawl_urls(crawl::Config cfg, const std::string& urls, const char* record_tag = nullptr) {
    if (record_tag != nullptr) {
        cfg.record_path = temp_record_path(record_tag);
    }
    crawl::UrlInput input;
    input.assign(urls);
    crawl::Stats stats(cfg.threads);
    Result r;
    {
        crawl::Engine engine(cfg, input, stats);
        const auto t0 = std::chrono::steady_clock::now();
        std::string error;
        REQUIRE(engine.run(error));
        r.secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    }
    r.s = stats.snapshot();
    CHECK(r.s[Counter::Inflight] == 0);
    CHECK(r.s[Counter::PoliteWaiting] == 0);
    if (record_tag != nullptr) {
        std::ifstream in(cfg.record_path, std::ios::binary);
        std::string line;
        const std::string key = "\"host\":\"";
        while (std::getline(in, line)) {
            const size_t at = line.find(key);
            REQUIRE(at != std::string::npos);
            const size_t end = line.find('"', at + key.size());
            r.records[line.substr(at + key.size(), end - at - key.size())] = line;
        }
        in.close();
        DeleteFileA(cfg.record_path.c_str());
    }
    return r;
}

std::string host_name(uint64_t n) {
    return "h" + std::to_string(n) + ".bench.test";
}

bool has(const std::string& line, const std::string& fragment) {
    return line.find(fragment) != std::string::npos;
}

}  // namespace

TEST_CASE("polite: per-IP caps hold under load and CDN ranges are exempt") {
    // 2,000 hosts on 5 IPs: 100 each on 127.0.0.1-4 (ordinary: 2 connections,
    // 10 ms apart) and 1,600 on 127.0.0.5, declared a CDN edge (32
    // connections, no spacing). Every request takes ~20 ms, so demand
    // exceeds both caps and they bind.
    bs::Behavior b = world();
    b.ip_pool = 5;
    b.http_delay = bs::Delay{20, 0};
    Rig rig(b, 5);
    std::string urls;
    for (uint64_t k = 0; k < 1600; ++k) {
        urls += rig.url(5 * k + 4);  // host 5k+4 -> 127.0.0.5
        if (k < 100) {
            for (uint64_t r = 0; r < 4; ++r) {
                urls += rig.url(5 * k + r);
            }
        }
    }
    crawl::Ipv4Ranges cdn;
    std::string error;
    REQUIRE(cdn.parse("127.0.0.5/32\n", error));
    crawl::Config cfg = config(rig);
    cfg.ip_concurrency = 2;
    cfg.ip_interval_ms = 10;
    cfg.cdn_policy = true;
    cfg.cdn_ranges = &cdn;
    cfg.cdn_ip_concurrency = 32;
    cfg.cdn_ip_interval_ms = 0;

    const Result r = crawl_urls(cfg, urls);
    CHECK(r.s[Counter::UniqueHosts] == 2000);
    CHECK(r.s[Counter::UniqueIps] == 5);
    CHECK(r.s[Counter::IpExtraHosts] == 1995);
    CHECK(r.s[Counter::IpBudgetSkips] == 0);
    CHECK(r.s[Counter::CdnHosts] == 1600);
    CHECK(r.s[Counter::RobotsAttempted] == 2000);
    CHECK(r.s[Counter::PagesOk] == 2000);
    CHECK(r.s[Counter::Http2xx] == 2000);
    CHECK(r.s[Counter::PoliteWaits] > 0);
    for (uint8_t i = 1; i <= 4; ++i) {
        const bs::IpTrack& t = rig.track(i);
        CAPTURE(int(i));
        CHECK(t.accepts == 100);  // robots and page share one keep-alive connection
        CHECK(t.max_open == 2);   // the cap binds and holds
        CHECK(t.min_gap_ms >= 10 - kClockSlackMs);
    }
    const bs::IpTrack& edge = rig.track(5);
    CHECK(edge.accepts == 1600);
    CHECK(edge.max_open > 2);    // exempt from the ordinary cap
    CHECK(edge.max_open <= 32);  // but within its own
    MESSAGE("CDN IP: at most " << edge.max_open << " connections at once; run " << r.secs << " s");
}

TEST_CASE("polite: connection starts to one IP are spaced") {
    // Two IPs, 10 hosts each, 200 ms apart: spacing, not the cap, decides,
    // and the two IPs proceed in parallel.
    bs::Behavior b = world();
    b.ip_pool = 2;
    Rig rig(b, 2);
    std::string urls;
    for (uint64_t n = 0; n < 20; ++n) {
        urls += rig.url(n);
    }
    crawl::Config cfg = config(rig);
    cfg.ip_concurrency = 2;
    cfg.ip_interval_ms = 200;

    const Result r = crawl_urls(cfg, urls);
    CHECK(r.s[Counter::PagesOk] == 20);
    for (uint8_t i = 1; i <= 2; ++i) {
        const bs::IpTrack& t = rig.track(i);
        CAPTURE(int(i));
        CHECK(t.accepts == 10);
        CHECK(t.min_gap_ms >= 200 - kClockSlackMs);
    }
    CHECK(r.secs >= 9 * 0.2 - 0.05);
    CHECK(r.secs < 9 * 0.2 + 1.5);  // not 2 x 1.8 s: the IPs are independent
}

TEST_CASE("polite: the per-IP host budget") {
    bs::Behavior b = world();
    b.ip_pool = 2;
    Rig rig(b, 2);
    std::string urls;
    for (uint64_t n = 0; n < 10; ++n) {
        urls += rig.url(n);
    }
    crawl::Config cfg = config(rig);
    cfg.mode = crawl::Mode::Real;
    cfg.robots_limit = crawl::kRealRobotsLimit;
    cfg.hosts_per_ip = 3;
    cfg.ip_interval_ms = 0;

    const Result r = crawl_urls(cfg, urls, "budget");
    CHECK(r.s[Counter::DnsOk] == 10);
    CHECK(r.s[Counter::UniqueIps] == 2);
    CHECK(r.s[Counter::IpExtraHosts] == 4);
    CHECK(r.s[Counter::IpBudgetSkips] == 4);
    CHECK(r.s[Counter::RobotsAttempted] == 6);
    CHECK(r.s[Counter::PagesOk] == 6);
    REQUIRE(r.records.size() == 10);
    size_t skipped = 0;
    for (const auto& [host, line] : r.records) {
        CAPTURE(line);
        if (has(line, "\"skip\":\"ip_budget\"")) {
            ++skipped;
            CHECK(has(line, "\"ip_dup\":true"));
            CHECK(has(line, "\"robots_status\":null"));
        } else {
            CHECK(has(line, "\"ip_dup\":false"));
            CHECK(has(line, "\"skip\":null"));
            CHECK(has(line, "\"status\":200"));
        }
    }
    CHECK(skipped == 4);
}

TEST_CASE("polite: Crawl-delay is honoured without holding a slot") {
    bs::Behavior b = world();
    b.robots_404 = 0;
    b.crawl_delay = 1;  // every robots.txt says Crawl-delay: 1
    b.crawl_delay_s = 1;
    Rig rig(b, 8);  // hosts 0..7 resolve to their own 127.0.0.1..8
    std::string urls;
    for (uint64_t n = 0; n < 8; ++n) {
        urls += rig.url(n);
    }
    crawl::Config cfg = config(rig);
    cfg.mode = crawl::Mode::Real;
    cfg.robots_limit = crawl::kRealRobotsLimit;
    cfg.threads = 1;
    cfg.concurrency = 2;  // if the waits held slots this would take 4 s
    cfg.hosts_per_ip = 1;

    const Result r = crawl_urls(cfg, urls, "delay");
    CHECK(r.s[Counter::PagesOk] == 8);
    CHECK(r.s[Counter::CrawlDelayWaits] == 8);
    CHECK(r.s[Counter::CrawlDelayMs] >= 8 * (1000 - static_cast<uint64_t>(kClockSlackMs)));
    CHECK(r.secs < 2.5);
    for (uint64_t n = 0; n < 8; ++n) {
        const std::vector<bs::RequestEvent> ev = rig.http->host_requests(n);
        CAPTURE(n);
        REQUIRE(ev.size() == 2);
        CHECK(ev[0].robots);
        CHECK_FALSE(ev[1].robots);
        CHECK(ev[1].t_ms - ev[0].t_ms >= 1000 - kClockSlackMs);
        const std::string& line = r.records.at(host_name(n));
        CAPTURE(line);
        CHECK(has(line, "\"crawl_delay\":1,"));
        CHECK(has(line, "\"skip\":null"));
        CHECK(has(line, "\"status\":200"));
    }
}

TEST_CASE("polite: a Crawl-delay above the cap skips the page") {
    bs::Behavior b = world();
    b.robots_404 = 0;
    b.crawl_delay = 1;
    b.crawl_delay_s = 5;
    Rig rig(b, 4);
    std::string urls;
    for (uint64_t n = 0; n < 4; ++n) {
        urls += rig.url(n);
    }
    crawl::Config cfg = config(rig);
    cfg.mode = crawl::Mode::Real;
    cfg.robots_limit = crawl::kRealRobotsLimit;
    cfg.max_crawl_delay_s = 2;

    const Result r = crawl_urls(cfg, urls, "delayskip");
    CHECK(r.s[Counter::RobotsPassed] == 4);
    CHECK(r.s[Counter::CrawlDelaySkips] == 4);
    CHECK(r.s[Counter::PagesAttempted] == 0);
    CHECK(r.secs < 2.0);
    for (uint64_t n = 0; n < 4; ++n) {
        CHECK(rig.http->host_requests(n).size() == 1);
        const std::string& line = r.records.at(host_name(n));
        CAPTURE(line);
        CHECK(has(line, "\"robots_allowed\":true,\"fetch\":null"));
        CHECK(has(line, "\"skip\":\"crawl_delay\""));
        CHECK(has(line, "\"crawl_delay\":5,"));
    }
}

TEST_CASE("polite: 429 with Retry-After is waited out once") {
    bs::Behavior b = world();
    b.throttle = 1;  // every host's first page request gets 429
    SUBCASE("within the cap: one retry") {
        b.retry_after_s = 1;
        Rig rig(b, 6);
        std::string urls;
        for (uint64_t n = 0; n < 6; ++n) {
            urls += rig.url(n);
        }
        crawl::Config cfg = config(rig);
        cfg.mode = crawl::Mode::Real;
        cfg.robots_limit = crawl::kRealRobotsLimit;
        cfg.hosts_per_ip = 1;

        const Result r = crawl_urls(cfg, urls, "retry");
        CHECK(r.s[Counter::Throttled] == 6);
        CHECK(r.s[Counter::RetryAfterRetries] == 6);
        CHECK(r.s[Counter::PagesOk] == 6);
        CHECK(r.s[Counter::Http2xx] == 6);
        CHECK(r.secs < 3.0);
        for (uint64_t n = 0; n < 6; ++n) {
            const std::vector<bs::RequestEvent> ev = rig.http->host_requests(n);
            CAPTURE(n);
            REQUIRE(ev.size() == 3);  // robots, 429, 200
            CHECK(ev[1].status == 429);
            CHECK(ev[2].status == 200);
            CHECK(ev[2].t_ms - ev[1].t_ms >= 1000 - kClockSlackMs);
            const std::string& line = r.records.at(host_name(n));
            CAPTURE(line);
            CHECK(has(line, "\"status\":200"));
            CHECK(has(line, "\"retry_after\":1,\"retried\":true}"));
            CHECK(has(line, "\"wait_ms\":"));
        }
    }
    SUBCASE("above the cap: no retry") {
        b.retry_after_s = 5;
        Rig rig(b, 3);
        std::string urls;
        for (uint64_t n = 0; n < 3; ++n) {
            urls += rig.url(n);
        }
        crawl::Config cfg = config(rig);
        cfg.mode = crawl::Mode::Real;
        cfg.robots_limit = crawl::kRealRobotsLimit;
        cfg.hosts_per_ip = 1;
        cfg.max_retry_after_s = 2;

        const Result r = crawl_urls(cfg, urls, "noretry");
        CHECK(r.s[Counter::Throttled] == 3);
        CHECK(r.s[Counter::RetryAfterRetries] == 0);
        CHECK(r.s[Counter::Http4xx] == 3);
        CHECK(r.secs < 2.0);
        for (uint64_t n = 0; n < 3; ++n) {
            CHECK(rig.http->host_requests(n).size() == 2);
            const std::string& line = r.records.at(host_name(n));
            CAPTURE(line);
            CHECK(has(line, "\"status\":429"));
            CHECK(has(line, "\"retry_after\":5,\"retried\":false}"));
        }
    }
}

TEST_CASE("polite: an unreachable IP's other hosts are skipped") {
    // Hosts alternate between 127.0.0.1 (served) and 127.0.0.2 (nothing
    // listens): after 3 failed connections in a row .2 counts as unreachable.
    bs::Behavior b = world();
    b.ip_pool = 2;
    Rig rig(b, 1);
    std::string urls;
    for (uint64_t n = 0; n < 40; ++n) {
        urls += rig.url(n);
    }
    crawl::Config cfg = config(rig);
    cfg.connect_timeout_ms = 300;
    cfg.ip_concurrency = 2;
    cfg.ip_interval_ms = 0;
    cfg.ip_fail_limit = 3;

    const Result r = crawl_urls(cfg, urls, "dead");
    CHECK(r.s[Counter::PagesOk] == 20);
    CHECK(r.s[Counter::ConnectFail] >= 3);
    CHECK(r.s[Counter::ConnectFail] <= 4);  // two in flight when the third failure lands
    CHECK(r.s[Counter::ConnectFail] + r.s[Counter::IpUnreachable] == 20);
    CHECK(r.secs < 3.0);
    size_t unreachable = 0;
    for (const auto& [host, line] : r.records) {
        unreachable += has(line, "\"skip\":\"ip_unreachable\"") ? 1 : 0;
    }
    CHECK(unreachable == r.s[Counter::IpUnreachable]);
}

TEST_CASE("polite: a huge IP does not starve the loop, and Ctrl+C drains its queue") {
    // 300 hosts on 127.0.0.1 (one connection, 100 ms apart: 30 s of work)
    // come first in the input, then 50 hosts on 50 other IPs. The queued
    // hosts hold no task slots, so the 50 finish at once; then the run is
    // stopped with ~290 hosts still queued and must end promptly.
    bs::Behavior b = world();
    b.ip_pool = 60;
    Rig rig(b, 51);
    std::string urls;
    for (uint64_t k = 0; k < 300; ++k) {
        urls += rig.url(60 * k);  // -> 127.0.0.1
    }
    for (uint64_t n = 1; n <= 50; ++n) {
        urls += rig.url(n);  // -> 127.0.0.2 .. 51
    }
    crawl::Config cfg = config(rig);
    cfg.threads = 2;
    cfg.concurrency = 8;
    cfg.ip_concurrency = 1;
    cfg.ip_interval_ms = 100;
    cfg.record_path = temp_record_path("stop");

    crawl::UrlInput input;
    input.assign(urls);
    crawl::Stats stats(cfg.threads);
    crawl::Engine engine(cfg, input, stats);
    std::atomic<bool> others_done{false};
    double stop_at = 0;
    const auto t0 = std::chrono::steady_clock::now();
    std::thread stopper([&] {
        while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(10)) {
            size_t done = 0;
            for (uint64_t n = 1; n <= 50; ++n) {
                done += rig.http->host_requests(n).size() == 2 ? 1 : 0;
            }
            if (done == 50) {
                others_done = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        stop_at = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        engine.request_stop();
    });
    std::string error;
    REQUIRE(engine.run(error));
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    stopper.join();
    CHECK(others_done.load());
    CHECK(stop_at < 3.0);
    CHECK(secs - stop_at < 1.0);
    const crawl::Snapshot s = stats.snapshot();
    CHECK(s[Counter::Inflight] == 0);
    CHECK(s[Counter::UniqueHosts] == 350);
    const uint64_t big_ip_fetched = rig.track(1).accepts;
    CHECK(big_ip_fetched < 60);
    CHECK(engine.records_written() == 350);  // queued hosts still get a record
    // Never attempted because of the stop: marked apart, not as failures.
    CHECK(s[Counter::StoppedHosts] >= 300 - big_ip_fetched - 1);
    CHECK(s[Counter::RobotsAttempted] + s[Counter::StoppedHosts] <= 350);
    std::ifstream in(cfg.record_path, std::ios::binary);
    std::string line;
    size_t stopped = 0;
    while (std::getline(in, line)) {
        if (has(line, "\"skip\":\"stopped\"")) {
            ++stopped;
            CHECK(has(line, "\"robots_error\":null"));
        }
    }
    in.close();
    DeleteFileA(cfg.record_path.c_str());
    CHECK(stopped == s[Counter::StoppedHosts]);
}
