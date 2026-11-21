#include "crawl/engine.h"

#include "crawl/tests/fake_servers.h"
#include "doctest/doctest.h"

#include <chrono>
#include <string>
#include <thread>

using namespace wc::crawl;
using namespace wc::crawl::test;

namespace {

Config base_config(uint16_t dns_port) {
    Config cfg;
    cfg.threads = 2;
    cfg.concurrency = 16;
    cfg.dns_servers = {DnsServer{loopback_ip(1), dns_port}};
    cfg.dns_inflight = 8;
    cfg.dns_timeout_ms = 500;
    cfg.dns_attempts = 2;
    cfg.connect_timeout_ms = 300;
    cfg.timeout_ms = 800;
    cfg.robots_limit = kClassicRobotsLimit;
    cfg.page_limit = 64 * 1024;
    cfg.quiet = true;
    return cfg;
}

Snapshot crawl(const Config& cfg, const std::string& urls) {
    UrlInput input;
    input.assign(urls);
    Stats stats(cfg.threads);
    Engine engine(cfg, input, stats);
    std::string error;
    REQUIRE(engine.run(error));
    const Snapshot s = stats.snapshot();
    CHECK(s[Counter::Inflight] == 0);
    return s;
}

std::string url(const char* host, uint16_t port, const char* path = "/") {
    return std::string("http://") + host + ":" + std::to_string(port) + path + "\n";
}

const char* kHtml = "Content-Type: text/html\r\n";

}  // namespace

TEST_CASE("engine: classic pipeline counts on a synthetic URL set") {
    ServerThread srv;
    FakeDns dns(srv);
    FakeHttp http(srv);

    const uint16_t pa = http.listen(loopback_ip(11));
    const uint16_t pb = http.listen(loopback_ip(12));
    const uint16_t pe = http.listen(loopback_ip(14));
    const uint16_t pf = http.listen(loopback_ip(15));
    const uint16_t pg = http.listen(loopback_ip(16));
    const uint16_t ph = http.listen(loopback_ip(17));
    const uint16_t pi = http.listen(loopback_ip(18));
    const uint16_t pj = http.listen(loopback_ip(19));

    dns.add("a.test", loopback_ip(11));
    dns.add("b.test", loopback_ip(12));
    dns.add("c.test", loopback_ip(12));  // same IP as b.test
    dns.add("d.test", loopback_ip(13));  // nothing listens there
    dns.add("e.test", loopback_ip(14));
    dns.add("f.test", loopback_ip(15));
    dns.add("g.test", loopback_ip(16));
    dns.add("h.test", loopback_ip(17));
    dns.add("i.test", loopback_ip(18));
    dns.add("j.test", loopback_ip(19));
    const uint16_t dns_port = dns.start();
    REQUIRE(dns_port != 0);

    for (const char* h : {"a.test", "e.test", "f.test", "g.test", "h.test", "j.test"}) {
        http.route(h, "/robots.txt", Route{reply(404, "")});
    }
    for (const char* h : {"b.test", "c.test"}) {
        http.route(h, "/robots.txt", Route{reply(200, "User-agent: *\nDisallow:\n")});
        http.route(h, "/", Route{reply(200, "<a href=/never>")});
    }
    http.route("i.test", "/robots.txt", Route{reply(404, "", {}, true)});  // Connection: close
    http.route("a.test", "/", Route{reply(200, "<a href=\"/1\">1</a><A HREF='/2'>2</A><a href=http://x.test/3>3</a>", kHtml)});
    Route hang;
    hang.hang = true;
    http.route("e.test", "/", hang);
    http.route("f.test", "/", Route{reply(200, std::string(100 * 1024, 'x'))});
    http.route("g.test", "/", Route{chunked_reply(200, {"<a hr", "ef=/g1>x</a><a href='/g2'>y</a>"}, kHtml)});
    http.route("h.test", "/", Route{reply(302, "", "Location: /elsewhere\r\n")});
    http.route("i.test", "/", Route{reply(200, "<a href=/only>only</a>")});
    http.route("j.test", "/", Route{reply(500, "oops")});

    std::string urls;
    urls += url("a.test", pa);
    urls += url("b.test", pb);
    urls += url("A.TEST", pa);  // duplicate host (case-insensitive)
    urls += url("c.test", pb);  // duplicate IP
    urls += url("nx.test", pa); // NXDOMAIN
    urls += url("d.test", pa);  // connect fails
    urls += url("e.test", pe);  // page never answers: timeout
    urls += url("f.test", pf);  // page over the limit
    urls += url("g.test", pg);  // chunked page
    urls += url("h.test", ph);  // 3xx (not followed in classic mode)
    urls += url("i.test", pi);  // robots closes the connection: page reconnects
    urls += url("j.test", pj);  // 5xx
    urls += "not a url\r\n\r\n";
    urls += "https://k.test/\n";  // classic mode is http only

    const Snapshot s = crawl(base_config(dns_port), urls);
    CHECK(s[Counter::UrlsRead] == 14);
    CHECK(s[Counter::UrlsParsed] == 12);
    CHECK(s[Counter::UniqueHosts] == 11);
    CHECK(s[Counter::DnsOk] == 10);
    CHECK(s[Counter::DnsFail] == 1);
    CHECK(s[Counter::UniqueIps] == 9);
    CHECK(s[Counter::RobotsAttempted] == 9);
    CHECK(s[Counter::RobotsPassed] == 7);
    CHECK(s[Counter::PagesAttempted] == 7);
    CHECK(s[Counter::PagesOk] == 5);
    CHECK(s[Counter::Http2xx] == 3);
    CHECK(s[Counter::Http3xx] == 1);
    CHECK(s[Counter::Http4xx] == 0);
    CHECK(s[Counter::Http5xx] == 1);
    CHECK(s[Counter::HttpOther] == 0);
    CHECK(s[Counter::Links] == 6);
    CHECK(s[Counter::ConnectFail] == 1);
    CHECK(s[Counter::Timeouts] == 1);
    CHECK(s[Counter::OtherFail] == 1);  // f.test: page over the limit
    CHECK(s[Counter::PortExhaustion] == 0);
    CHECK(s[Counter::TlsFail] == 0);
    CHECK(s[Counter::RedirectsFollowed] == 0);
    CHECK(s[Counter::BytesReceived] > 0);
    CHECK(s[Counter::DnsQueriesSent] >= 11);

    // Keep-alive: robots and page on one connection; Connection: close forces two.
    CHECK(http.accepts(loopback_ip(11)) == 1);
    CHECK(http.requests("a.test", "/robots.txt") == 1);
    CHECK(http.requests("a.test", "/") == 1);
    CHECK(http.accepts(loopback_ip(18)) == 2);
    CHECK(http.accepts(loopback_ip(12)) == 1);
    CHECK(http.requests("b.test", "/") + http.requests("c.test", "/") == 0);
}

TEST_CASE("engine: classic --no-keepalive uses one connection per request") {
    ServerThread srv;
    FakeDns dns(srv);
    FakeHttp http(srv);
    const uint16_t port = http.listen(loopback_ip(41));
    dns.add("a.test", loopback_ip(41));
    const uint16_t dns_port = dns.start();
    http.route("a.test", "/robots.txt", Route{reply(404, "")});
    http.route("a.test", "/p", Route{reply(200, "<a href=/1>1</a>")});

    Config cfg = base_config(dns_port);
    cfg.keepalive = false;
    const Snapshot s = crawl(cfg, url("a.test", port, "/p"));
    CHECK(s[Counter::PagesOk] == 1);
    CHECK(s[Counter::Links] == 1);
    CHECK(http.accepts(loopback_ip(41)) == 2);
}

TEST_CASE("engine: real mode follows redirects and honours robots.txt") {
    ServerThread srv;
    FakeDns dns(srv);
    FakeHttp http(srv);
    uint16_t port[7] = {};
    for (uint8_t i = 1; i <= 6; ++i) {
        port[i] = http.listen(loopback_ip(static_cast<uint8_t>(20 + i)));
        dns.add("r" + std::to_string(i) + ".test", loopback_ip(static_cast<uint8_t>(20 + i)));
    }
    const uint16_t dns_port = dns.start();

    // r1: robots disallows the page.
    http.route("r1.test", "/robots.txt", Route{reply(200, "User-agent: *\nDisallow: /private\n")});
    http.route("r1.test", "/private/x", Route{reply(200, "secret", kHtml)});
    // r2: same-origin redirect on the kept-alive connection.
    http.route("r2.test", "/robots.txt", Route{reply(404, "")});
    http.route("r2.test", "/old", Route{reply(301, "", "Location: /new\r\n")});
    http.route("r2.test", "/new", Route{reply(200, "<a href=/a>a</a> <a href=/b>b</a>", kHtml)});
    // r3 -> r4: cross-host redirect; r4's robots.txt disallows wincrawl there.
    http.route("r3.test", "/robots.txt", Route{reply(404, "")});
    const std::string r4 = "http://r4.test:" + std::to_string(port[4]) + "/landing";
    http.route("r3.test", "/", Route{reply(302, "", "Location: " + r4 + "\r\n")});
    http.route("r4.test", "/robots.txt",
               Route{reply(200, "User-agent: wincrawl\nDisallow: /landing\n\nUser-agent: *\nAllow: /\n")});
    http.route("r4.test", "/landing", Route{reply(200, "<a href=/z>z</a>", kHtml)});
    // r5: robots.txt 5xx means disallow all.
    http.route("r5.test", "/robots.txt", Route{reply(500, "")});
    http.route("r5.test", "/", Route{reply(200, "<a href=/z>z</a>", kHtml)});
    // r6: redirected robots.txt allows; the page is not HTML, so no links.
    http.route("r6.test", "/robots.txt", Route{reply(301, "", "Location: /robots-real.txt\r\n")});
    http.route("r6.test", "/robots-real.txt", Route{reply(200, "User-agent: *\nAllow: /\n")});
    http.route("r6.test", "/", Route{reply(200, "<a href=/z>z</a>", "Content-Type: text/plain\r\n")});

    std::string urls;
    urls += url("r1.test", port[1], "/private/x");
    urls += url("r2.test", port[2], "/old");
    urls += url("r3.test", port[3], "/");
    urls += url("r5.test", port[5], "/");
    urls += url("r6.test", port[6], "/");

    Config cfg = base_config(dns_port);
    cfg.mode = Mode::Real;
    cfg.robots_limit = kRealRobotsLimit;
    const Snapshot s = crawl(cfg, urls);
    CHECK(s[Counter::UrlsRead] == 5);
    CHECK(s[Counter::UrlsParsed] == 5);
    CHECK(s[Counter::UniqueHosts] == 5);
    CHECK(s[Counter::DnsOk] == 5);
    CHECK(s[Counter::UniqueIps] == 5);
    CHECK(s[Counter::RobotsAttempted] == 5);
    CHECK(s[Counter::RobotsPassed] == 3);
    CHECK(s[Counter::PagesAttempted] == 3);
    CHECK(s[Counter::PagesOk] == 3);
    CHECK(s[Counter::Http2xx] == 2);
    CHECK(s[Counter::Http3xx] == 1);
    CHECK(s[Counter::Links] == 2);
    CHECK(s[Counter::RedirectsFollowed] == 2);

    CHECK(http.requests("r1.test", "/private/x") == 0);
    CHECK(http.accepts(loopback_ip(22)) == 1);
    CHECK(http.requests("r2.test", "/new") == 1);
    CHECK(http.requests("r4.test", "/robots.txt") == 1);
    CHECK(http.requests("r4.test", "/landing") == 0);
    CHECK(http.requests("r5.test", "/") == 0);
    CHECK(http.requests("r6.test", "/robots-real.txt") == 1);
    CHECK(http.requests("r6.test", "/") == 1);
}

TEST_CASE("engine: request_stop aborts in-flight work promptly") {
    ServerThread srv;
    FakeDns dns(srv);
    FakeHttp http(srv);
    Route hang;
    hang.hang = true;
    std::string urls;
    for (uint8_t i = 0; i < 12; ++i) {
        const uint8_t octet = static_cast<uint8_t>(60 + i);
        const std::string host = "s" + std::to_string(i) + ".test";
        const uint16_t port = http.listen(loopback_ip(octet));
        dns.add(host, loopback_ip(octet));
        http.route(host, "/robots.txt", hang);
        urls += url(host.c_str(), port);
    }
    const uint16_t dns_port = dns.start();

    Config cfg = base_config(dns_port);
    cfg.timeout_ms = 20000;  // only request_stop() can end this run quickly
    UrlInput input;
    input.assign(urls);
    Stats stats(cfg.threads);
    Engine engine(cfg, input, stats);
    std::thread stopper([&] {
        while (http.total_requests() < 12) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        engine.request_stop();
    });
    const auto t0 = std::chrono::steady_clock::now();
    std::string error;
    REQUIRE(engine.run(error));
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    stopper.join();
    CHECK(engine.stop_requested());
    CHECK(secs < 5.0);
    const Snapshot s = stats.snapshot();
    CHECK(s[Counter::RobotsAttempted] == 12);
    CHECK(s[Counter::PagesOk] == 0);
    CHECK(s[Counter::Inflight] == 0);
}
