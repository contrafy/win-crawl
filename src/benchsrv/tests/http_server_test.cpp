#include "benchsrv/http_server.h"

#include "net/loop.h"
#include "raw_client.h"

#include "doctest/doctest.h"

#include <chrono>
#include <thread>

using namespace wc::benchsrv;
using namespace wc::benchsrv::test;

namespace {

std::string get(std::string_view path, uint64_t host, std::string_view extra = "", std::string_view method = "GET",
                std::string_view version = "HTTP/1.1") {
    std::string r;
    r.append(method).append(" ").append(path).append(" ").append(version).append("\r\n");
    r += "Host: h" + std::to_string(host) + ".bench.test:8080\r\nUser-Agent: test\r\n";
    r.append(extra);
    r += "\r\n";
    return r;
}

// First host/path whose page plan matches `pred`.
template <class Pred>
std::pair<uint64_t, PagePlan> find_page(const Behavior& b, Pred pred) {
    for (uint64_t n = 0;; ++n) {
        const PagePlan p = page_plan(b, n, "/p/1");
        if (pred(p)) return {n, p};
    }
}

struct Fixture {
    Fixture(HttpServerConfig config = {}) : server(behavior, config) {
        wc::net::startup();
        REQUIRE(server.start(loopback(0)) == 0);
        addr = server.local_address();
        REQUIRE(addr.sin_port != 0);
    }
    static Behavior make_behavior() {
        Behavior b;
        b.page_kb = 8;
        b.links = 12;
        return b;
    }
    Behavior behavior = make_behavior();
    HttpServer server;
    sockaddr_in addr{};
};

}  // namespace

TEST_CASE("keep-alive serves several requests on one connection") {
    HttpServerConfig cfg;
    cfg.threads = 2;
    Fixture f(cfg);
    RawSocket s = tcp_connect(f.addr);
    REQUIRE(s.get() != INVALID_SOCKET);
    HttpReader reader(s.get());

    const auto [host, plan] = find_page(f.behavior, [](const PagePlan& p) { return p.kind == PageKind::Ok && !p.chunked; });
    REQUIRE(send_all(s.get(), get("/robots.txt", host)));
    HttpReply robots = reader.read();
    REQUIRE(robots.ok);
    CHECK(robots.status == (robots_missing(f.behavior, host) ? 404 : 200));
    CHECK(robots.header("Connection") == "keep-alive");

    REQUIRE(send_all(s.get(), get("/p/1", host)));
    HttpReply page = reader.read();
    REQUIRE(page.ok);
    CHECK(page.status == 200);
    CHECK(page.header("Content-Type") == "text/html; charset=utf-8");
    CHECK(page.body == f.server.responses().page_body(plan.template_index));

    // Pipelined: both requests in one segment, answered in order.
    REQUIRE(send_all(s.get(), get("/r/1", host) + get("/robots.txt", host)));
    HttpReply a = reader.read();
    HttpReply b = reader.read();
    CHECK(a.status == 200);
    CHECK(b.status == robots.status);
    CHECK(reader.buffered() == 0);

    const HttpCounters c = f.server.counters();
    CHECK(c.requests == 4);
    CHECK(c.accepted == 1);
    CHECK(c.robots == 2);
}

TEST_CASE("HEAD responses carry headers only") {
    Fixture f;
    RawSocket s = tcp_connect(f.addr);
    HttpReader reader(s.get());
    const auto [host, plan] = find_page(f.behavior, [](const PagePlan& p) { return p.kind == PageKind::Ok && !p.chunked; });
    REQUIRE(send_all(s.get(), get("/p/1", host, "", "HEAD")));
    HttpReply head = reader.read(true);
    REQUIRE(head.ok);
    CHECK(head.status == 200);
    CHECK(head.header("Content-Length") == std::to_string(f.server.responses().page_body(plan.template_index).size()));
    // If the server had sent a body, the next read would not start at a status line.
    REQUIRE(send_all(s.get(), get("/robots.txt", host, "", "HEAD")));
    HttpReply next = reader.read(true);
    REQUIRE(next.ok);
    CHECK(next.status == (robots_missing(f.behavior, host) ? 404 : 200));
    CHECK(reader.buffered() == 0);
}

TEST_CASE("Connection: close and HTTP/1.0 close after the response") {
    Fixture f;

    // Close-delimited readers need a clean FIN after the full body, not a reset.
    RawSocket s = tcp_connect(f.addr);
    HttpReader reader(s.get());
    REQUIRE(send_all(s.get(), get("/p/1", 3, "Connection: close\r\n")));
    HttpReply r = reader.read();
    REQUIRE(r.ok);
    CHECK(r.header("Connection") == "close");
    CHECK(reader.clean_eof());

    // HTTP/1.0 defaults to close; the legacy crawler reads to EOF.
    RawSocket s10 = tcp_connect(f.addr);
    HttpReader r10(s10.get());
    REQUIRE(send_all(s10.get(), get("/robots.txt", 3, "", "HEAD", "HTTP/1.0")));
    CHECK(r10.read(true).ok);
    CHECK(r10.clean_eof());

    // HTTP/1.0 with keep-alive stays open.
    RawSocket ska = tcp_connect(f.addr);
    HttpReader rka(ska.get());
    for (int i = 0; i < 2; ++i) {
        REQUIRE(send_all(ska.get(), get("/robots.txt", 3, "Connection: keep-alive\r\n", "GET", "HTTP/1.0")));
        HttpReply k = rka.read();
        REQUIRE(k.ok);
        CHECK(k.header("Connection") == "keep-alive");
    }
}

TEST_CASE("chunked responses are well formed") {
    Fixture f;
    const auto [host, plan] = find_page(f.behavior, [](const PagePlan& p) { return p.kind == PageKind::Ok && p.chunked; });
    RawSocket s = tcp_connect(f.addr);
    HttpReader reader(s.get());
    for (int i = 0; i < 2; ++i) {  // keep-alive after a chunked body
        REQUIRE(send_all(s.get(), get("/p/1", host)));
        HttpReply r = reader.read();
        REQUIRE(r.ok);
        CHECK_FALSE(r.framing_error);
        CHECK(r.chunked);
        CHECK(r.header("Content-Length").empty());
        CHECK(r.body == f.server.responses().page_body(plan.template_index));
    }
    CHECK(reader.buffered() == 0);
}

TEST_CASE("status codes and robots follow the deterministic model") {
    Fixture f;
    RawSocket s = tcp_connect(f.addr);
    HttpReader reader(s.get());
    size_t missing = 0;
    constexpr uint64_t kHosts = 300;
    for (uint64_t n = 0; n < kHosts; ++n) {
        REQUIRE(send_all(s.get(), get("/robots.txt", n, "", "HEAD")));
        HttpReply r = reader.read(true);
        REQUIRE(r.ok);
        CHECK(r.status == (robots_missing(f.behavior, n) ? 404 : 200));
        missing += r.status == 404 ? 1 : 0;

        REQUIRE(send_all(s.get(), get("/p/1", n)));
        HttpReply p = reader.read();
        REQUIRE(p.ok);
        const int expect[] = {200, 301, 404, 503};
        CHECK(p.status == expect[static_cast<int>(page_plan(f.behavior, n, "/p/1").kind)]);
        if (p.status == 301) CHECK(p.header("Location") == "/r/1");
    }
    CHECK(static_cast<double>(missing) / kHosts == doctest::Approx(f.behavior.robots_404).epsilon(0.2));

    // IP-literal Host headers key behaviour by address (127.0.0.(N+1)).
    for (uint64_t n = 0; n < 20; ++n) {
        std::string req = "HEAD /robots.txt HTTP/1.1\r\nHost: 127.0.0." + std::to_string(n + 1) + ":8080\r\n\r\n";
        REQUIRE(send_all(s.get(), req));
        HttpReply r = reader.read(true);
        CHECK(r.status == (robots_missing(f.behavior, n) ? 404 : 200));
    }
    // Without a Host header the local address (127.0.0.1 = host 0) decides.
    REQUIRE(send_all(s.get(), "HEAD /robots.txt HTTP/1.1\r\n\r\n"));
    CHECK(reader.read(true).status == (robots_missing(f.behavior, 0) ? 404 : 200));
}

TEST_CASE("bad and unsupported requests get an error and a close") {
    Fixture f;
    {
        RawSocket s = tcp_connect(f.addr);
        HttpReader reader(s.get());
        REQUIRE(send_all(s.get(), "BROKEN\r\n\r\n"));
        CHECK(reader.read().status == 400);
        CHECK(reader.at_eof());
    }
    {
        RawSocket s = tcp_connect(f.addr);
        HttpReader reader(s.get());
        REQUIRE(send_all(s.get(), "DELETE / HTTP/1.1\r\nHost: h1.bench.test\r\n\r\n"));
        CHECK(reader.read().status == 501);
        CHECK(reader.at_eof());
    }
    {
        RawSocket s = tcp_connect(f.addr);
        HttpReader reader(s.get());
        REQUIRE(send_all(s.get(), "GET / HTTP/1.1\r\nX-Big: " + std::string(9000, 'a')));
        CHECK(reader.read().status == 431);
    }
}

TEST_CASE("idle connections are reset and stop() closes live ones") {
    HttpServerConfig cfg;
    cfg.idle_timeout_ms = 200;
    Fixture f(cfg);
    RawSocket idle = tcp_connect(f.addr);
    HttpReader idle_reader(idle.get());
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(idle_reader.at_eof());
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));

    RawSocket live = tcp_connect(f.addr);
    HttpReader live_reader(live.get());
    REQUIRE(send_all(live.get(), get("/robots.txt", 1)));
    REQUIRE(live_reader.read().ok);
    f.server.stop();
    CHECK(live_reader.at_eof());
    CHECK(f.server.counters().active == 0);
}

TEST_CASE("response delay is applied") {
    Behavior b;
    b.http_delay = Delay{120, 0};
    HttpServer server(b, HttpServerConfig{});
    wc::net::startup();
    REQUIRE(server.start(loopback(0)) == 0);
    RawSocket s = tcp_connect(server.local_address());
    HttpReader reader(s.get());
    const auto t0 = std::chrono::steady_clock::now();
    REQUIRE(send_all(s.get(), get("/robots.txt", 5)));
    REQUIRE(reader.read().ok);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms >= 120 - 16);
    CHECK(ms < 2000);
}
