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

// The server counts a response when its send completes, which can be after the
// client has already read it; poll briefly instead of reading once.
HttpCounters counters_when(const HttpServer& server, uint64_t requests) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    HttpCounters c = server.counters();
    while (c.requests < requests && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        c = server.counters();
    }
    return c;
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

    const HttpCounters c = counters_when(f.server, 4);
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

namespace {

// Waits until the server has seen every connection closed.
void wait_closed(const HttpServer& server) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (server.counters().active != 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

const IpTrack* find_track(const std::vector<IpTrack>& tracks, uint32_t ip_be) {
    for (const IpTrack& t : tracks) {
        if (t.ip == ip_be) return &t;
    }
    return nullptr;
}

}  // namespace

TEST_CASE("tracking: per-IP concurrency, accept gaps and the request log on two addresses") {
    HttpServerConfig cfg;
    cfg.threads = 2;
    cfg.track = true;
    Behavior b = Fixture::make_behavior();
    HttpServer server(b, cfg);
    wc::net::startup();
    sockaddr_in a1 = loopback(0);
    sockaddr_in a2 = a1;
    a2.sin_addr.s_addr = htonl(0x7F000002);
    REQUIRE(server.start(std::vector<sockaddr_in>{a1, a2}) == 0);  // port 0 twice: one shared port
    a1.sin_port = a2.sin_port = server.local_address().sin_port;
    {
        // x answers once, then y opens and answers, then x answers again: by
        // the server's own clock x (accept .. last response) spans y.
        RawSocket x = tcp_connect(a1);
        HttpReader rx(x.get());
        REQUIRE(send_all(x.get(), get("/robots.txt", 7)));
        REQUIRE(rx.read().ok);
        RawSocket y = tcp_connect(a1);
        HttpReader ry(y.get());
        REQUIRE(send_all(y.get(), get("/p/1", 7)));
        REQUIRE(ry.read().ok);
        REQUIRE(send_all(x.get(), get("/p/2", 7)));
        REQUIRE(rx.read().ok);
    }
    {
        RawSocket z = tcp_connect(a2);
        HttpReader rz(z.get());
        REQUIRE(send_all(z.get(), get("/p/1", 8)));
        REQUIRE(rz.read().ok);
    }
    wait_closed(server);
    const std::vector<IpTrack> tracks = server.ip_tracks();
    REQUIRE(tracks.size() == 2);
    const IpTrack* one = find_track(tracks, htonl(0x7F000001));
    const IpTrack* two = find_track(tracks, htonl(0x7F000002));
    REQUIRE(one != nullptr);
    REQUIRE(two != nullptr);
    CHECK(one->accepts == 2);
    CHECK(one->max_open == 2);
    CHECK(one->min_gap_ms >= 0);
    CHECK(two->accepts == 1);
    CHECK(two->max_open == 1);
    CHECK(two->min_gap_ms == -1);
    const std::vector<RequestEvent> log = server.host_requests(7);
    REQUIRE(log.size() == 3);
    CHECK(log[0].robots);
    CHECK_FALSE(log[1].robots);
    CHECK(log[0].t_ms <= log[1].t_ms);
    CHECK(log[1].t_ms <= log[2].t_ms);
    CHECK(server.host_requests(8).size() == 1);
    CHECK(server.host_requests(9).empty());
    CHECK(server.tracked_hosts() == 2);
}

TEST_CASE("tracking is off by default") {
    Fixture f;
    RawSocket s = tcp_connect(f.addr);
    HttpReader reader(s.get());
    REQUIRE(send_all(s.get(), get("/robots.txt", 3)));
    REQUIRE(reader.read().ok);
    CHECK(f.server.ip_tracks().empty());
    CHECK(f.server.tracked_hosts() == 0);
}

TEST_CASE("Crawl-delay robots and throttled first page requests") {
    Behavior b = Fixture::make_behavior();
    b.robots_404 = 0;
    b.crawl_delay = 1;
    b.crawl_delay_s = 3;
    b.throttle = 1;
    b.retry_after_s = 7;
    b.redirect = b.not_found = b.server_error = 0;
    HttpServer server(b, HttpServerConfig{});
    wc::net::startup();
    REQUIRE(server.start(loopback(0)) == 0);
    RawSocket s = tcp_connect(server.local_address());
    HttpReader reader(s.get());
    REQUIRE(send_all(s.get(), get("/robots.txt", 4)));
    HttpReply robots = reader.read();
    REQUIRE(robots.ok);
    CHECK(robots.status == 200);
    CHECK(robots.body.find("Crawl-delay: 3\n") != std::string::npos);
    for (uint64_t host : {4, 5}) {
        REQUIRE(send_all(s.get(), get("/p/1", host)));
        HttpReply first = reader.read();
        REQUIRE(first.ok);
        CHECK(first.status == 429);
        CHECK(first.header("Retry-After") == "7");
        REQUIRE(send_all(s.get(), get("/p/1", host)));
        CHECK(reader.read().status == 200);
    }
}
