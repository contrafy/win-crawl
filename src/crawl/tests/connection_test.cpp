#include "crawl/connection.h"

#include "crawl/tests/fake_servers.h"
#include "doctest/doctest.h"
#include "parse/url.h"

#include <functional>
#include <string>
#include <vector>

using namespace wc;
using namespace wc::crawl;
using namespace wc::crawl::test;

namespace {

struct Outcome {
    FetchError error = FetchError::None;
    int status = 0;
    std::string body;
    bool reused = false;
    bool keep_alive = false;
};

// Records every completion; `then` may start the next fetch from inside it.
struct Recorder : FetchHandler {
    std::vector<Outcome> got;
    std::function<void(Connection&)> then;

    void on_fetch(Connection& c, const FetchResult& r) override {
        Outcome o;
        o.error = r.error;
        o.status = r.status;
        o.body = std::string(r.body);
        o.reused = r.reused;
        o.keep_alive = r.reply != nullptr && r.reply->keep_alive();
        got.push_back(o);
        if (then) {
            auto next = std::move(then);
            then = nullptr;
            next(c);
        }
    }
};

std::string request(const char* method, const std::string& url, bool keep_alive = true) {
    parse::Url u;
    REQUIRE(parse::parse_url(url, u));
    std::string out;
    parse::append_request(out, method, u, "wincrawl-test", keep_alive);
    return out;
}

FetchOptions options(bool head = false, size_t limit = 1 << 20, uint32_t timeout_ms = 3000) {
    FetchOptions o;
    o.head = head;
    o.limit = limit;
    o.timeout_ms = timeout_ms;
    o.connect_timeout_ms = 1500;
    return o;
}

Endpoint endpoint(uint32_t ip, uint16_t port) {
    Endpoint ep;
    ep.ipv4_be = ip;
    ep.port = port;
    ep.server_name = "k.test";
    return ep;
}

struct Fixture {
    ServerThread srv;
    FakeHttp http{srv};
    net::Loop loop;
    Recorder rec;
    Connection conn{loop, rec, nullptr, tls::Verify::None};

    ~Fixture() {
        conn.abort();
        run_until(loop, [&] { return !conn.busy(); }, 3000);
    }

    bool wait_for(size_t n, uint32_t timeout_ms = 4000) {
        return run_until(loop, [&] { return rec.got.size() >= n; }, timeout_ms);
    }
};

}  // namespace

TEST_CASE("connection: HEAD then GET reuse one keep-alive connection") {
    Fixture f;
    const uint32_t ip = loopback_ip(31);
    const uint16_t port = f.http.listen(ip);
    REQUIRE(port != 0);
    f.http.route("k.test", "/robots.txt", Route{reply(404, "no robots here")});
    f.http.route("k.test", "/page", Route{reply(200, "<a href=/x>x</a>")});
    const std::string base = "http://k.test:" + std::to_string(port);

    f.rec.then = [&](Connection& c) { c.fetch(endpoint(ip, port), request("GET", base + "/page"), options()); };
    f.conn.fetch(endpoint(ip, port), request("HEAD", base + "/robots.txt"), options(true));
    REQUIRE(f.wait_for(2));
    CHECK(f.rec.got[0].error == FetchError::None);
    CHECK(f.rec.got[0].status == 404);
    CHECK(f.rec.got[0].body.empty());
    CHECK_FALSE(f.rec.got[0].reused);
    CHECK(f.rec.got[1].error == FetchError::None);
    CHECK(f.rec.got[1].status == 200);
    CHECK(f.rec.got[1].body == "<a href=/x>x</a>");
    CHECK(f.rec.got[1].reused);
    CHECK(f.conn.connects() == 1);
    CHECK(f.http.accepts(ip) == 1);
    CHECK(f.conn.reusable());
}

TEST_CASE("connection: a different endpoint or Connection: close forces a new connection") {
    Fixture f;
    const uint32_t ip = loopback_ip(33);
    const uint16_t port = f.http.listen(ip);
    f.http.route("k.test", "/a", Route{reply(200, "a", {}, true)});
    f.http.route("k.test", "/b", Route{reply(200, "b")});
    const std::string base = "http://k.test:" + std::to_string(port);

    f.rec.then = [&](Connection& c) { c.fetch(endpoint(ip, port), request("GET", base + "/b"), options()); };
    f.conn.fetch(endpoint(ip, port), request("GET", base + "/a"), options());
    REQUIRE(f.wait_for(2));
    CHECK(f.rec.got[0].status == 200);
    CHECK_FALSE(f.rec.got[0].keep_alive);
    CHECK(f.rec.got[1].status == 200);
    CHECK(f.rec.got[1].body == "b");
    CHECK_FALSE(f.rec.got[1].reused);
    CHECK(f.conn.connects() == 2);
    CHECK(f.http.accepts(ip) == 2);
}

TEST_CASE("connection: a kept-alive connection closed by the server is retried once") {
    Fixture f;
    const uint32_t ip = loopback_ip(34);
    const uint16_t port = f.http.listen(ip);
    // The reply claims keep-alive but the server closes right after it.
    Route sneaky{reply(200, "first")};
    sneaky.close_after = true;
    f.http.route("k.test", "/first", sneaky);
    f.http.route("k.test", "/second", Route{reply(200, "second")});
    const std::string base = "http://k.test:" + std::to_string(port);

    f.conn.fetch(endpoint(ip, port), request("GET", base + "/first"), options());
    REQUIRE(f.wait_for(1));
    REQUIRE(f.conn.reusable());
    // Let the server's FIN arrive before the reuse attempt.
    run_until(f.loop, [] { return false; }, 100);
    f.conn.fetch(endpoint(ip, port), request("GET", base + "/second"), options());
    REQUIRE(f.wait_for(2));
    CHECK(f.rec.got[1].error == FetchError::None);
    CHECK(f.rec.got[1].body == "second");
    CHECK(f.conn.connects() == 2);
    CHECK(f.http.accepts(ip) == 2);
}

TEST_CASE("connection: chunked and close-delimited bodies") {
    Fixture f;
    const uint32_t ip = loopback_ip(35);
    const uint16_t port = f.http.listen(ip);
    f.http.route("k.test", "/chunked", Route{chunked_reply(200, {"hello ", "chunked ", "world"})});
    Route eof{"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nuntil the end"};
    eof.close_after = true;
    f.http.route("k.test", "/eof", eof);
    const std::string base = "http://k.test:" + std::to_string(port);

    f.rec.then = [&](Connection& c) { c.fetch(endpoint(ip, port), request("GET", base + "/eof"), options()); };
    f.conn.fetch(endpoint(ip, port), request("GET", base + "/chunked"), options());
    REQUIRE(f.wait_for(2));
    CHECK(f.rec.got[0].error == FetchError::None);
    CHECK(f.rec.got[0].body == "hello chunked world");
    CHECK(f.rec.got[1].error == FetchError::None);
    CHECK(f.rec.got[1].body == "until the end");
    CHECK(f.rec.got[1].reused);  // the chunked reply left the connection reusable
    CHECK_FALSE(f.conn.reusable());
}

TEST_CASE("connection: failures are classified") {
    Fixture f;
    const uint32_t ip = loopback_ip(36);
    const uint16_t port = f.http.listen(ip);
    f.http.route("k.test", "/big", Route{reply(200, std::string(100000, 'x'))});
    f.http.route("k.test", "/garbage", Route{"garbage\r\n\r\n"});
    Route hang;
    hang.hang = true;
    f.http.route("k.test", "/hang", hang);
    const std::string base = "http://k.test:" + std::to_string(port);

    f.conn.fetch(endpoint(ip, port), request("GET", base + "/big"), options(false, 16 * 1024));
    REQUIRE(f.wait_for(1));
    CHECK(f.rec.got[0].error == FetchError::TooLarge);

    f.conn.fetch(endpoint(ip, port), request("GET", base + "/garbage"), options());
    REQUIRE(f.wait_for(2));
    CHECK(f.rec.got[1].error == FetchError::BadReply);

    f.conn.fetch(endpoint(ip, port), request("GET", base + "/hang"), options(false, 1 << 20, 300));
    REQUIRE(f.wait_for(3));
    CHECK(f.rec.got[2].error == FetchError::Timeout);

    // Nothing listens on 127.0.0.37. Windows retries refused SYNs for ~2 s, so
    // a short connect timeout keeps the test fast; both outcomes are ConnectFail.
    FetchOptions quick = options();
    quick.connect_timeout_ms = 300;
    f.conn.fetch(endpoint(loopback_ip(37), port), request("GET", base + "/"), quick);
    REQUIRE(f.wait_for(4));
    CHECK(f.rec.got[3].error == FetchError::ConnectFail);
    CHECK_FALSE(f.conn.busy());
}

TEST_CASE("connection: abort fails the fetch in flight") {
    Fixture f;
    const uint32_t ip = loopback_ip(38);
    const uint16_t port = f.http.listen(ip);
    Route hang;
    hang.hang = true;
    f.http.route("k.test", "/hang", hang);
    const std::string base = "http://k.test:" + std::to_string(port);

    f.conn.fetch(endpoint(ip, port), request("GET", base + "/hang"), options());
    run_until(f.loop, [&] { return f.http.total_requests() > 0; }, 2000);
    CHECK(f.rec.got.empty());
    f.conn.abort();
    REQUIRE(f.wait_for(1));
    CHECK(f.rec.got[0].error == FetchError::Aborted);
}
