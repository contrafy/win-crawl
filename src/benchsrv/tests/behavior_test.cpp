#include "benchsrv/behavior.h"
#include "benchsrv/http_server.h"
#include "benchsrv/urlgen.h"

#include "doctest/doctest.h"

#include <winsock2.h>

#include <set>
#include <string>
#include <unordered_set>

using namespace wc::benchsrv;

namespace {

size_t count_ci(const std::string& text, std::string_view needle) {
    size_t count = 0;
    for (size_t i = 0; i + needle.size() <= text.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size() && match; ++j) {
            char c = text[i + j];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            match = c == needle[j];
        }
        count += match ? 1 : 0;
    }
    return count;
}

// Decodes a chunked payload; fails the test on malformed framing.
std::string dechunk(std::string_view wire) {
    std::string body;
    for (;;) {
        const size_t eol = wire.find("\r\n");
        REQUIRE(eol != std::string_view::npos);
        const size_t n = std::stoul(std::string(wire.substr(0, eol)), nullptr, 16);
        wire.remove_prefix(eol + 2);
        if (n == 0) {
            REQUIRE(wire == "\r\n");
            return body;
        }
        REQUIRE(wire.size() >= n + 2);
        body.append(wire.substr(0, n));
        REQUIRE(wire.substr(n, 2) == "\r\n");
        wire.remove_prefix(n + 2);
    }
}

}  // namespace

TEST_CASE("host names and addresses round-trip") {
    CHECK(parse_host_name("h0.bench.test", "bench.test") == 0u);
    CHECK(parse_host_name("H123.Bench.TEST.", "bench.test") == 123u);
    CHECK_FALSE(parse_host_name("h.bench.test", "bench.test"));
    CHECK_FALSE(parse_host_name("x1.bench.test", "bench.test"));
    CHECK_FALSE(parse_host_name("h1x.bench.test", "bench.test"));
    CHECK_FALSE(parse_host_name("h1.bench.testx", "bench.test"));
    CHECK_FALSE(parse_host_name("h1.a.bench.test", "bench.test"));
    CHECK_FALSE(parse_host_name("bench.test", "bench.test"));

    CHECK(host_unique_ip(0) == htonl(0x7F000001u));
    CHECK(host_unique_ip(255) == htonl(0x7F000100u));
    for (uint64_t n : {0ull, 1ull, 77ull, 65535ull, 16777213ull}) {
        CHECK(ip_host_number(host_unique_ip(n)) == n);
    }
    CHECK_FALSE(ip_host_number(htonl(0x7F000000u)));
    CHECK_FALSE(ip_host_number(htonl(0x0A000001u)));

    CHECK(host_header_number("h7.bench.test:8080", "bench.test") == 7u);
    CHECK(host_header_number("h7.bench.test", "bench.test") == 7u);
    CHECK(host_header_number("127.0.0.8:8080", "bench.test") == 7u);
    CHECK(host_header_number("127.0.0.8", "bench.test") == 7u);
    CHECK(host_header_number("Example.COM", "bench.test") == host_header_number("example.com:80", "bench.test"));
    CHECK_FALSE(host_header_number("", "bench.test"));
}

TEST_CASE("delays parse and stay in range") {
    Delay d;
    CHECK(parse_delay("30", d));
    CHECK(d.mean_ms == 30);
    CHECK(d.jitter_ms == 0);
    CHECK(parse_delay("80,40", d));
    CHECK(d.mean_ms == 80);
    CHECK(d.jitter_ms == 40);
    CHECK_FALSE(parse_delay("80,", d));
    CHECK_FALSE(parse_delay("x", d));
    std::set<uint32_t> seen;
    for (uint64_t h = 0; h < 1000; ++h) {
        const uint32_t v = d.pick(mix64(h));
        CHECK(v >= 40);
        CHECK(v <= 120);
        seen.insert(v);
    }
    CHECK(seen.size() > 40);
    Delay clamp{5, 20};
    for (uint64_t h = 0; h < 100; ++h) CHECK(clamp.pick(mix64(h)) <= 25);
}

TEST_CASE("decision fractions match the configuration and are deterministic") {
    Behavior b;
    constexpr uint64_t kHosts = 100000;
    size_t nx = 0, robots = 0, shared = 0, answered = 0;
    std::unordered_set<uint32_t> ips;
    for (uint64_t n = 0; n < kHosts; ++n) {
        if (host_nxdomain(b, n)) {
            ++nx;
        } else {
            ++answered;
            if (!ips.insert(host_ip(b, n)).second) ++shared;
        }
        robots += robots_missing(b, n) ? 1 : 0;
    }
    CHECK(static_cast<double>(nx) / kHosts == doctest::Approx(b.nxdomain).epsilon(0.1));
    CHECK(static_cast<double>(robots) / kHosts == doctest::Approx(b.robots_404).epsilon(0.05));
    CHECK(static_cast<double>(shared) / answered == doctest::Approx(b.ip_share).epsilon(0.1));

    Behavior other = b;
    other.seed = 1;
    size_t differ = 0;
    for (uint64_t n = 0; n < 1000; ++n) {
        CHECK(host_nxdomain(b, n) == host_nxdomain(b, n));
        differ += host_nxdomain(b, n) != host_nxdomain(other, n) ? 1 : 0;
    }
    CHECK(differ > 50);
}

TEST_CASE("politeness knobs: IP pool, Crawl-delay and throttle fractions") {
    Behavior b;
    b.ip_pool = 5;
    for (uint64_t n = 0; n < 100; ++n) {
        CHECK(host_ip(b, n) == host_unique_ip(n % 5));
    }
    b.crawl_delay = 0.3;
    b.throttle = 0.2;
    constexpr uint64_t kHosts = 100000;
    size_t delayed = 0, throttled = 0;
    for (uint64_t n = 0; n < kHosts; ++n) {
        delayed += host_crawl_delay(b, n) ? 1 : 0;
        throttled += host_throttled(b, n) ? 1 : 0;
    }
    CHECK(static_cast<double>(delayed) / kHosts == doctest::Approx(0.3).epsilon(0.05));
    CHECK(static_cast<double>(throttled) / kHosts == doctest::Approx(0.2).epsilon(0.05));
    Behavior off;  // defaults: neither
    CHECK_FALSE(host_crawl_delay(off, 1));
    CHECK_FALSE(host_throttled(off, 1));
}

TEST_CASE("page plans: status mix and redirect targets") {
    Behavior b;
    size_t counts[4] = {};
    size_t chunked = 0;
    for (uint64_t n = 0; n < 20000; ++n) {
        const PagePlan p = page_plan(b, n, "/p/" + std::to_string(n % 97));
        ++counts[static_cast<int>(p.kind)];
        chunked += (p.kind == PageKind::Ok && p.chunked) ? 1 : 0;
        CHECK(p.template_index < kPageTemplates);
        CHECK(page_plan(b, n, "/r/1").kind == PageKind::Ok);
    }
    CHECK(counts[1] / 20000.0 == doctest::Approx(b.redirect).epsilon(0.2));
    CHECK(counts[2] / 20000.0 == doctest::Approx(b.not_found).epsilon(0.2));
    CHECK(counts[3] / 20000.0 == doctest::Approx(b.server_error).epsilon(0.25));
    CHECK(chunked / static_cast<double>(counts[0]) == doctest::Approx(b.chunked).epsilon(0.15));
}

TEST_CASE("pre-generated pages have the configured links and sizes") {
    Behavior b;
    b.page_kb = 16;
    b.links = 25;
    ResponseSet rs(b, 8080);
    size_t total = 0;
    for (uint32_t t = 0; t < kPageTemplates; ++t) {
        const std::string& body = rs.page_body(t);
        total += body.size();
        CHECK(count_ci(body, "href=") == b.links);
        const Response& plain = rs.page(t, false, 0);
        CHECK(plain.status == 200);
        CHECK(plain.data.substr(plain.head_len) == body);
        CHECK(plain.data.find("Content-Length: " + std::to_string(body.size()) + "\r\n") < plain.head_len);
        const Response& chunked = rs.page(t, true, 1);
        CHECK(chunked.data.find("Transfer-Encoding: chunked\r\n") < chunked.head_len);
        CHECK(chunked.data.find("Connection: close\r\n") < chunked.head_len);
        CHECK(dechunk(std::string_view(chunked.data).substr(chunked.head_len)) == body);
    }
    const double mean_kb = static_cast<double>(total) / kPageTemplates / 1024.0;
    CHECK(mean_kb == doctest::Approx(16.0).epsilon(0.1));
    CHECK(rs.robots(true, 0).status == 404);
    CHECK(rs.robots(false, 0).status == 200);
    CHECK(rs.redirect(0).data.find("Location: /r/1\r\n") != std::string::npos);
}

TEST_CASE("request parser") {
    HttpRequest r;
    std::string req = "GET /p/1 HTTP/1.1\r\nHost: h1.bench.test:8080\r\nUser-Agent: x\r\n\r\nGET";
    REQUIRE(parse_request(req.data(), req.size(), r) == RequestParse::Ok);
    CHECK_FALSE(r.head);
    CHECK_FALSE(r.close);
    CHECK(r.target == "/p/1");
    CHECK(r.host == "h1.bench.test:8080");
    CHECK(r.length == req.size() - 3);
    CHECK(parse_request(req.data(), r.length - 1, r) == RequestParse::NeedMore);

    req = "HEAD /robots.txt HTTP/1.0\r\nhost:h2.bench.test\r\n\r\n";
    REQUIRE(parse_request(req.data(), req.size(), r) == RequestParse::Ok);
    CHECK(r.head);
    CHECK(r.close);
    CHECK(r.host == "h2.bench.test");

    req = "GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n";
    REQUIRE(parse_request(req.data(), req.size(), r) == RequestParse::Ok);
    CHECK_FALSE(r.close);

    req = "GET / HTTP/1.1\r\nConnection: TE, close\r\n\r\n";
    REQUIRE(parse_request(req.data(), req.size(), r) == RequestParse::Ok);
    CHECK(r.close);

    req = "GET http://h9.bench.test:8080/x?y HTTP/1.1\r\n\r\n";
    REQUIRE(parse_request(req.data(), req.size(), r) == RequestParse::Ok);
    CHECK(r.host == "h9.bench.test:8080");
    CHECK(r.target == "/x?y");

    req = "POST / HTTP/1.1\r\nHost: a\r\n\r\n";
    CHECK(parse_request(req.data(), req.size(), r) == RequestParse::NotImplemented);
    req = "GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
    CHECK(parse_request(req.data(), req.size(), r) == RequestParse::Bad);
    req = "GARBAGE\r\n\r\n";
    CHECK(parse_request(req.data(), req.size(), r) == RequestParse::Bad);
    req = "GET / SPDY/3\r\n\r\n";
    CHECK(parse_request(req.data(), req.size(), r) == RequestParse::Bad);
}

TEST_CASE("url generator") {
    UrlGenOptions o;
    o.count = 20000;
    o.dup_hosts = 0.25;
    std::string out;
    uint64_t next_host = 0;
    for (uint64_t i = 0; i < o.count; ++i) append_url(o, i, next_host, out);
    CHECK(static_cast<double>(next_host) / o.count == doctest::Approx(0.75).epsilon(0.05));
    CHECK(out.substr(0, 25) == "http://h0.bench.test:8080");
    size_t lines = 0;
    for (char c : out) lines += c == '\n' ? 1 : 0;
    CHECK(lines == o.count);

    std::string again;
    uint64_t next_again = 0;
    for (uint64_t i = 0; i < o.count; ++i) append_url(o, i, next_again, again);
    CHECK(again == out);

    o.ip_literal = true;
    o.port = 9000;
    out.clear();
    next_host = 0;
    append_url(o, 0, next_host, out);
    CHECK(out.substr(0, 24) == "http://127.0.0.1:9000/p/");
}
