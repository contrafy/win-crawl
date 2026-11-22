#include "parse/http.h"

#include "doctest/doctest.h"

#include <random>
#include <string>
#include <vector>

using wc::parse::HttpError;
using wc::parse::ParseStatus;
using wc::parse::ResponseParser;

namespace {

struct Outcome {
    ParseStatus status = ParseStatus::NeedMore;
    HttpError error = HttpError::None;
    int code = 0;
    int minor = -1;
    bool keep_alive = false;
    std::string body;
    size_t consumed = 0;
    size_t header_bytes = 0;
    std::string location;
    std::string content_type;

    bool operator==(const Outcome&) const = default;
};

// Feeds `resp` in pieces of the given sizes (the remainder as one final
// piece), appending to a growable buffer like the crawler does, then signals
// EOF if requested and the parser still wants more.
Outcome run(std::string_view resp, const std::vector<size_t>& pieces, bool head = false, size_t max = 1 << 20,
            bool eof = true) {
    ResponseParser p;
    p.reset(head, max);
    std::string buf;
    ParseStatus st = ParseStatus::NeedMore;
    size_t off = 0;
    auto feed = [&](size_t n) {
        buf.append(resp.substr(off, n));
        off += n;
        st = p.parse(buf.data(), buf.size());
    };
    for (const size_t n : pieces) {
        if (off >= resp.size() || st != ParseStatus::NeedMore) {
            break;
        }
        feed(std::min(n, resp.size() - off));
    }
    if (st == ParseStatus::NeedMore && off < resp.size()) {
        feed(resp.size() - off);
    }
    if (st == ParseStatus::NeedMore && eof) {
        st = p.finish(buf.data(), buf.size());
    }
    Outcome o;
    o.status = st;
    o.error = p.error();
    if (st == ParseStatus::Done) {
        o.code = p.status();
        o.minor = p.http_minor();
        o.keep_alive = p.keep_alive();
        o.body = std::string(p.body());
        o.consumed = p.consumed();
        o.header_bytes = p.header_bytes();
        o.location = std::string(p.header("location"));
        o.content_type = std::string(p.header("CONTENT-TYPE"));
    }
    return o;
}

Outcome run_whole(std::string_view resp, bool head = false, size_t max = 1 << 20, bool eof = true) {
    return run(resp, {resp.size()}, head, max, eof);
}

// The outcome must not depend on how the bytes were split across recvs.
Outcome run_all_splits(std::string_view resp, bool head = false, size_t max = 1 << 20, bool eof = true) {
    const Outcome whole = run_whole(resp, head, max, eof);
    const Outcome bytewise = run(resp, std::vector<size_t>(resp.size(), 1), head, max, eof);
    CHECK(bytewise == whole);
    for (size_t cut = 1; cut < resp.size(); ++cut) {
        const Outcome two = run(resp, {cut}, head, max, eof);
        CHECK(two == whole);
    }
    std::mt19937 rng(12345);
    for (int trial = 0; trial < 50; ++trial) {
        std::vector<size_t> pieces;
        size_t total = 0;
        while (total < resp.size()) {
            const size_t n = std::uniform_int_distribution<size_t>(1, 7)(rng);
            pieces.push_back(n);
            total += n;
        }
        const Outcome r = run(resp, pieces, head, max, eof);
        CHECK(r == whole);
    }
    return whole;
}

}  // namespace

TEST_CASE("append_request writes an HTTP/1.1 request") {
    wc::parse::Url u;
    REQUIRE(wc::parse::parse_url("http://Example.com:8080/a/b?c=d#f", u));
    std::string req = "junk:";
    wc::parse::append_request(req, "GET", u, "wincrawl/2.0", true);
    CHECK(req ==
          "junk:GET /a/b?c=d HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: wincrawl/2.0\r\n"
          "Accept: */*\r\nConnection: keep-alive\r\n\r\n");
    REQUIRE(wc::parse::parse_url("http://x.org", u));
    req.clear();
    wc::parse::append_request(req, "HEAD", u, "", false);
    CHECK(req == "HEAD / HTTP/1.1\r\nHost: x.org\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    req.clear();
    wc::parse::append_request(req, "GET", u, "ua", true, "Signature-Input: sig1=()\r\nSignature: sig1=:AA==:\r\n");
    CHECK(req ==
          "GET / HTTP/1.1\r\nHost: x.org\r\nUser-Agent: ua\r\nAccept: */*\r\nConnection: keep-alive\r\n"
          "Signature-Input: sig1=()\r\nSignature: sig1=:AA==:\r\n\r\n");
}

TEST_CASE("Content-Length body") {
    const std::string head = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n";
    const Outcome o = run_all_splits(head + "hello");
    CHECK(o.status == ParseStatus::Done);
    CHECK(o.code == 200);
    CHECK(o.minor == 1);
    CHECK(o.body == "hello");
    CHECK(o.keep_alive);
    CHECK(o.content_type == "text/html");
    CHECK(o.header_bytes == head.size());
    CHECK(o.consumed == head.size() + 5);
}

TEST_CASE("Content-Length: 0 and header accessors") {
    const std::string resp =
        "HTTP/1.1 301 Moved Permanently\r\nLocation:   http://x.com/new  \r\nContent-Length: 0\r\nX-Empty:\r\n\r\n";
    const Outcome o = run_all_splits(resp);
    CHECK(o.status == ParseStatus::Done);
    CHECK(o.code == 301);
    CHECK(o.location == "http://x.com/new");
    CHECK(o.body.empty());

    ResponseParser p;
    p.reset(false, 1000);
    std::string buf = resp;
    REQUIRE(p.parse(buf.data(), buf.size()) == ParseStatus::Done);
    CHECK(p.header_count() == 3);
    CHECK(p.header_at(0).name == "Location");
    CHECK(p.has_header("x-empty"));
    CHECK(p.header("x-empty").empty());
    CHECK_FALSE(p.has_header("x-missing"));
    CHECK(p.header("Content-Length") == "0");
}

TEST_CASE("pipelined response starts at consumed()") {
    const std::string first = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    const std::string second = "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";
    std::string buf = first + second;
    ResponseParser p;
    p.reset(false, 1000);
    REQUIRE(p.parse(buf.data(), buf.size()) == ParseStatus::Done);
    CHECK(p.body() == "abc");
    REQUIRE(p.consumed() == first.size());
    const size_t off = p.consumed();
    p.reset(false, 1000);
    REQUIRE(p.parse(buf.data() + off, buf.size() - off) == ParseStatus::Done);
    CHECK(p.status() == 404);
    CHECK(p.body() == "no");
}

TEST_CASE("responses without a body") {
    SUBCASE("HEAD ignores Content-Length") {
        const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
        const Outcome o = run_all_splits(resp, true, 100, false);
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.body.empty());
        CHECK(o.consumed == resp.size());
        CHECK(o.keep_alive);
    }
    SUBCASE("HEAD ignores chunked") {
        const Outcome o = run_whole("HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n", true, 1000, false);
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.code == 404);
        CHECK(o.keep_alive);
    }
    SUBCASE("204 and 304") {
        for (const char* code : {"204 No Content", "304 Not Modified"}) {
            const std::string resp = std::string("HTTP/1.1 ") + code + "\r\nContent-Length: 10\r\n\r\n";
            const Outcome o = run_all_splits(resp, false, 1000, false);
            CHECK(o.status == ParseStatus::Done);
            CHECK(o.consumed == resp.size());
            CHECK(o.keep_alive);
        }
    }
    SUBCASE("101 is final, bodyless, and not reusable") {
        const Outcome o = run_whole("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\nraw", false, 1000, false);
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.code == 101);
        CHECK_FALSE(o.keep_alive);
    }
}

TEST_CASE("interim 1xx responses are skipped") {
    const std::string interim = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n";
    const std::string final_head = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";
    const Outcome o = run_all_splits(interim + final_head + "ok");
    CHECK(o.status == ParseStatus::Done);
    CHECK(o.code == 200);
    CHECK(o.body == "ok");
    CHECK(o.header_bytes == final_head.size());
    CHECK(o.consumed == interim.size() + final_head.size() + 2);

    ResponseParser p;
    p.reset(false, 1000);
    std::string buf = interim + final_head + "ok";
    REQUIRE(p.parse(buf.data(), buf.size()) == ParseStatus::Done);
    CHECK_FALSE(p.has_header("Link"));
}

TEST_CASE("chunked transfer coding") {
    SUBCASE("extensions, trailers, embedded CRLF in data") {
        const std::string resp =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"
            "4\r\nWiki\r\n"
            "5;name=value;x=\"q\"\r\npedia\r\n"
            "E\r\n in\r\n\r\nchunks.\r\n"
            "0;last\r\nExpires: never\r\nX-Trailer: 1\r\n\r\n";
        const Outcome o = run_all_splits(resp);
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.body == "Wikipedia in\r\n\r\nchunks.");
        CHECK(o.consumed == resp.size());
        CHECK(o.keep_alive);
    }
    SUBCASE("uppercase hex, padding, LF-only framing, whitespace before extension") {
        const std::string resp =
            "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n"
            "00A  ;ext\n0123456789\n"
            "1f\nABCDEFGHIJKLMNOPQRSTUVWXYZabcde\n"
            "0000\n\n";
        const Outcome o = run_all_splits(resp);
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.body == "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde");
        CHECK(o.consumed == resp.size());
    }
    SUBCASE("bytes after the terminating chunk are not consumed") {
        const std::string msg = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        const std::string next = "HTTP/1.1 200 OK\r\n";
        const Outcome o = run_whole(msg + next);
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.body == "abc");
        CHECK(o.consumed == msg.size());
    }
    SUBCASE("transfer-coding list ending in chunked") {
        const Outcome o = run_whole(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n");
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.body == "hi");
    }
    SUBCASE("Transfer-Encoding overrides Content-Length and forbids reuse") {
        const Outcome o = run_all_splits(
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n");
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.body == "hi");
        CHECK_FALSE(o.keep_alive);
    }
    SUBCASE("non-chunked final coding is close-delimited") {
        const Outcome o = run_whole("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nrawbytes");
        CHECK(o.status == ParseStatus::Done);
        CHECK(o.body == "rawbytes");
        CHECK_FALSE(o.keep_alive);
    }
    SUBCASE("malformed framing") {
        const char* bad[] = {
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3x\r\nabc\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcd\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\rX0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFF\r\n",
        };
        for (const char* r : bad) {
            CAPTURE(r);
            const Outcome o = run_all_splits(r);
            CHECK(o.status == ParseStatus::Error);
            CHECK(o.error == HttpError::BadChunk);
        }
    }
    SUBCASE("EOF inside chunked body is truncation") {
        const Outcome o = run_all_splits("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab");
        CHECK(o.status == ParseStatus::Error);
        CHECK(o.error == HttpError::Truncated);
    }
}

TEST_CASE("close-delimited body") {
    const Outcome o = run_all_splits("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>");
    CHECK(o.status == ParseStatus::Done);
    CHECK(o.body == "<html>body</html>");
    CHECK_FALSE(o.keep_alive);

    const Outcome none = run_whole("HTTP/1.0 200 OK\r\n\r\nabc", false, 1000, false);
    CHECK(none.status == ParseStatus::NeedMore);

    const Outcome empty = run_whole("HTTP/1.0 200 OK\r\n\r\n");
    CHECK(empty.status == ParseStatus::Done);
    CHECK(empty.body.empty());
}

TEST_CASE("keep-alive matrix") {
    struct Case {
        const char* version;
        const char* connection;  // nullptr = no header
        bool expect;
    };
    const Case cases[] = {
        {"1.1", nullptr, true},
        {"1.1", "keep-alive", true},
        {"1.1", "close", false},
        {"1.1", "Close", false},
        {"1.1", "Keep-Alive, Upgrade", true},
        {"1.1", "foo, close", false},
        {"1.1", "keep-alive, close", false},
        {"1.0", nullptr, false},
        {"1.0", "keep-alive", true},
        {"1.0", "Keep-Alive", true},
        {"1.0", "close", false},
        {"1.0", "te, KEEP-ALIVE", true},
    };
    for (const Case& c : cases) {
        CAPTURE(c.version);
        CAPTURE(c.connection ? c.connection : "(none)");
        std::string resp = std::string("HTTP/") + c.version + " 200 OK\r\nContent-Length: 1\r\n";
        if (c.connection != nullptr) {
            resp += std::string("Connection: ") + c.connection + "\r\n";
        }
        resp += "\r\nx";
        const Outcome o = run_whole(resp, false, 1000, false);
        REQUIRE(o.status == ParseStatus::Done);
        CHECK(o.minor == c.version[2] - '0');
        CHECK(o.keep_alive == c.expect);
    }
    // Two Connection fields combine.
    const Outcome two =
        run_whole("HTTP/1.1 200 OK\r\nConnection: upgrade\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    CHECK_FALSE(two.keep_alive);
}

TEST_CASE("size limit") {
    SUBCASE("Content-Length beyond the cap fails before the body arrives") {
        ResponseParser p;
        p.reset(false, 100);
        std::string buf = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
        CHECK(p.parse(buf.data(), buf.size()) == ParseStatus::Error);
        CHECK(p.error() == HttpError::TooLarge);
        CHECK_FALSE(p.keep_alive());
    }
    SUBCASE("exactly at the cap succeeds") {
        const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
        CHECK(run_all_splits(resp, false, resp.size()).status == ParseStatus::Done);
        const Outcome over = run_all_splits(resp, false, resp.size() - 1);
        CHECK(over.status == ParseStatus::Error);
        CHECK(over.error == HttpError::TooLarge);
    }
    SUBCASE("oversized headers") {
        const std::string resp = "HTTP/1.1 200 OK\r\nX-Big: " + std::string(200, 'x') + "\r\n\r\n";
        const Outcome o = run_all_splits(resp, true, 100);
        CHECK(o.status == ParseStatus::Error);
        CHECK(o.error == HttpError::TooLarge);
    }
    SUBCASE("chunked and close-delimited bodies") {
        std::string chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        for (int i = 0; i < 20; ++i) {
            chunked += "5\r\nabcde\r\n";
        }
        chunked += "0\r\n\r\n";
        CHECK(run_whole(chunked, false, chunked.size()).status == ParseStatus::Done);
        const Outcome c = run_all_splits(chunked, false, 120);
        CHECK(c.error == HttpError::TooLarge);
        const Outcome big = run_whole("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000\r\nab", false, 1000);
        CHECK(big.error == HttpError::TooLarge);

        const std::string close = "HTTP/1.1 200 OK\r\n\r\n" + std::string(200, 'b');
        CHECK(run_whole(close, false, close.size()).status == ParseStatus::Done);
        const Outcome d = run_all_splits(close, false, 100);
        CHECK(d.error == HttpError::TooLarge);
    }
    SUBCASE("trailing bytes beyond a complete message do not count") {
        const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" + std::string(500, 'z');
        CHECK(run_whole(resp, false, 100).status == ParseStatus::Done);
    }
}

TEST_CASE("garbage and malformed replies") {
    SUBCASE("non-HTTP data fails on the first wrong byte") {
        for (const char* g : {"<html><body>hi</body></html>", "SSH-2.0-OpenSSH\r\n", "\x16\x03\x01\x02\x00", "http/1.1 200 OK\r\n",
                              "HTTP/x.1 200 OK\r\n", "HTTP 200 OK\r\n", "ICY 200 OK\r\n"}) {
            CAPTURE(g);
            ResponseParser p;
            p.reset(false, 1000);
            std::string buf = g;
            CHECK(p.parse(buf.data(), buf.size()) == ParseStatus::Error);
            CHECK(p.error() == HttpError::BadStatusLine);
            p.reset(false, 1000);
            std::string one(1, g[0]);
            const ParseStatus st = p.parse(one.data(), 1);
            CHECK((g[0] == 'H' ? st == ParseStatus::NeedMore : st == ParseStatus::Error));
        }
    }
    SUBCASE("bad status lines") {
        for (const char* g : {"HTTP/2 200 OK\r\n\r\n", "HTTP/1.1 2OO OK\r\n\r\n", "HTTP/1.1 200OK\r\n\r\n", "HTTP/1.1 20\r\n\r\n",
                              "HTTP/1.1\r\n\r\n", "HTTP/1.1 099 Low\r\n\r\n", "HTTP/1.1  \r\n\r\n", "HTTP/1.x 200 OK\r\n\r\n"}) {
            CAPTURE(g);
            const Outcome o = run_all_splits(g);
            CHECK(o.status == ParseStatus::Error);
            CHECK(o.error == HttpError::BadStatusLine);
        }
    }
    SUBCASE("lenient status lines and headers") {
        const Outcome a = run_all_splits("HTTP/1.1 200\r\nContent-Length: 1\r\n\r\nx");
        CHECK(a.status == ParseStatus::Done);
        CHECK(a.code == 200);
        const Outcome b = run_all_splits("\r\nHTTP/1.0 999 Weird\nContent-Length: 1\nno colon line\n folded: x\n\nx");
        CHECK(b.status == ParseStatus::Done);
        CHECK(b.code == 999);
        CHECK(b.minor == 0);
        CHECK(b.body == "x");
    }
    SUBCASE("empty header name") {
        const Outcome o = run_all_splits("HTTP/1.1 200 OK\r\n: v\r\n\r\n");
        CHECK(o.error == HttpError::BadHeader);
    }
    SUBCASE("bad Content-Length") {
        for (const char* cl : {"abc", "-1", "1 2", "5, 6", "", "99999999999999999999999"}) {
            CAPTURE(cl);
            const Outcome o = run_whole(std::string("HTTP/1.1 200 OK\r\nContent-Length: ") + cl + "\r\n\r\nhello");
            CHECK(o.status == ParseStatus::Error);
            CHECK(o.error == HttpError::BadContentLength);
        }
        const Outcome dup =
            run_whole("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!");
        CHECK(dup.error == HttpError::BadContentLength);
        const Outcome same = run_whole("HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\nContent-Length: 5\r\n\r\nhello");
        CHECK(same.status == ParseStatus::Done);
        CHECK(same.body == "hello");
    }
    SUBCASE("truncation") {
        CHECK(run_whole("").error == HttpError::Truncated);
        CHECK(run_all_splits("HTTP/1.1 200 OK\r\nContent-Le").error == HttpError::Truncated);
        CHECK(run_all_splits("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello").error == HttpError::Truncated);
    }
}

TEST_CASE("parser state is sticky and resettable") {
    ResponseParser p;
    p.reset(false, 1000);
    std::string buf = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
    REQUIRE(p.parse(buf.data(), buf.size()) == ParseStatus::Done);
    CHECK(p.parse(buf.data(), buf.size()) == ParseStatus::Done);
    CHECK(p.finish(buf.data(), buf.size()) == ParseStatus::Done);
    CHECK(p.state() == ParseStatus::Done);
    p.reset(false, 1000);
    CHECK(p.state() == ParseStatus::NeedMore);
    CHECK(p.body().empty());
    std::string bad = "nope";
    CHECK(p.parse(bad.data(), bad.size()) == ParseStatus::Error);
    CHECK(wc::parse::to_string(p.error()) == std::string("bad status line"));
}
