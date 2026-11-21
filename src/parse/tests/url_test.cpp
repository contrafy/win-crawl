#include "parse/url.h"

#include "doctest/doctest.h"

#include <cstring>
#include <string>

using wc::parse::parse_ipv4_literal;
using wc::parse::parse_url;
using wc::parse::resolve_url;
using wc::parse::Scheme;
using wc::parse::Url;

namespace {

std::string resolved(std::string_view base, std::string_view ref) {
    Url b;
    REQUIRE(parse_url(base, b));
    Url out;
    if (!resolve_url(b, ref, out)) {
        return "<fail>";
    }
    return wc::parse::to_string(out);
}

}  // namespace

TEST_CASE("parse_url accepts absolute http(s) URLs") {
    struct Case {
        const char* in;
        Scheme scheme;
        const char* host;
        uint16_t port;
        const char* target;
    };
    const Case cases[] = {
        {"http://example.com", Scheme::Http, "example.com", 80, "/"},
        {"http://example.com/", Scheme::Http, "example.com", 80, "/"},
        {"http://Example.COM/A/b?C=D#frag", Scheme::Http, "example.com", 80, "/A/b?C=D"},
        {"HTTPS://x.org", Scheme::Https, "x.org", 443, "/"},
        {"hTtP://x.org:8080/p", Scheme::Http, "x.org", 8080, "/p"},
        {"https://x.org:80/", Scheme::Https, "x.org", 80, "/"},
        {"http://host?q=1", Scheme::Http, "host", 80, "/?q=1"},
        {"http://host#frag", Scheme::Http, "host", 80, "/"},
        {"http://host?", Scheme::Http, "host", 80, "/?"},
        {"http://h:/x", Scheme::Http, "h", 80, "/x"},
        {"http://h:00080/x", Scheme::Http, "h", 80, "/x"},
        {"http://h:65535/", Scheme::Http, "h", 65535, "/"},
        {"  http://h/x \r\n", Scheme::Http, "h", 80, "/x"},
        {"http://h/a\nb\tc", Scheme::Http, "h", 80, "/abc"},
        {"http://h/a/./b/../c", Scheme::Http, "h", 80, "/a/c"},
        {"http://h/a/..", Scheme::Http, "h", 80, "/"},
        {"http://h/../../x", Scheme::Http, "h", 80, "/x"},
        {"http://h/a b", Scheme::Http, "h", 80, "/a%20b"},
        {"http://h/\xC3\xA9?q=\xC3\xA9", Scheme::Http, "h", 80, "/%C3%A9?q=%C3%A9"},
        {"http://h/%7Efoo/%2e%2e", Scheme::Http, "h", 80, "/%7Efoo/%2e%2e"},
        {"http://h/a?b/../c", Scheme::Http, "h", 80, "/a?b/../c"},
        {"http://my_host-1.example/", Scheme::Http, "my_host-1.example", 80, "/"},
        {"http://1.2.3.4:81/", Scheme::Http, "1.2.3.4", 81, "/"},
        {"http://h//double//slash", Scheme::Http, "h", 80, "//double//slash"},
        {"http://h/{x}|^`", Scheme::Http, "h", 80, "/{x}|^`"},
    };
    for (const Case& c : cases) {
        CAPTURE(c.in);
        Url u;
        REQUIRE(parse_url(c.in, u));
        CHECK(u.scheme == c.scheme);
        CHECK(u.host == c.host);
        CHECK(u.port == c.port);
        CHECK(u.target == c.target);
    }
}

TEST_CASE("parse_url rejects invalid input") {
    const std::string long_host(254, 'a');
    const std::string ok_host(253, 'a');
    Url u;
    CHECK(parse_url("http://" + ok_host + "/", u));
    const std::string bad[] = {
        "",
        "   ",
        "ftp://h/",
        "mailto:a@b.c",
        "javascript:alert(1)",
        "http://",
        "http:///x",
        "http:/h/x",
        "http:h",
        "http:\\\\h\\x",
        "//h/x",
        "/relative",
        "relative",
        "http://user@h/",
        "http://user:pw@h/",
        "http://[::1]/",
        "http://[::1]:80/",
        "http://h:0/",
        "http://h:65536/",
        "http://h:99999999999/",
        "http://h:12a/",
        "http://h:-1/",
        "http://h%41/",
        "http://ho st/",
        "http://h!/",
        "http://h\xC3\xA9/",
        "http://" + long_host + "/",
        "http://:80/",
        "http://?q",
        "http://#f",
    };
    for (const std::string& s : bad) {
        CAPTURE(s);
        CHECK_FALSE(parse_url(s, u));
    }
}

TEST_CASE("to_string and host_header omit the default port") {
    Url u;
    REQUIRE(parse_url("http://a.com/x?y", u));
    CHECK(wc::parse::to_string(u) == "http://a.com/x?y");
    CHECK(wc::parse::host_header(u) == "a.com");
    REQUIRE(parse_url("http://a.com:8080", u));
    CHECK(wc::parse::to_string(u) == "http://a.com:8080/");
    CHECK(wc::parse::host_header(u) == "a.com:8080");
    REQUIRE(parse_url("https://a.com:443/", u));
    CHECK(wc::parse::to_string(u) == "https://a.com/");
    CHECK(wc::parse::host_header(u) == "a.com");
    REQUIRE(parse_url("https://a.com:80/", u));
    CHECK(wc::parse::to_string(u) == "https://a.com:80/");
    std::string s = "x=";
    wc::parse::append_to_string(s, u);
    CHECK(s == "x=https://a.com:80/");
}

TEST_CASE("resolve_url: RFC 3986 5.4.1 normal examples") {
    const char* base = "http://a/b/c/d;p?q";
    const char* cases[][2] = {
        {"g", "http://a/b/c/g"},
        {"./g", "http://a/b/c/g"},
        {"g/", "http://a/b/c/g/"},
        {"/g", "http://a/g"},
        {"//g", "http://g/"},
        {"?y", "http://a/b/c/d;p?y"},
        {"g?y", "http://a/b/c/g?y"},
        {"#s", "http://a/b/c/d;p?q"},
        {"g#s", "http://a/b/c/g"},
        {"g?y#s", "http://a/b/c/g?y"},
        {";x", "http://a/b/c/;x"},
        {"g;x", "http://a/b/c/g;x"},
        {"g;x?y#s", "http://a/b/c/g;x?y"},
        {"", "http://a/b/c/d;p?q"},
        {".", "http://a/b/c/"},
        {"./", "http://a/b/c/"},
        {"..", "http://a/b/"},
        {"../", "http://a/b/"},
        {"../g", "http://a/b/g"},
        {"../..", "http://a/"},
        {"../../", "http://a/"},
        {"../../g", "http://a/g"},
        // "g:h" -> "g:h" is not an http(s) URL.
        {"g:h", "<fail>"},
    };
    for (const auto& c : cases) {
        CAPTURE(c[0]);
        CHECK(resolved(base, c[0]) == c[1]);
    }
}

TEST_CASE("resolve_url: RFC 3986 5.4.2 abnormal examples") {
    const char* base = "http://a/b/c/d;p?q";
    const char* cases[][2] = {
        {"../../../g", "http://a/g"},
        {"../../../../g", "http://a/g"},
        {"/./g", "http://a/g"},
        {"/../g", "http://a/g"},
        {"g.", "http://a/b/c/g."},
        {".g", "http://a/b/c/.g"},
        {"g..", "http://a/b/c/g.."},
        {"..g", "http://a/b/c/..g"},
        {"./../g", "http://a/b/g"},
        {"./g/.", "http://a/b/c/g/"},
        {"g/./h", "http://a/b/c/g/h"},
        {"g/../h", "http://a/b/c/h"},
        {"g;x=1/./y", "http://a/b/c/g;x=1/y"},
        {"g;x=1/../y", "http://a/b/c/y"},
        {"g?y/./x", "http://a/b/c/g?y/./x"},
        {"g?y/../x", "http://a/b/c/g?y/../x"},
        {"g#s/./x", "http://a/b/c/g"},
        {"g#s/../x", "http://a/b/c/g"},
        // Backward-compatible (and browser) reading of a same-scheme ref.
        {"http:g", "http://a/b/c/g"},
    };
    for (const auto& c : cases) {
        CAPTURE(c[0]);
        CHECK(resolved(base, c[0]) == c[1]);
    }
}

TEST_CASE("resolve_url: crawler-relevant references") {
    const char* base = "http://www.site.com/dir/page.html?x=1";
    const char* cases[][2] = {
        {"other.html", "http://www.site.com/dir/other.html"},
        {"  other.html\n", "http://www.site.com/dir/other.html"},
        {"oth\ner\t.html", "http://www.site.com/dir/other.html"},
        {"?", "http://www.site.com/dir/page.html?"},
        {"?y=2", "http://www.site.com/dir/page.html?y=2"},
        {"#top", "http://www.site.com/dir/page.html?x=1"},
        {"//cdn.site.com/a.js", "http://cdn.site.com/a.js"},
        {"//cdn.site.com", "http://cdn.site.com/"},
        {"//cdn.site.com?q", "http://cdn.site.com/?q"},
        {"https://secure.site.com/login", "https://secure.site.com/login"},
        {"HTTP://UPPER.COM/Path", "http://upper.com/Path"},
        {"http://x.com:8080/a/../b", "http://x.com:8080/b"},
        {"/a b/c", "http://www.site.com/a%20b/c"},
        {"mailto:me@site.com", "<fail>"},
        {"javascript:void(0)", "<fail>"},
        {"JavaScript:void(0)", "<fail>"},
        {"data:text/html,hi", "<fail>"},
        {"ftp://site.com/f", "<fail>"},
        {"tel:+123", "<fail>"},
        {"https:foo", "<fail>"},
        {"//user@evil.com/", "<fail>"},
        {"//[::1]/", "<fail>"},
        {"//bad host/", "<fail>"},
        {"http://", "<fail>"},
    };
    for (const auto& c : cases) {
        CAPTURE(c[0]);
        CHECK(resolved(base, c[0]) == c[1]);
    }
    CHECK(resolved("https://s.com/a/b", "//cdn.com/x") == "https://cdn.com/x");
    CHECK(resolved("https://s.com:8443/a/b", "c") == "https://s.com:8443/a/c");
    CHECK(resolved("https://s.com/a/b", "https:c") == "https://s.com/a/c");
    CHECK(resolved("http://s.com", "c") == "http://s.com/c");
    CHECK(resolved("http://s.com", "../c") == "http://s.com/c");
}

TEST_CASE("resolve_url allows out to alias base and reuses it") {
    Url u;
    REQUIRE(parse_url("http://a.com/x/y/z", u));
    REQUIRE(resolve_url(u, "../w?q", u));
    CHECK(wc::parse::to_string(u) == "http://a.com/x/w?q");
    REQUIRE(resolve_url(u, "//b.com/", u));
    CHECK(wc::parse::to_string(u) == "http://b.com/");
}

TEST_CASE("parse_ipv4_literal is strict") {
    uint32_t ip = 0;
    REQUIRE(parse_ipv4_literal("1.2.3.4", ip));
    unsigned char b[4];
    std::memcpy(b, &ip, 4);
    CHECK(b[0] == 1);
    CHECK(b[1] == 2);
    CHECK(b[2] == 3);
    CHECK(b[3] == 4);
    CHECK(parse_ipv4_literal("0.0.0.0", ip));
    CHECK(ip == 0);
    CHECK(parse_ipv4_literal("255.255.255.255", ip));
    CHECK(ip == 0xFFFFFFFFu);
    CHECK(parse_ipv4_literal("10.0.0.1", ip));
    const char* bad[] = {"", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.04", "256.1.1.1", "1.2.3.4 ", " 1.2.3.4",
                         "a.b.c.d", "1..2.3", "1234.1.1.1", "1.2.3.", ".1.2.3", "1.2.3.4:80", "0x1.2.3.4", "example.com"};
    for (const char* s : bad) {
        CAPTURE(s);
        CHECK_FALSE(parse_ipv4_literal(s, ip));
    }
}
