#include "parse/links.h"

#include "doctest/doctest.h"

#include <string>
#include <vector>

using wc::parse::LinkExtractor;
using wc::parse::Url;

namespace {

std::vector<std::string> links_of(std::string_view html, std::string_view page = "http://example.com/dir/page.html") {
    Url base;
    REQUIRE(wc::parse::parse_url(page, base));
    LinkExtractor ex;
    std::vector<Url> out;
    const size_t n = ex.extract(html, base, &out);
    CHECK(n == out.size());
    CHECK(ex.extract(html, base) == n);  // count-only agrees
    std::vector<std::string> s;
    for (const Url& u : out) {
        s.push_back(wc::parse::to_string(u));
    }
    return s;
}

using List = std::vector<std::string>;

}  // namespace

TEST_CASE("href quoting and attribute syntax") {
    struct Case {
        const char* html;
        List expect;
    };
    const Case cases[] = {
        {R"(<a href="x.html">x</a>)", {"http://example.com/dir/x.html"}},
        {R"(<a href='x.html'>x</a>)", {"http://example.com/dir/x.html"}},
        {R"(<a href=x.html>x</a>)", {"http://example.com/dir/x.html"}},
        {R"(<a href=/x/y?z=1>x</a>)", {"http://example.com/x/y?z=1"}},
        {R"(<a href = "x.html" >)", {"http://example.com/dir/x.html"}},
        {"<a\n\thref\n=\n'x.html'>", {"http://example.com/dir/x.html"}},
        {R"(<A HREF="X.html">)", {"http://example.com/dir/X.html"}},
        {R"(<a Href="x">)", {"http://example.com/dir/x"}},
        {R"(<AREA shape=rect href="map.html">)", {"http://example.com/dir/map.html"}},
        {R"(<a class="c" id=i href="x" target=_blank>)", {"http://example.com/dir/x"}},
        {R"(<a title="a > b" href="x">)", {"http://example.com/dir/x"}},
        {R"(<a title='say "hi"' href="x">)", {"http://example.com/dir/x"}},
        {R"(<a href="x" />)", {"http://example.com/dir/x"}},
        {R"(<a/href="x">)", {"http://example.com/dir/x"}},
        {R"(<a href="first" href="second">)", {"http://example.com/dir/first"}},
        {R"(<a data-href="no" href="yes">)", {"http://example.com/dir/yes"}},
        {R"(<a href="  spaced.html  ">)", {"http://example.com/dir/spaced.html"}},
        {"<a href=\"multi\nline.html\">", {"http://example.com/dir/multiline.html"}},
        {R"(<a name="anchor">)", {}},
        {R"(<a href>)", {}},
        {R"(<a href="">)", {}},
        {R"(<a href="   ">)", {}},
        {R"(<a hreff="x"><a xhref="x">)", {}},
        {R"(<abbr href="x"><address href="x"><b href="x"><span href="x">)", {}},
        {R"(<link href="style.css"><img src="i.png"><frame src="f.html"><iframe src="f">)", {}},
        {R"(<a href="unterminated)", {}},
        {"<a href=\"x\"", {"http://example.com/dir/x"}},
        {"<", {}},
        {"<a", {}},
        {"", {}},
    };
    for (const Case& c : cases) {
        CAPTURE(c.html);
        CHECK(links_of(c.html) == c.expect);
    }
}

TEST_CASE("scheme filtering and resolution") {
    const List got = links_of(R"html(
        <a href="http://other.com/a">
        <a href="HTTPS://Secure.com">
        <a href="//cdn.example.com/x">
        <a href="../up.html">
        <a href="/abs?q=1#frag">
        <a href="?only=query">
        <a href="#top">
        <a href="mailto:me@example.com">
        <a href="javascript:void(0)">
        <a href=" JavaScript:alert(1)">
        <a href="tel:123">
        <a href="ftp://files.example.com/">
        <a href="data:text/html,hi">
        <a href="http://bad host/">
        <a href="http://[::1]/">
        <a href="http://user@host/">
    )html");
    const List expect = {
        "http://other.com/a",
        "https://secure.com/",
        "http://cdn.example.com/x",
        "http://example.com/up.html",
        "http://example.com/abs?q=1",
        "http://example.com/dir/page.html?only=query",
        "http://example.com/dir/page.html",
    };
    CHECK(got == expect);
}

TEST_CASE("character references in href") {
    struct Case {
        const char* html;
        const char* expect;
    };
    const Case cases[] = {
        {R"(<a href="?a=1&amp;b=2">)", "http://example.com/dir/page.html?a=1&b=2"},
        {R"(<a href="?a=1&#38;b=2">)", "http://example.com/dir/page.html?a=1&b=2"},
        {R"(<a href="?a=1&#038;b=2">)", "http://example.com/dir/page.html?a=1&b=2"},
        {R"(<a href="?a=1&#x26;b=2">)", "http://example.com/dir/page.html?a=1&b=2"},
        {R"(<a href="?a=1&#X26;b=2">)", "http://example.com/dir/page.html?a=1&b=2"},
        {R"(<a href="?a=1&AMP;b=2">)", "http://example.com/dir/page.html?a=1&b=2"},
        {R"(<a href="?a=1&b=2">)", "http://example.com/dir/page.html?a=1&b=2"},
        {R"(<a href="?a=1&amp=2">)", "http://example.com/dir/page.html?a=1&amp=2"},
        {R"(<a href="?a=1&ampb=2">)", "http://example.com/dir/page.html?a=1&ampb=2"},
        {R"(<a href="?x&amp">)", "http://example.com/dir/page.html?x&"},
        {R"(<a href="?x=&quot;q&quot;">)", "http://example.com/dir/page.html?x=\"q\""},
        {R"(<a href="&#47;root">)", "http://example.com/root"},
        {R"(<a href="&#x2F;root&#x2f;x">)", "http://example.com/root/x"},
        {R"(<a href="?e=&#233;">)", "http://example.com/dir/page.html?e=%C3%A9"},
        // Malformed numeric references stay literal, so '#' starts the fragment.
        {R"(<a href="/x&#y&#x;z">)", "http://example.com/x&"},
        {R"(<a href="/x&#zz">)", "http://example.com/x&"},
        {R"(<a href="?&#;">)", "http://example.com/dir/page.html?&"},
        {R"(<a href="http&#58;//other.com/">)", "http://other.com/"},
        {R"html(<a href="javascript&#58;alert(1)">)html", nullptr},
        {R"html(<a href="&#x6A;avascript:alert(1)">)html", nullptr},
    };
    for (const Case& c : cases) {
        CAPTURE(c.html);
        const List got = links_of(c.html);
        if (c.expect == nullptr) {
            CHECK(got.empty());
        } else {
            CHECK(got == List{c.expect});
        }
    }
}

TEST_CASE("base href") {
    CHECK(links_of(R"(<head><base href="http://other.com/b/"></head><a href="x">)") == List{"http://other.com/b/x"});
    CHECK(links_of(R"(<BASE HREF="/root/"><a href="x">)") == List{"http://example.com/root/x"});
    // Links before <base> use the page URL; only the first <base href> counts.
    CHECK(links_of(R"(<a href="x"><base href="http://b.com/"><base href="http://c.com/"><a href="y">)") ==
          List{"http://example.com/dir/x", "http://b.com/y"});
    // A <base> without href does not freeze the base; an unusable one is ignored.
    CHECK(links_of(R"(<base target="_top"><base href="http://b.com/"><a href="y">)") == List{"http://b.com/y"});
    CHECK(links_of(R"(<base href="mailto:x@y"><a href="y">)") == List{"http://example.com/dir/y"});
    // <base> is not itself a link.
    CHECK(links_of(R"(<base href="http://b.com/">)").empty());
    // The base persists only within one extract() call.
    Url page;
    REQUIRE(wc::parse::parse_url("http://p.com/", page));
    LinkExtractor ex;
    std::vector<Url> out;
    CHECK(ex.extract(R"(<base href="http://b.com/x/"><a href="y">)", page, &out) == 1);
    CHECK(wc::parse::to_string(out[0]) == "http://b.com/x/y");
    CHECK(ex.extract(R"(<a href="y">)", page, &out) == 1);
    CHECK(wc::parse::to_string(out[0]) == "http://p.com/y");
}

TEST_CASE("comments, script and style are skipped") {
    struct Case {
        const char* html;
        size_t expect;
    };
    const Case cases[] = {
        {R"(<!-- <a href="no"> --><a href="yes">)", 1},
        {R"(<!--<a href="no">--><a href="yes">)", 1},
        {R"(<!-- -- > <a href="no"> --><a href="yes">)", 1},
        {R"(<!--><a href="yes">)", 1},
        {R"(<!---><a href="yes">)", 1},
        {R"(<!-- unterminated <a href="no">)", 0},
        {R"(<!DOCTYPE html><a href="yes">)", 1},
        {R"(<![CDATA[x]]><a href="yes">)", 1},
        {R"(<script>var s = '<a href="no">';</script><a href="yes">)", 1},
        {R"(<SCRIPT type="text/javascript">document.write("<a href='no'>")</ScRiPt ><a href="yes">)", 1},
        {R"(<script src="x.js"></script><a href="yes"><script>"</scriptx><a href='no'>"</script>)", 1},
        {R"(<script>if (a<b) {}</script/><a href="yes">)", 1},
        {R"(<style>a[href="<a href='no'>"]{}</style><a href="yes">)", 1},
        {R"(<script>unterminated <a href="no">)", 0},
        {R"(<scripts><a href="yes"></scripts>)", 1},
        {R"(<noscript><a href="yes"></noscript>)", 1},
        {R"(</a href="no"><a href="yes">)", 1},
        {R"(<?xml version="1.0"?><a href="yes">)", 1},
        {R"(a < b and <a href="yes">)", 1},
    };
    for (const Case& c : cases) {
        CAPTURE(c.html);
        CHECK(links_of(c.html).size() == c.expect);
    }
}

TEST_CASE("document order, duplicates, and reuse") {
    const char* html = R"(<html><body>
        <p>Intro <a href="one.html">1</a>, <a href="two.html">2</a></p>
        <map><area href="/map"></map>
        <a href="one.html">again</a>
    </body></html>)";
    CHECK(links_of(html) == List{"http://example.com/dir/one.html", "http://example.com/dir/two.html",
                                 "http://example.com/map", "http://example.com/dir/one.html"});

    Url page;
    REQUIRE(wc::parse::parse_url("https://s.com:8443/a/", page));
    LinkExtractor ex;
    std::vector<Url> out{page, page, page};
    CHECK(ex.extract(R"(<a href="b">)", page, &out) == 1);
    REQUIRE(out.size() == 1);
    CHECK(wc::parse::to_string(out[0]) == "https://s.com:8443/a/b");
    CHECK(ex.extract("no links here", page, &out) == 0);
    CHECK(out.empty());
}

TEST_CASE("large synthetic page") {
    std::string html = "<html><head><script>var x='<a href=no>';</script></head><body>";
    for (int i = 0; i < 1000; ++i) {
        html += "<div class=\"row\"><span>text text text</span><a href=\"/p/" + std::to_string(i) +
                "?a=1&amp;b=2\">link</a><!-- <a href=\"c\"> --></div>\n";
    }
    html += "</body></html>";
    Url page;
    REQUIRE(wc::parse::parse_url("http://big.com/", page));
    LinkExtractor ex;
    std::vector<Url> out;
    CHECK(ex.extract(html, page) == 1000);
    CHECK(ex.extract(html, page, &out) == 1000);
    CHECK(wc::parse::to_string(out[999]) == "http://big.com/p/999?a=1&b=2");
}
