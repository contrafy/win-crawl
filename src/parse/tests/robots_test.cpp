#include "parse/robots.h"

#include "doctest/doctest.h"

#include <chrono>
#include <string>

using wc::parse::RobotsRules;

namespace {

struct Check {
    const char* target;
    bool allowed;
};

void expect(const RobotsRules& rules, std::initializer_list<Check> checks) {
    for (const Check& c : checks) {
        CAPTURE(c.target);
        CHECK(rules.allowed(c.target) == c.allowed);
    }
}

// Rules as written for a single "*" group.
RobotsRules star(const std::string& lines) {
    return RobotsRules::parse("User-agent: *\n" + lines, "wincrawl");
}

}  // namespace

TEST_CASE("RFC 9309 section 5.1 example: group selection") {
    const char* txt =
        "User-Agent: *\n"
        "Disallow: *.gif$\n"
        "Disallow: /example/\n"
        "Allow: /publications/\n"
        "\n"
        "User-Agent: foobot\n"
        "Disallow:/\n"
        "Allow:/example/page.html\n"
        "Allow:/example/allowed.gif\n"
        "\n"
        "User-Agent: barbot\n"
        "User-Agent: bazbot\n"
        "Disallow: /example/page.html\n"
        "\n"
        "User-Agent: quxbot\n";

    expect(RobotsRules::parse(txt, "foobot"), {{"/example/page.html", true},
                                               {"/example/allowed.gif", true},
                                               {"/example/other.html", false},
                                               {"/", false},
                                               {"/robots.txt", true}});
    for (const char* bot : {"barbot", "bazbot", "BazBot"}) {
        CAPTURE(bot);
        expect(RobotsRules::parse(txt, bot),
               {{"/example/page.html", false}, {"/example/other.html", true}, {"/x.gif", true}});
    }
    // A matching group with no rules allows everything.
    const RobotsRules qux = RobotsRules::parse(txt, "quxbot");
    CHECK(qux.rule_count() == 0);
    expect(qux, {{"/example/page.html", true}, {"/x.gif", true}});
    // Everyone else gets "*".
    expect(RobotsRules::parse(txt, "wincrawl"), {{"/x.gif", false},
                                                 {"/x.gif?y", true},
                                                 {"/example/", false},
                                                 {"/example/a", false},
                                                 {"/example", true},
                                                 {"/publications/", true},
                                                 {"/", true}});
}

TEST_CASE("user-agent matching") {
    const char* txt =
        "User-agent: WinCrawl/2.0 (+http://x)\n"
        "Disallow: /a\n"
        "\n"
        "User-agent: wincrawler\n"
        "Disallow: /b\n"
        "\n"
        "User-agent: *\n"
        "Disallow: /c\n";
    expect(RobotsRules::parse(txt, "wincrawl"), {{"/a", false}, {"/b", true}, {"/c", true}});
    expect(RobotsRules::parse(txt, "WINCRAWLER"), {{"/a", true}, {"/b", false}, {"/c", true}});
    expect(RobotsRules::parse(txt, "win"), {{"/a", true}, {"/b", true}, {"/c", false}});
    expect(RobotsRules::parse(txt, "otherbot"), {{"/a", true}, {"/b", true}, {"/c", false}});

    SUBCASE("groups for the same agent merge, as do star groups") {
        const char* merged =
            "User-agent: wincrawl\nDisallow: /a\n"
            "User-agent: *\nDisallow: /s1\n"
            "User-agent: other\nDisallow: /o\n"
            "User-agent: WinCrawl\nDisallow: /b\n"
            "User-agent: *\nDisallow: /s2\n";
        expect(RobotsRules::parse(merged, "wincrawl"), {{"/a", false}, {"/b", false}, {"/s1", true}, {"/o", true}});
        expect(RobotsRules::parse(merged, "x"), {{"/a", true}, {"/s1", false}, {"/s2", false}});
    }
    SUBCASE("a group may name several agents including *") {
        const char* shared = "User-agent: other\nUser-agent: *\nUser-agent: wincrawl\nDisallow: /p\n";
        expect(RobotsRules::parse(shared, "wincrawl"), {{"/p", false}});
        expect(RobotsRules::parse(shared, "x"), {{"/p", false}});
    }
    SUBCASE("rules before any user-agent are ignored") {
        expect(RobotsRules::parse("Disallow: /\nUser-agent: x\nDisallow: /y\n", "wincrawl"), {{"/", true}});
    }
    SUBCASE("no robots content allows everything") {
        expect(RobotsRules::parse("", "wincrawl"), {{"/", true}, {"/anything", true}});
        expect(RobotsRules::parse("<html>not robots</html>", "wincrawl"), {{"/", true}});
    }
    SUBCASE("specific group overrides star even if less restrictive") {
        expect(RobotsRules::parse("User-agent: *\nDisallow: /\n\nUser-agent: wincrawl\nDisallow:\n", "wincrawl"),
               {{"/", true}, {"/x", true}});
    }
}

TEST_CASE("Google path matching examples") {
    SUBCASE("prefix") {
        const RobotsRules r = star("Disallow: /fish\n");
        expect(r, {{"/fish", false},
                   {"/fish.html", false},
                   {"/fish/salmon.html", false},
                   {"/fishheads", false},
                   {"/fishheads/yummy.html", false},
                   {"/fish.php?id=anything", false},
                   {"/Fish.asp", true},
                   {"/catfish", true},
                   {"/?id=fish", true},
                   {"/desert/fish", true}});
        // Trailing '*' is the same as none.
        expect(star("Disallow: /fish*\n"), {{"/fish", false}, {"/fishheads", false}, {"/Fish.asp", true}});
    }
    SUBCASE("directory") {
        expect(star("Disallow: /fish/\n"),
               {{"/fish/", false}, {"/fish/?id=anything", false}, {"/fish/salmon.htm", false}, {"/fish", true},
                {"/fish.html", true}, {"/animals/fish/", true}, {"/Fish/Salmon.asp", true}});
    }
    SUBCASE("wildcard and end anchor") {
        expect(star("Disallow: /*.php\n"),
               {{"/index.php", false}, {"/filename.php", false}, {"/folder/filename.php", false},
                {"/folder/filename.php?parameters", false}, {"/folder/any.php.file.html", false},
                {"/filename.php/", false}, {"/", true}, {"/windows.PHP", true}});
        expect(star("Disallow: /*.php$\n"),
               {{"/filename.php", false}, {"/folder/filename.php", false}, {"/filename.php?parameters", true},
                {"/filename.php/", true}, {"/filename.php5", true}, {"/windows.PHP", true}});
        expect(star("Disallow: /fish*.php\n"),
               {{"/fish.php", false}, {"/fishheads/catfish.php?parameters", false}, {"/Fish.PHP", true}});
        expect(star("Disallow: /$\n"), {{"/", false}, {"/a", true}});
        expect(star("Disallow: /a*b*c\n"), {{"/axxbyyc", false}, {"/abc", false}, {"/acb", true}});
        expect(star("Disallow: *\n"), {{"/", false}, {"/x", false}});
        // '$' is only special at the end.
        expect(star("Disallow: /a$b\n"), {{"/a$b", false}, {"/a", true}});
    }
}

TEST_CASE("Google precedence examples") {
    // Longest match wins; Allow wins ties.
    expect(star("Allow: /p\nDisallow: /\n"), {{"/page", true}, {"/q", false}});
    expect(star("Allow: /folder\nDisallow: /folder\n"), {{"/folder/page", true}});
    expect(star("Allow: /page\nDisallow: /*.htm\n"), {{"/page.htm", false}});
    expect(star("Allow: /page\nDisallow: /*.ph\n"), {{"/page.php5", true}});
    expect(star("Allow: /$\nDisallow: /\n"), {{"/", true}, {"/page.htm", false}});
    expect(star("Allow: /$\nDisallow: /\n"), {{"/", true}, {"/page.htm", false}});
    // Order in the file does not matter.
    expect(star("Disallow: /\nAllow: /p\n"), {{"/page", true}});
    expect(star("Disallow: /a/b\nAllow: /a\n"), {{"/a/b/c", false}, {"/a/c", true}});
}

TEST_CASE("empty and special rules") {
    expect(star("Disallow:\n"), {{"/", true}, {"/x", true}});
    expect(star("Disallow: \nAllow:\n"), {{"/", true}});
    expect(star("Disallow: /\n"), {{"/robots.txt", true}, {"/robots.txt?x=1", true}, {"/robots.txtx", false}});
    CHECK(star("Disallow:\n").rule_count() == 0);
}

TEST_CASE("syntax tolerance") {
    SUBCASE("comments, case, whitespace, unknown lines") {
        const char* txt =
            "# leading comment\n"
            "  USER-AGENT  :  *   # trailing comment\n"
            "sitemap: http://x.com/sitemap.xml\n"
            "DISALLOW:/private # hidden\n"
            "foo: bar\n"
            "no colon here\n"
            "allow : /private/ok\n";
        expect(RobotsRules::parse(txt, "wincrawl"),
               {{"/private", false}, {"/private/x", false}, {"/private/ok", true}, {"/public", true}});
    }
    SUBCASE("BOM and line endings") {
        for (const char* txt : {"\xEF\xBB\xBFUser-agent: *\nDisallow: /x\n", "User-agent: *\r\nDisallow: /x\r\n",
                                "User-agent: *\rDisallow: /x\r", "User-agent: *\n\r\nDisallow: /x",
                                "User-agent: *\r\n\r\nDisallow: /x"}) {
            CAPTURE(txt);
            expect(RobotsRules::parse(txt, "wincrawl"), {{"/x", false}, {"/y", true}});
        }
    }
    SUBCASE("key typos accepted by Google") {
        expect(RobotsRules::parse("useragent: *\ndissallow: /a\ndisalow: /b\n", "wincrawl"),
               {{"/a", false}, {"/b", false}, {"/c", true}});
    }
    SUBCASE("sitemap and unknown lines do not split agent lines") {
        expect(RobotsRules::parse("User-agent: a\nSitemap: http://x/s.xml\nUser-agent: wincrawl\nDisallow: /x\n",
                                  "wincrawl"),
               {{"/x", false}});
    }
}

TEST_CASE("percent-encoding normalization") {
    expect(star("Disallow: /%7Efoo\n"), {{"/~foo", false}, {"/%7efoo", false}, {"/%7Efoo", false}});
    expect(star("Disallow: /~bar\n"), {{"/%7Ebar", false}, {"/~bar", false}});
    expect(star("Disallow: /a%2fb\n"), {{"/a%2Fb", false}, {"/a%2fb", false}, {"/a/b", true}});
    expect(star("Disallow: /\xC3\xA9t\xC3\xA9\n"), {{"/%C3%A9t%C3%A9", false}, {"/%c3%a9t%c3%a9", false}, {"/ete", true}});
    expect(star("Disallow: /a b\n"), {{"/a%20b", false}});
}

TEST_CASE("crawl-delay") {
    CHECK_FALSE(star("Disallow: /x\n").crawl_delay().has_value());
    CHECK(star("Crawl-delay: 2.5\n").crawl_delay().value() == doctest::Approx(2.5));
    CHECK(star("crawl-delay: 10\nCrawl-delay: 20\n").crawl_delay().value() == doctest::Approx(10));
    CHECK_FALSE(star("Crawl-delay: soon\n").crawl_delay().has_value());
    CHECK_FALSE(star("Crawl-delay: -1\n").crawl_delay().has_value());
    const char* txt = "User-agent: *\nCrawl-delay: 5\n\nUser-agent: wincrawl\nCrawl-delay: 1\nDisallow: /x\n";
    CHECK(RobotsRules::parse(txt, "wincrawl").crawl_delay().value() == doctest::Approx(1));
    CHECK(RobotsRules::parse(txt, "other").crawl_delay().value() == doctest::Approx(5));
    // Crawl-delay ends the agent list like any rule.
    const RobotsRules r = RobotsRules::parse("User-agent: a\nCrawl-delay: 3\nUser-agent: wincrawl\nDisallow: /\n",
                                             "wincrawl");
    CHECK_FALSE(r.crawl_delay().has_value());
    CHECK_FALSE(r.allowed("/x"));
}

TEST_CASE("long targets and patterns") {
    const std::string path = "/" + std::string(4000, 'a') + ".gif";
    expect(star("Disallow: /*a*a*a*a*.gif$\n"), {{path.c_str(), false}});
    expect(star("Disallow: /*b\n"), {{path.c_str(), true}});
}

TEST_CASE("wildcard segments: leftmost matching, anchors, literal '$'") {
    expect(star("Disallow: /*ab*ab$\n"), {{"/xabab", false}, {"/xab", true}, {"/aabab", false}, {"/abxab", false},
                                         {"/abab", false}, {"/ab", true}});
    expect(star("Disallow: /a*$\n"), {{"/a", false}, {"/abc", false}, {"/b", true}});
    expect(star("Disallow: /a$b\n"), {{"/a$b", false}, {"/a", true}, {"/a$bc", false}});
    expect(star("Disallow: /a$$\n"), {{"/a$", false}, {"/a$x", true}, {"/a", true}});
    expect(star("Disallow: /**x**\n"), {{"/yx", false}, {"/y", true}});
    expect(star("Disallow: *.php$\n"), {{"/index.php", false}, {"/index.php?x", true}, {"/a.php.bak", true}});
    expect(star("Disallow: /*aab\n"), {{"/aaab", false}, {"/abaab", false}, {"/aba", true}});
    expect(star("Disallow: /*xyz*xy$\n"), {{"/xyzxy", false}, {"/xyxy", true}, {"/xyzx", true}});
}

TEST_CASE("hostile robots.txt matches in linear time") {
    // 260 rules of 1000 "*a" pairs (a 512 KiB file) against an 8 KB target:
    // the old position-set matcher took O(rules * pattern * target) here,
    // about 300 ms per allowed() call for a 2 KB target in release builds.
    std::string rule = "Disallow: /";
    for (int i = 0; i < 1000; ++i) {
        rule += "*a";
    }
    rule += "b\n";
    std::string body = "User-agent: *\n";
    while (body.size() + rule.size() <= 512 * 1024) {
        body += rule;
    }
    const RobotsRules rules = RobotsRules::parse(body, "wincrawl");
    CHECK(rules.rule_count() == 260);
    const std::string miss = "/" + std::string(8000, 'a');
    const std::string hit = miss + "b";
    const auto start = std::chrono::steady_clock::now();
    CHECK(rules.allowed(miss));
    CHECK_FALSE(rules.allowed(hit));
    // Generous: linear matching takes a few ms even in debug builds.
    CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
}
