// LinkExtractor on arbitrary HTML.
//
// Input: if it starts with "http", the first line is the page URL and the
// rest is the document; otherwise the whole input is the document, served
// from a fixed page URL.
//
// Invariants:
// - count-only extraction returns the same count as collecting, which equals
//   the number of collected URLs, and a reused (warm) extractor agrees with a
//   fresh one in both modes;
// - every collected URL is well formed and to_string() of it re-parses to
//   the same Url.

#include "parse/links.h"

#include "check.h"

#include <string>
#include <string_view>
#include <vector>

using namespace wc::parse;

namespace {

bool same(const Url& a, const Url& b) {
    return a.scheme == b.scheme && a.host == b.host && a.port == b.port && a.target == b.target;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string_view html(reinterpret_cast<const char*>(data), size);
    Url page;
    FUZZ_CHECK(parse_url("http://www.example.com/dir/page.html?x=1", page));
    if (html.substr(0, 4) == "http") {
        const size_t nl = html.find('\n');
        Url u;
        if (nl != std::string_view::npos && parse_url(html.substr(0, nl), u)) {
            page = u;
            html.remove_prefix(nl + 1);
        }
    }

    // Exact-size heap copy, so ASan catches reads past the document.
    const std::vector<char> doc(html.begin(), html.end());
    const std::string_view d(doc.data(), doc.size());

    static LinkExtractor warm;  // scratch buffers carry over between inputs
    LinkExtractor fresh;
    std::vector<Url> links;
    links.push_back(page);  // extract() must clear it
    const size_t collected = fresh.extract(d, page, &links);
    FUZZ_CHECK(collected == links.size());
    FUZZ_CHECK(fresh.extract(d, page) == collected);
    FUZZ_CHECK(warm.extract(d, page) == collected);
    std::vector<Url> again;
    FUZZ_CHECK(warm.extract(d, page, &again) == collected);
    FUZZ_CHECK(again.size() == links.size());

    std::string s;
    for (size_t i = 0; i < links.size(); ++i) {
        const Url& u = links[i];
        FUZZ_CHECK(same(u, again[i]));
        FUZZ_CHECK(!u.host.empty() && !u.target.empty() && u.target.front() == '/' && u.port != 0);
        s.clear();
        append_to_string(s, u);
        Url re;
        FUZZ_CHECK(parse_url(s, re));
        FUZZ_CHECK(same(re, u));
    }
    return 0;
}
