#pragma once
// HTML link extraction: href values of <a> and <area> tags, resolved against
// the page URL (or the first <base href>), counting only http/https results.

#include "parse/url.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace wc::parse {

// Not a full HTML5 tokenizer: it finds tags by scanning for '<', parses the
// attributes of <a>, <area> and <base> only, and skips comments and the
// contents of <script> and <style>. Attribute values have character
// references decoded (&amp;, &#38;, &#x26;, ...). Empty hrefs and refs that do
// not resolve to a valid http(s) URL are not counted; fragment-only refs
// ("#top") count as links to the page itself.
//
// Deliberate differences from the course's HTMLParserBase (which the legacy
// crawler used): that parser counts only http (drops absolute https), ignores
// <area> and <base>, scans inside <style>, drops rel="nofollow" links and
// hrefs with non-ASCII character references, and counts empty hrefs,
// <frame>/<iframe> src and <meta http-equiv=refresh> URLs.
//
// One extractor per thread; its scratch buffers are reused across calls, so
// count-only extraction does not allocate once warmed up (except for the rare
// href containing an embedded tab or newline, which is copied to strip it).
class LinkExtractor {
public:
    // Returns the number of links. When `out` is non-null it is cleared and
    // receives the resolved links in document order (duplicates included).
    size_t extract(std::string_view html, const Url& page_url, std::vector<Url>* out = nullptr);

private:
    // Decodes character references in `raw` when present; returns a view of
    // either `raw` or `decoded_`.
    std::string_view decode(std::string_view raw);

    Url base_;
    Url scratch_;
    std::string decoded_;
};

}  // namespace wc::parse
