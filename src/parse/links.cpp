#include "parse/links.h"

#include <cstring>

namespace wc::parse {
namespace {

constexpr char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }
constexpr bool is_alpha(char c) {
    const char l = static_cast<char>(c | 0x20);
    return l >= 'a' && l <= 'z';
}
constexpr bool is_digit(char c) { return c >= '0' && c <= '9'; }
constexpr bool is_alnum(char c) { return is_alpha(c) || is_digit(c); }
// HTML whitespace: tab, LF, FF, CR, space.
constexpr bool is_space(char c) { return c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\f'; }

// `s` (lowercase) equals [p, p + s.size()) case-insensitively.
bool imatch(const char* p, const char* end, std::string_view s) {
    if (static_cast<size_t>(end - p) < s.size()) {
        return false;
    }
    for (size_t i = 0; i < s.size(); ++i) {
        if (to_lower(p[i]) != s[i]) {
            return false;
        }
    }
    return true;
}

const char* find_char(const char* p, const char* end, char c) {
    return p < end ? static_cast<const char*>(std::memchr(p, c, static_cast<size_t>(end - p))) : nullptr;
}

// Returns the position just past the comment that starts at `p` (after
// "<!--"), or nullptr if it runs to EOF. "<!-->" and "<!--->" end at once.
const char* skip_comment(const char* p, const char* end) {
    const char* const start = p;
    while (const char* gt = find_char(p, end, '>')) {
        if (gt == start || (gt == start + 1 && *start == '-') || (gt - start >= 2 && gt[-1] == '-' && gt[-2] == '-')) {
            return gt + 1;
        }
        p = gt + 1;
    }
    return nullptr;
}

// Position of the "</name" closing a raw-text element, or nullptr.
const char* find_end_tag(const char* p, const char* end, std::string_view name) {
    while (const char* lt = find_char(p, end, '<')) {
        const char* n = lt + 2;
        if (n <= end && lt[1] == '/' && imatch(n, end, name)) {
            const char* after = n + name.size();
            if (after == end || is_space(*after) || *after == '/' || *after == '>') {
                return lt;
            }
        }
        p = lt + 1;
    }
    return nullptr;
}

enum class Tag : uint8_t { Other, A, Area, Base, Script, Style };

Tag classify(const char* name, size_t len) {
    switch (len) {
    case 1:
        return to_lower(name[0]) == 'a' ? Tag::A : Tag::Other;
    case 4:
        if (imatch(name, name + 4, "area")) {
            return Tag::Area;
        }
        return imatch(name, name + 4, "base") ? Tag::Base : Tag::Other;
    case 5:
        return imatch(name, name + 5, "style") ? Tag::Style : Tag::Other;
    case 6:
        return imatch(name, name + 6, "script") ? Tag::Script : Tag::Other;
    default:
        return Tag::Other;
    }
}

void append_utf8(std::string& out, uint32_t cp) {
    if (cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
        cp = 0xFFFD;
    }
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

}  // namespace

std::string_view LinkExtractor::decode(std::string_view raw) {
    size_t amp = raw.find('&');
    if (amp == std::string_view::npos) {
        return raw;
    }
    struct Named {
        std::string_view name;  // without '&', with ';'
        char ch;
    };
    static constexpr Named kNamed[] = {
        {"amp;", '&'}, {"AMP;", '&'}, {"quot;", '"'}, {"QUOT;", '"'}, {"apos;", '\''},
        {"lt;", '<'},  {"LT;", '<'},  {"gt;", '>'},   {"GT;", '>'},
    };

    decoded_.assign(raw.substr(0, amp));
    size_t i = amp;
    while (i < raw.size()) {
        if (raw[i] != '&') {
            decoded_.push_back(raw[i++]);
            continue;
        }
        const std::string_view rest = raw.substr(i + 1);
        if (!rest.empty() && rest[0] == '#') {
            // &#ddd; or &#xhhh; (the semicolon is optional in practice).
            size_t j = 1;
            const bool hex = j < rest.size() && (rest[j] == 'x' || rest[j] == 'X');
            j += hex ? 1 : 0;
            const size_t digits_begin = j;
            uint32_t cp = 0;
            while (j < rest.size()) {
                const char c = rest[j];
                uint32_t d;
                if (is_digit(c)) {
                    d = static_cast<uint32_t>(c - '0');
                } else if (hex && to_lower(c) >= 'a' && to_lower(c) <= 'f') {
                    d = static_cast<uint32_t>(to_lower(c) - 'a' + 10);
                } else {
                    break;
                }
                cp = cp > 0x10FFFF ? cp : cp * (hex ? 16 : 10) + d;
                ++j;
            }
            if (j == digits_begin) {
                decoded_.push_back('&');
                ++i;
                continue;
            }
            if (j < rest.size() && rest[j] == ';') {
                ++j;
            }
            append_utf8(decoded_, cp);
            i += 1 + j;
            continue;
        }
        bool matched = false;
        for (const Named& n : kNamed) {
            if (rest.substr(0, n.name.size()) == n.name) {
                decoded_.push_back(n.ch);
                i += 1 + n.name.size();
                matched = true;
                break;
            }
        }
        // Legacy "&amp" without ';' decodes in attributes unless followed by
        // an alphanumeric or '=' (HTML §13.2.5.73).
        if (!matched && rest.substr(0, 3) == "amp" && (rest.size() == 3 || (!is_alnum(rest[3]) && rest[3] != '='))) {
            decoded_.push_back('&');
            i += 4;
            matched = true;
        }
        if (!matched) {
            decoded_.push_back('&');
            ++i;
        }
    }
    return decoded_;
}

size_t LinkExtractor::extract(std::string_view html, const Url& page_url, std::vector<Url>* out) {
    if (out != nullptr) {
        out->clear();
    }
    const char* p = html.data();
    const char* const end = p + html.size();
    const Url* base = &page_url;
    bool base_seen = false;
    size_t count = 0;

    while ((p = find_char(p, end, '<')) != nullptr) {
        ++p;
        if (p >= end) {
            break;
        }
        const char first = *p;
        if (first == '!') {
            if (end - p >= 3 && p[1] == '-' && p[2] == '-') {
                p = skip_comment(p + 3, end);
                if (p == nullptr) {
                    break;
                }
            }
            continue;
        }
        // Fast reject: only a, area, base, script, style matter.
        const char l = to_lower(first);
        if (l != 'a' && l != 'b' && l != 's') {
            continue;
        }
        const char* const name = p;
        while (p < end && !is_space(*p) && *p != '/' && *p != '>') {
            ++p;
        }
        const Tag tag = classify(name, static_cast<size_t>(p - name));
        if (tag == Tag::Other) {
            continue;
        }
        if (tag == Tag::Script || tag == Tag::Style) {
            p = find_end_tag(p, end, tag == Tag::Script ? "script" : "style");
            if (p == nullptr) {
                break;
            }
            continue;
        }

        // Attributes, following the HTML tokenizer's before/after attribute
        // name and value states closely enough to find quoted '>' correctly.
        std::string_view href;
        bool has_href = false;
        for (;;) {
            while (p < end && (is_space(*p) || *p == '/')) {
                ++p;
            }
            if (p >= end) {
                break;
            }
            if (*p == '>') {
                ++p;
                break;
            }
            const char* const attr = p;
            ++p;  // a leading '=' belongs to the name
            while (p < end && !is_space(*p) && *p != '/' && *p != '>' && *p != '=') {
                ++p;
            }
            const bool is_href = p - attr == 4 && imatch(attr, p, "href");
            while (p < end && is_space(*p)) {
                ++p;
            }
            if (p >= end || *p != '=') {
                if (is_href && !has_href) {
                    has_href = true;
                    href = {};
                }
                continue;
            }
            ++p;
            while (p < end && is_space(*p)) {
                ++p;
            }
            std::string_view value;
            if (p < end && (*p == '"' || *p == '\'')) {
                const char* const vbegin = p + 1;
                const char* q = find_char(vbegin, end, *p);
                if (q == nullptr) {
                    // Unterminated quote swallows the rest of the document.
                    p = end;
                    break;
                }
                value = std::string_view(vbegin, static_cast<size_t>(q - vbegin));
                p = q + 1;
            } else {
                const char* const vbegin = p;
                while (p < end && !is_space(*p) && *p != '>') {
                    ++p;
                }
                value = std::string_view(vbegin, static_cast<size_t>(p - vbegin));
            }
            // Duplicate attributes are dropped; the first one wins.
            if (is_href && !has_href) {
                has_href = true;
                href = value;
            }
        }
        if (!has_href) {
            continue;
        }

        const std::string_view ref = decode(href);
        if (tag == Tag::Base) {
            if (!base_seen) {
                base_seen = true;
                if (resolve_url(page_url, ref, base_)) {
                    base = &base_;
                }
            }
            continue;
        }
        bool blank = true;
        for (const char c : ref) {
            if (static_cast<unsigned char>(c) > 0x20) {
                blank = false;
                break;
            }
        }
        if (blank || !resolve_url(*base, ref, scratch_)) {
            continue;
        }
        ++count;
        if (out != nullptr) {
            out->push_back(scratch_);
        }
    }
    return count;
}

}  // namespace wc::parse
