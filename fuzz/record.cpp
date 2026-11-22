// The study record's text helpers (crawl/record.h): append_json_string,
// truncate_utf8, alt_svc_has_h3 and parse_hsts, on arbitrary bytes.
//
// Input: byte 0 is the truncate_utf8 limit; the rest is the text, used as a
// string to escape, an Alt-Svc value and a Strict-Transport-Security value.
//
// Invariants:
// - append_json_string appends exactly one JSON string literal (RFC 8259
//   grammar, checked by a small validator here) that is valid UTF-8 (no
//   overlongs, surrogates or code points past U+10FFFF) and keeps what was
//   already in the buffer; for valid UTF-8 input it decodes back to the input;
// - truncate_utf8 returns a prefix of at most `max` bytes that, for valid
//   UTF-8 input, is valid UTF-8 and at most 3 bytes shorter than `max`;
// - alt_svc_has_h3 is false without "h3" in the value, true once a leading
//   h3 alternative is prepended, and ignores leading OWS;
// - parse_hsts: valid results survive a round trip through their canonical
//   serialization, and directive names are case-insensitive.

#include "crawl/record.h"

#include "check.h"

#include <cstdint>
#include <string>
#include <string_view>

using namespace wc::crawl;

namespace {

// Decodes one UTF-8 sequence at s[i]; returns its length (0 if invalid).
size_t utf8_decode(std::string_view s, size_t i, uint32_t& cp) {
    const auto b = [&](size_t k) { return static_cast<unsigned char>(s[k]); };
    const unsigned char c = b(i);
    size_t len;
    if (c < 0x80) {
        cp = c;
        return 1;
    } else if (c >= 0xC2 && c <= 0xDF) {
        len = 2;
        cp = c & 0x1F;
    } else if (c >= 0xE0 && c <= 0xEF) {
        len = 3;
        cp = c & 0x0F;
    } else if (c >= 0xF0 && c <= 0xF4) {
        len = 4;
        cp = c & 0x07;
    } else {
        return 0;
    }
    if (i + len > s.size()) return 0;
    for (size_t k = 1; k < len; ++k) {
        if ((b(i + k) & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (b(i + k) & 0x3F);
    }
    const uint32_t min = len == 2 ? 0x80 : len == 3 ? 0x800 : 0x10000;
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    return len;
}

bool valid_utf8(std::string_view s) {
    for (size_t i = 0; i < s.size();) {
        uint32_t cp;
        const size_t len = utf8_decode(s, i, cp);
        if (len == 0) return false;
        i += len;
    }
    return true;
}

void append_utf8(std::string& out, uint32_t cp) {
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

int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Validates `lit` as exactly one JSON string literal (RFC 8259 section 7)
// and decodes it into `out` as UTF-8 (lone surrogate escapes rejected).
bool json_string(std::string_view lit, std::string& out) {
    out.clear();
    if (lit.size() < 2 || lit.front() != '"' || lit.back() != '"') return false;
    const std::string_view s = lit.substr(1, lit.size() - 2);
    for (size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x20 || c == '"') return false;
        if (c != '\\') {
            uint32_t cp;
            const size_t len = utf8_decode(s, i, cp);
            if (len == 0) return false;
            out.append(s.data() + i, len);
            i += len;
            continue;
        }
        if (i + 1 >= s.size()) return false;
        const char e = s[i + 1];
        i += 2;
        switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
            if (i + 4 > s.size()) return false;
            uint32_t cp = 0;
            for (size_t k = 0; k < 4; ++k) {
                const int h = hex(s[i + k]);
                if (h < 0) return false;
                cp = cp * 16 + static_cast<uint32_t>(h);
            }
            i += 4;
            if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // the writer never needs surrogate pairs
            append_utf8(out, cp);
            break;
        }
        default:
            return false;
        }
    }
    return true;
}

bool contains_h3(std::string_view s) { return s.find("h3") != std::string_view::npos; }

bool same(const Hsts& a, const Hsts& b) {
    return a.valid == b.valid && a.max_age == b.max_age && a.include_subdomains == b.include_subdomains &&
           a.preload == b.preload;
}

std::string upper(std::string_view s) {
    std::string u(s);
    for (char& c : u) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 32);
    }
    return u;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const size_t max = data[0];
    const std::string_view text(reinterpret_cast<const char*>(data + 1), size - 1);
    const bool utf8 = valid_utf8(text);

    // append_json_string
    std::string out = "{\"k\":";
    append_json_string(out, text);
    FUZZ_CHECK(out.compare(0, 5, "{\"k\":") == 0);
    std::string decoded;
    FUZZ_CHECK(json_string(std::string_view(out).substr(5), decoded));
    FUZZ_CHECK(valid_utf8(out));
    if (utf8) FUZZ_CHECK(decoded == text);

    // truncate_utf8
    const std::string_view cut = truncate_utf8(text, max);
    FUZZ_CHECK(cut.data() == text.data() && cut.size() <= max && cut.size() <= text.size());
    if (text.size() <= max) FUZZ_CHECK(cut.size() == text.size());
    if (utf8) {
        FUZZ_CHECK(valid_utf8(cut));
        FUZZ_CHECK(text.size() <= max || cut.size() + 3 >= max);
    }

    // alt_svc_has_h3
    const bool h3 = alt_svc_has_h3(text);
    if (!contains_h3(text)) FUZZ_CHECK(!h3);
    FUZZ_CHECK(alt_svc_has_h3(std::string("h3=\":443\"; ma=86400, ") + std::string(text)));
    FUZZ_CHECK(alt_svc_has_h3(std::string(" \t") + std::string(text)) == h3);

    // parse_hsts
    const Hsts h = parse_hsts(text);
    if (h.valid) {
        std::string canon = "max-age=" + std::to_string(h.max_age);
        if (h.include_subdomains) canon += "; includeSubDomains";
        if (h.preload) canon += "; preload";
        FUZZ_CHECK(same(parse_hsts(canon), h));
    }
    FUZZ_CHECK(same(parse_hsts(upper(text)), h));
    return 0;
}
