// RobotsRules::parse + allowed().
//
// Input byte 0 selects the mode; the rest is split into lines.
//
// Raw mode (bit 0 clear): the rest is a robots.txt body; after a "\0\0"
// separator, if present, each line is a target to check. Invariants:
// "/robots.txt" is always allowed; a file without rules allows everything;
// a crawl-delay is finite and non-negative; allowed() is deterministic.
//
// Model mode (bit 0 set): each line becomes one rule of a single
// "User-agent: *" group ("Allow: " when the line's first byte is odd,
// otherwise "Disallow: ", then the rest of the line as the pattern), and the
// rules are also checked by a straightforward reference matcher (RFC 9309
// longest match, Allow wins ties, '*' wildcard, trailing '$' anchor,
// percent-encoding normalized). Targets are the rule patterns themselves plus
// fuzz-derived variations, so matches actually occur.

#include "parse/robots.h"

#include "check.h"

#include <algorithm>
#include <cmath>
#include <string>
#include <string_view>
#include <vector>

using wc::parse::RobotsRules;

namespace {

std::vector<std::string_view> split_lines(std::string_view s) {
    std::vector<std::string_view> out;
    while (!s.empty()) {
        const size_t nl = s.find('\n');
        out.push_back(s.substr(0, nl));
        if (nl == std::string_view::npos) break;
        s.remove_prefix(nl + 1);
    }
    return out;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// RFC 9309 §2.2.2 percent-encoding normalization, written independently of
// the parser's: decode %XX of unreserved octets, uppercase other escapes,
// encode octets that may not appear raw.
std::string normalize(std::string_view in) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c == '%' && i + 2 < in.size() && hex_value(in[i + 1]) >= 0 && hex_value(in[i + 2]) >= 0) {
            const auto v = static_cast<unsigned char>(hex_value(in[i + 1]) * 16 + hex_value(in[i + 2]));
            const bool unreserved = (v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z') || (v >= '0' && v <= '9') ||
                                    v == '-' || v == '.' || v == '_' || v == '~';
            if (unreserved) {
                out.push_back(static_cast<char>(v));
            } else {
                out += '%';
                out += kHex[v >> 4];
                out += kHex[v & 15];
            }
            i += 2;
        } else if (c <= 0x20 || c >= 0x7F) {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 15];
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

// Does `pat` match a prefix of `path`? Textbook DP: m[i][j] says whether
// pat[i..] matches a prefix of path[j..]. The literal run before the first
// '*' is compared directly first, which settles most pairs cheaply.
bool ref_match(std::string_view path, std::string_view pat) {
    size_t lit = 0;
    while (lit < pat.size() && pat[lit] != '*' && !(pat[lit] == '$' && lit + 1 == pat.size())) ++lit;
    if (path.size() < lit || path.substr(0, lit) != pat.substr(0, lit)) return false;
    path.remove_prefix(lit);
    pat.remove_prefix(lit);

    const size_t P = pat.size();
    const size_t N = path.size();
    static std::vector<char> table;  // reused: allocation dominates under ASan
    table.assign((P + 1) * (N + 1), 0);
    auto m = [&](size_t i, size_t j) -> char& { return table[i * (N + 1) + j]; };
    for (size_t j = 0; j <= N; ++j) m(P, j) = 1;
    for (size_t i = P; i-- > 0;) {
        for (size_t j = N + 1; j-- > 0;) {
            if (pat[i] == '$' && i + 1 == P) {
                m(i, j) = j == N;
            } else if (pat[i] == '*') {
                m(i, j) = m(i + 1, j) || (j < N && m(i, j + 1));  // match nothing, or one more byte
            } else {
                m(i, j) = j < N && path[j] == pat[i] && m(i + 1, j + 1);
            }
        }
    }
    return m(0, 0) != 0;
}

struct ModelRule {
    std::string pattern;  // normalized
    bool allow;
};

bool ref_allowed(const std::vector<ModelRule>& rules, std::string_view target) {
    if (target.substr(0, target.find('?')) == "/robots.txt" || rules.empty()) return true;
    const std::string norm = normalize(target);
    bool any_allow = false, any_disallow = false;
    size_t best_allow = 0, best_disallow = 0;
    for (const ModelRule& r : rules) {
        if (!ref_match(norm, r.pattern)) continue;
        if (r.allow) {
            any_allow = true;
            best_allow = std::max(best_allow, r.pattern.size());
        } else {
            any_disallow = true;
            best_disallow = std::max(best_disallow, r.pattern.size());
        }
    }
    return !any_disallow || (any_allow && best_allow >= best_disallow);
}

void check_raw(std::string_view input) {
    const size_t sep = input.find(std::string_view("\0\0", 2));
    const std::string_view body = input.substr(0, sep);
    const RobotsRules rules = RobotsRules::parse(body, "wincrawl");
    FUZZ_CHECK(rules.allowed("/robots.txt"));
    FUZZ_CHECK(rules.allowed("/robots.txt?x=1"));
    if (rules.rule_count() == 0) FUZZ_CHECK(rules.allowed("/"));
    if (const auto d = rules.crawl_delay()) FUZZ_CHECK(std::isfinite(*d) && *d >= 0);

    std::vector<std::string_view> targets = {"/", "/index.html", "/a/b?c=d"};
    if (sep != std::string_view::npos) {
        for (const std::string_view t : split_lines(input.substr(sep + 2))) targets.push_back(t);
    }
    for (const std::string_view t : targets) {
        const bool a = rules.allowed(t);
        FUZZ_CHECK(rules.allowed(t) == a);
        if (rules.rule_count() == 0) FUZZ_CHECK(a);
    }
}

void check_model(std::string_view input) {
    std::string body = "User-agent: *\n";
    std::vector<ModelRule> model;
    std::vector<std::string> targets = {"/", "/robots.txt"};
    for (std::string_view line : split_lines(input)) {
        if (line.empty()) continue;
        const bool allow = static_cast<unsigned char>(line[0]) & 1;
        line.remove_prefix(1);
        // The pattern as the parser will see it: ends at '\r' or '#',
        // surrounding spaces/tabs trimmed, empty patterns ignored. The
        // length cap keeps the reference matcher cheap.
        line = line.substr(0, line.find_first_of("\r#"));
        line = line.substr(0, 40);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) line.remove_suffix(1);
        if (line.empty()) continue;
        body += allow ? "Allow: " : "Disallow: ";
        body += line;
        body += '\n';
        model.push_back({normalize(line), allow});

        // Targets that exercise this pattern: itself without wildcards or
        // anchor, and with a suffix.
        std::string t;
        for (const char c : line) {
            if (c != '*' && c != '$') t.push_back(c);
        }
        if (t.empty() || t[0] != '/') t.insert(t.begin(), '/');
        targets.push_back(t);
        targets.push_back(t + "x/y?z");
        if (model.size() >= 16) break;
    }

    const RobotsRules rules = RobotsRules::parse(body, "wincrawl");
    FUZZ_CHECK(rules.rule_count() == model.size());
    for (const std::string& t : targets) {
        FUZZ_CHECK(rules.allowed(t) == ref_allowed(model, t));
    }
    // The same rules under a specific group for our token replace "*".
    const RobotsRules specific = RobotsRules::parse("User-agent: other\nDisallow: /\n\nUser-agent: WinCrawl/2.0\n" +
                                                        body.substr(body.find('\n') + 1),
                                                    "wincrawl");
    FUZZ_CHECK(specific.rule_count() == model.size());
    for (const std::string& t : targets) {
        FUZZ_CHECK(specific.allowed(t) == ref_allowed(model, t));
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data + 1), size - 1);
    if (data[0] & 1) {
        check_model(rest);
    } else {
        check_raw(rest);
    }
    return 0;
}
