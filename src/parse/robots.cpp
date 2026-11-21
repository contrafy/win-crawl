#include "parse/robots.h"

#include <charconv>
#include <cmath>
#include <initializer_list>
#include <vector>

namespace wc::parse {
namespace {

constexpr char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }
constexpr bool is_ws(char c) { return c == ' ' || c == '\t'; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (to_lower(a[i]) != to_lower(b[i])) {
            return false;
        }
    }
    return true;
}

bool iequals_any(std::string_view key, std::initializer_list<std::string_view> names) {
    for (const std::string_view n : names) {
        if (iequals(key, n)) {
            return true;
        }
    }
    return false;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && is_ws(s.front())) {
        s.remove_prefix(1);
    }
    while (!s.empty() && is_ws(s.back())) {
        s.remove_suffix(1);
    }
    return s;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    const char l = to_lower(c);
    return (l >= 'a' && l <= 'f') ? l - 'a' + 10 : -1;
}

constexpr bool is_unreserved(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_' || c == '~';
}

// RFC 9309 §2.2.2: compare with percent-encoding normalized. Encoded
// unreserved octets are decoded, other escapes get uppercase hex, and raw
// octets that need encoding (controls, space, non-ASCII) are encoded.
void normalize(std::string_view in, std::string& out) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c == '%' && i + 2 < in.size() && hex_value(in[i + 1]) >= 0 && hex_value(in[i + 2]) >= 0) {
            const auto v = static_cast<unsigned char>(hex_value(in[i + 1]) * 16 + hex_value(in[i + 2]));
            if (is_unreserved(v)) {
                out.push_back(static_cast<char>(v));
            } else {
                out.push_back('%');
                out.push_back(kHex[v >> 4]);
                out.push_back(kHex[v & 15]);
            }
            i += 2;
        } else if (c <= 0x20 || c >= 0x7F) {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
}

// Does `pattern` ('*' = any run, trailing '$' = end anchor) match a prefix of
// `path`? Tracks the set of reachable path positions, so no backtracking.
bool matches(std::string_view path, std::string_view pattern, std::vector<size_t>& pos) {
    const size_t n = path.size();
    pos.assign(1, 0);
    for (size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if (c == '$' && i + 1 == pattern.size()) {
            return pos.back() == n;
        }
        if (c == '*') {
            const size_t first = pos.front();
            pos.resize(n - first + 1);
            for (size_t j = 0; j < pos.size(); ++j) {
                pos[j] = first + j;
            }
            continue;
        }
        size_t kept = 0;
        for (const size_t p : pos) {
            if (p < n && path[p] == c) {
                pos[kept++] = p + 1;
            }
        }
        if (kept == 0) {
            return false;
        }
        pos.resize(kept);
    }
    return true;
}

}  // namespace

RobotsRules RobotsRules::parse(std::string_view body, std::string_view product_token) {
    if (body.substr(0, 3) == "\xEF\xBB\xBF") {
        body.remove_prefix(3);
    }

    RobotsRules specific;
    RobotsRules star;
    bool any_specific = false;
    bool in_agents = false;  // previous record was a user-agent line
    bool cur_specific = false;
    bool cur_star = false;
    std::string norm;

    while (!body.empty()) {
        size_t eol = 0;
        while (eol < body.size() && body[eol] != '\n' && body[eol] != '\r') {
            ++eol;
        }
        std::string_view line = body.substr(0, eol);
        body.remove_prefix(eol);
        if (!body.empty() && body[0] == '\r') {
            body.remove_prefix(1);
        }
        if (!body.empty() && body[0] == '\n') {
            body.remove_prefix(1);
        }

        line = line.substr(0, line.find('#'));
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos) {
            continue;
        }
        const std::string_view key = trim(line.substr(0, colon));
        const std::string_view value = trim(line.substr(colon + 1));

        if (iequals_any(key, {"user-agent", "useragent", "user agent"})) {
            if (!in_agents) {
                cur_specific = false;
                cur_star = false;
            }
            in_agents = true;
            if (!value.empty() && value[0] == '*' && (value.size() == 1 || is_ws(value[1]))) {
                cur_star = true;
                continue;
            }
            // The product token is the leading run of [A-Za-z_-]; anything
            // after (version, comments) is ignored.
            size_t n = 0;
            while (n < value.size() &&
                   ((to_lower(value[n]) >= 'a' && to_lower(value[n]) <= 'z') || value[n] == '_' || value[n] == '-')) {
                ++n;
            }
            if (n != 0 && iequals(value.substr(0, n), product_token)) {
                cur_specific = true;
                any_specific = true;
            }
            continue;
        }

        const bool is_allow = iequals(key, "allow");
        const bool is_disallow =
            !is_allow && iequals_any(key, {"disallow", "dissallow", "dissalow", "disalow", "diasllow", "disallaw"});
        const bool is_delay = !is_allow && !is_disallow && iequals_any(key, {"crawl-delay", "crawldelay", "crawl delay"});
        if (!is_allow && !is_disallow && !is_delay) {
            continue;  // sitemap, host, unknown: not group members
        }
        in_agents = false;
        if (!cur_specific && !cur_star) {
            continue;
        }
        if (is_delay) {
            double d = 0;
            const auto res = std::from_chars(value.data(), value.data() + value.size(), d);
            if (res.ec != std::errc{} || !std::isfinite(d) || d < 0) {
                continue;
            }
            if (cur_specific && !specific.crawl_delay_) {
                specific.crawl_delay_ = d;
            }
            if (cur_star && !star.crawl_delay_) {
                star.crawl_delay_ = d;
            }
            continue;
        }
        // An empty pattern matches nothing (RFC 9309 §2.2.2).
        if (value.empty()) {
            continue;
        }
        normalize(value, norm);
        if (cur_specific) {
            specific.rules_.push_back(Rule{norm, is_allow});
        }
        if (cur_star) {
            star.rules_.push_back(Rule{norm, is_allow});
        }
    }
    return any_specific ? std::move(specific) : std::move(star);
}

bool RobotsRules::allowed(std::string_view target) const {
    const std::string_view path = target.substr(0, target.find('?'));
    if (path == "/robots.txt" || rules_.empty()) {
        return true;
    }
    std::string norm;
    normalize(target, norm);
    std::vector<size_t> pos;
    pos.reserve(norm.size() + 1);
    size_t best_allow = 0;
    size_t best_disallow = 0;
    bool any_allow = false;
    bool any_disallow = false;
    for (const Rule& r : rules_) {
        if (!matches(norm, r.pattern, pos)) {
            continue;
        }
        const size_t len = r.pattern.size();
        if (r.allow) {
            if (!any_allow || len > best_allow) {
                best_allow = len;
            }
            any_allow = true;
        } else {
            if (!any_disallow || len > best_disallow) {
                best_disallow = len;
            }
            any_disallow = true;
        }
    }
    return !any_disallow || (any_allow && best_allow >= best_disallow);
}

}  // namespace wc::parse
