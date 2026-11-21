#include "parse/url.h"

#include <charconv>
#include <cstring>

namespace wc::parse {
namespace {

constexpr bool is_alpha(char c) {
    const char l = static_cast<char>(c | 0x20);
    return l >= 'a' && l <= 'z';
}
constexpr bool is_digit(char c) { return c >= '0' && c <= '9'; }
constexpr char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

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

// WHATWG URL parsing strips leading/trailing C0 controls and spaces.
std::string_view trim(std::string_view s) {
    while (!s.empty() && static_cast<unsigned char>(s.front()) <= 0x20) {
        s.remove_prefix(1);
    }
    while (!s.empty() && static_cast<unsigned char>(s.back()) <= 0x20) {
        s.remove_suffix(1);
    }
    return s;
}

constexpr bool is_tab_or_newline(char c) { return c == '\t' || c == '\n' || c == '\r'; }

// Bytes that may not appear raw in an HTTP request-target.
constexpr bool needs_escape(char c) {
    const auto u = static_cast<unsigned char>(c);
    return u <= 0x20 || u >= 0x7F;
}

void append_escaped(std::string& dst, std::string_view src) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    size_t start = 0;
    for (size_t i = 0; i < src.size(); ++i) {
        if (needs_escape(src[i])) {
            dst.append(src.data() + start, i - start);
            const auto u = static_cast<unsigned char>(src[i]);
            const char esc[3] = {'%', kHex[u >> 4], kHex[u & 15]};
            dst.append(esc, 3);
            start = i + 1;
        }
    }
    dst.append(src.data() + start, src.size() - start);
}

// RFC 3986 §5.2.4 on an absolute path, in place. Output never outgrows the
// input, so the write cursor trails the read cursor.
size_t remove_dot_segments(char* p, size_t n) {
    size_t r = 0;
    size_t w = 0;
    while (r < n) {
        // p[r] == '/' here: every segment is preceded by one.
        const size_t seg = r + 1;
        size_t next = seg;
        while (next < n && p[next] != '/') {
            ++next;
        }
        const size_t len = next - seg;
        const bool last = next >= n;
        if (len == 1 && p[seg] == '.') {
            if (last) {
                p[w++] = '/';
            }
        } else if (len == 2 && p[seg] == '.' && p[seg + 1] == '.') {
            while (w > 0 && p[w - 1] != '/') {
                --w;
            }
            if (w > 0) {
                --w;
            }
            if (last) {
                p[w++] = '/';
            }
        } else {
            std::memmove(p + w, p + r, next - r);
            w += next - r;
        }
        r = next;
    }
    if (w == 0) {
        p[w++] = '/';
    }
    return w;
}

// Appends `path` (absolute, or empty meaning "/") to `target` and removes dot
// segments from everything from `path_begin` on.
void append_path(std::string& target, size_t path_begin, std::string_view path) {
    append_escaped(target, path);
    if (target.size() == path_begin) {
        target.push_back('/');
        return;
    }
    const size_t n = remove_dot_segments(target.data() + path_begin, target.size() - path_begin);
    target.resize(path_begin + n);
}

struct Ref {
    bool has_scheme = false;
    Scheme scheme = Scheme::Http;
    bool has_authority = false;
    std::string_view authority;
    std::string_view path;
    bool has_query = false;
    std::string_view query;
};

// RFC 3986 Appendix B split. Fails only on a non-http(s) scheme.
bool split_ref(std::string_view s, Ref& r) {
    if (!s.empty() && is_alpha(s[0])) {
        size_t i = 1;
        while (i < s.size() && (is_alpha(s[i]) || is_digit(s[i]) || s[i] == '+' || s[i] == '-' || s[i] == '.')) {
            ++i;
        }
        if (i < s.size() && s[i] == ':') {
            const std::string_view name = s.substr(0, i);
            if (iequals(name, "http")) {
                r.scheme = Scheme::Http;
            } else if (iequals(name, "https")) {
                r.scheme = Scheme::Https;
            } else {
                return false;
            }
            r.has_scheme = true;
            s.remove_prefix(i + 1);
        }
    }
    if (s.size() >= 2 && s[0] == '/' && s[1] == '/') {
        s.remove_prefix(2);
        const size_t end = s.find_first_of("/?#");
        r.has_authority = true;
        r.authority = s.substr(0, end);
        s.remove_prefix(end == std::string_view::npos ? s.size() : end);
    }
    const size_t q = s.find_first_of("?#");
    r.path = s.substr(0, q);
    if (q != std::string_view::npos && s[q] == '?') {
        s.remove_prefix(q + 1);
        r.has_query = true;
        r.query = s.substr(0, s.find('#'));
    }
    return true;
}

bool parse_authority(std::string_view a, Scheme scheme, Url& out) {
    if (a.empty() || a.front() == '[' || a.find('@') != std::string_view::npos) {
        return false;
    }
    const size_t colon = a.find(':');
    const std::string_view host = a.substr(0, colon);
    uint32_t port = default_port(scheme);
    if (colon != std::string_view::npos && colon + 1 < a.size()) {
        port = 0;
        for (const char c : a.substr(colon + 1)) {
            if (!is_digit(c)) {
                return false;
            }
            port = port * 10 + static_cast<uint32_t>(c - '0');
            if (port > 65535) {
                return false;
            }
        }
        if (port == 0) {
            return false;
        }
    }
    if (host.empty() || host.size() > 253) {
        return false;
    }
    for (const char c : host) {
        const char l = to_lower(c);
        if (!((l >= 'a' && l <= 'z') || is_digit(l) || l == '.' || l == '-' || l == '_')) {
            return false;
        }
    }
    out.host.assign(host);
    for (char& c : out.host) {
        c = to_lower(c);
    }
    out.scheme = scheme;
    out.port = static_cast<uint16_t>(port);
    return true;
}

void append_query(std::string& target, const Ref& r) {
    if (r.has_query) {
        target.push_back('?');
        append_escaped(target, r.query);
    }
}

bool resolve_impl(const Url* base, std::string_view text, Url& out) {
    text = trim(text);
    std::string cleaned;
    for (const char c : text) {
        if (is_tab_or_newline(c)) {
            cleaned.reserve(text.size());
            for (const char k : text) {
                if (!is_tab_or_newline(k)) {
                    cleaned.push_back(k);
                }
            }
            text = cleaned;
            break;
        }
    }

    Ref r;
    if (!split_ref(text, r)) {
        return false;
    }
    if (r.has_scheme && !r.has_authority) {
        // "http:g": same-scheme references without authority are relative.
        if (base == nullptr || r.scheme != base->scheme) {
            return false;
        }
        r.has_scheme = false;
    }

    if (r.has_authority) {
        if (!r.has_scheme && base == nullptr) {
            return false;
        }
        if (!parse_authority(r.authority, r.has_scheme ? r.scheme : base->scheme, out)) {
            return false;
        }
        out.target.clear();
        append_path(out.target, 0, r.path);
        append_query(out.target, r);
        return true;
    }
    if (base == nullptr) {
        return false;
    }

    out.scheme = base->scheme;
    out.host.assign(base->host);
    out.port = base->port;
    const std::string_view base_target = base->target;
    if (r.path.empty()) {
        if (!r.has_query) {
            out.target.assign(base_target);
            return true;
        }
        out.target.assign(base_target.substr(0, base_target.find('?')));
    } else if (r.path.front() == '/') {
        out.target.clear();
        append_path(out.target, 0, r.path);
    } else {
        // Merge (§5.2.3): base path up to and including its last '/'.
        const std::string_view base_path = base_target.substr(0, base_target.find('?'));
        const size_t slash = base_path.rfind('/');
        out.target.assign(base_path.substr(0, slash == std::string_view::npos ? 0 : slash + 1));
        if (out.target.empty()) {
            out.target.push_back('/');
        }
        append_path(out.target, 0, r.path);
    }
    append_query(out.target, r);
    return true;
}

}  // namespace

bool parse_url(std::string_view text, Url& out) {
    return resolve_impl(nullptr, text, out);
}

bool resolve_url(const Url& base, std::string_view ref, Url& out) {
    if (&out == &base) {
        const Url copy = base;
        return resolve_impl(&copy, ref, out);
    }
    return resolve_impl(&base, ref, out);
}

void append_host_header(std::string& out, const Url& url) {
    out.append(url.host);
    if (url.port != default_port(url.scheme)) {
        char buf[8];
        buf[0] = ':';
        const auto res = std::to_chars(buf + 1, buf + sizeof(buf), url.port);
        out.append(buf, res.ptr);
    }
}

void append_to_string(std::string& out, const Url& url) {
    out.append(url.scheme == Scheme::Https ? "https://" : "http://");
    append_host_header(out, url);
    out.append(url.target);
}

std::string to_string(const Url& url) {
    std::string s;
    s.reserve(url.host.size() + url.target.size() + 14);
    append_to_string(s, url);
    return s;
}

bool parse_ipv4_literal(std::string_view host, uint32_t& ipv4_be) {
    unsigned char bytes[4];
    size_t i = 0;
    for (int part = 0; part < 4; ++part) {
        if (part > 0) {
            if (i >= host.size() || host[i] != '.') {
                return false;
            }
            ++i;
        }
        const size_t start = i;
        unsigned value = 0;
        while (i < host.size() && is_digit(host[i]) && i - start < 3) {
            value = value * 10 + static_cast<unsigned>(host[i] - '0');
            ++i;
        }
        const size_t digits = i - start;
        if (digits == 0 || value > 255 || (digits > 1 && host[start] == '0')) {
            return false;
        }
        bytes[part] = static_cast<unsigned char>(value);
    }
    if (i != host.size()) {
        return false;
    }
    std::memcpy(&ipv4_be, bytes, 4);
    return true;
}

std::string host_header(const Url& url) {
    std::string s;
    append_host_header(s, url);
    return s;
}

}  // namespace wc::parse
