#pragma once
// Absolute http/https URLs as the crawler needs them: lowercase host, numeric
// port, and an origin-form request target ("/path?query", fragment dropped).

#include <cstdint>
#include <string>
#include <string_view>

namespace wc::parse {

enum class Scheme : uint8_t { Http, Https };

struct Url {
    Scheme scheme = Scheme::Http;
    std::string host;      // lowercase, [a-z0-9.-_], 1..253 chars
    uint16_t port = 80;    // always set; the scheme default when the URL omits it
    std::string target = "/";  // path [+ '?' query], always starts with '/'
};

constexpr uint16_t default_port(Scheme scheme) {
    return scheme == Scheme::Https ? 443 : 80;
}

// Parses an absolute http(s) URL. Surrounding whitespace is trimmed and
// embedded tab/CR/LF removed (as browsers do). Dot segments are removed, and
// bytes that cannot appear on an HTTP request line (controls, space, DEL,
// non-ASCII) are percent-encoded so `target` can be sent verbatim. An empty
// port ("http://h:/") means the default port. Rejects other schemes,
// userinfo, IPv6 literals, bad ports, and hosts outside [a-z0-9.-_].
// `out` is assigned in place, so a reused Url does not reallocate.
bool parse_url(std::string_view text, Url& out);

// RFC 3986 §5.2 reference resolution of `ref` against `base`. Only http(s)
// results are produced: other schemes (mailto:, javascript:, data:, ...)
// fail. Like browsers (and RFC 3986 §5.4.2's backward-compatible reading),
// "http:g" against an http base is treated as the relative reference "g".
// `out` may alias `base`.
bool resolve_url(const Url& base, std::string_view ref, Url& out);

// "scheme://host[:port]/target"; the port is omitted when it is the default.
std::string to_string(const Url& url);
void append_to_string(std::string& out, const Url& url);

// Strict dotted quad "a.b.c.d" (each part 0..255, 1-3 digits, no leading
// zeros). The result is in network byte order (in_addr::s_addr).
bool parse_ipv4_literal(std::string_view host, uint32_t& ipv4_be);

// Value for the Host request header: host, plus ":port" when non-default.
std::string host_header(const Url& url);
void append_host_header(std::string& out, const Url& url);

}  // namespace wc::parse
