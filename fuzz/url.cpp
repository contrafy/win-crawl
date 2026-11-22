// parse_url / resolve_url / to_string round trips.
//
// Input: "<base>\n<ref>" (no newline: the whole input is both). The base is
// parsed with parse_url; the ref is parsed absolutely and resolved against
// the base (or against a fixed base when the input base does not parse).
//
// Invariants, for every Url produced:
// - well formed: host 1..253 chars of [a-z0-9._-], port != 0, target starts
//   with '/' and holds no byte that cannot go on a request line, no '#';
// - to_string(u) reparses to the same Url (scheme, host, port, target), and
//   so does it as a reference resolved against any base;
// - append_to_string/append_host_header agree with to_string/host_header;
// - resolving the empty reference returns the base itself, and resolving
//   into the base object itself (aliasing) equals resolving into a fresh one.

#include "parse/url.h"

#include "check.h"

#include <string>
#include <string_view>

using namespace wc::parse;

namespace {

bool same(const Url& a, const Url& b) {
    return a.scheme == b.scheme && a.host == b.host && a.port == b.port && a.target == b.target;
}

void check_well_formed(const Url& u) {
    FUZZ_CHECK(!u.host.empty() && u.host.size() <= 253);
    for (const char c : u.host) {
        FUZZ_CHECK((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_');
    }
    FUZZ_CHECK(u.port != 0);
    FUZZ_CHECK(!u.target.empty() && u.target.front() == '/');
    for (const char c : u.target) {
        const auto b = static_cast<unsigned char>(c);
        FUZZ_CHECK(b > 0x20 && b < 0x7F && c != '#');
    }
}

void check_round_trip(const Url& u, const Url& other_base) {
    check_well_formed(u);
    const std::string s = to_string(u);
    std::string appended = "x";
    append_to_string(appended, u);
    FUZZ_CHECK(appended.substr(1) == s);
    std::string host = "y";
    append_host_header(host, u);
    FUZZ_CHECK(host.substr(1) == host_header(u));

    Url again;
    FUZZ_CHECK(parse_url(s, again));
    FUZZ_CHECK(same(again, u));
    Url resolved;
    FUZZ_CHECK(resolve_url(other_base, s, resolved));
    FUZZ_CHECK(same(resolved, u));
    Url self;
    FUZZ_CHECK(resolve_url(u, "", self));
    FUZZ_CHECK(same(self, u));

    uint32_t ip = 0;
    if (parse_ipv4_literal(u.host, ip)) {
        const auto* b = reinterpret_cast<const uint8_t*>(&ip);
        const std::string dotted = std::to_string(b[0]) + '.' + std::to_string(b[1]) + '.' + std::to_string(b[2]) +
                                   '.' + std::to_string(b[3]);
        FUZZ_CHECK(dotted == u.host);
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    const size_t nl = input.find('\n');
    const std::string_view base_text = nl == std::string_view::npos ? input : input.substr(0, nl);
    const std::string_view ref = nl == std::string_view::npos ? input : input.substr(nl + 1);

    Url fixed;
    FUZZ_CHECK(parse_url("https://fixed.example:8443/a/b/c?q", fixed));

    Url base;
    const bool base_ok = parse_url(base_text, base);
    if (base_ok) check_round_trip(base, fixed);
    const Url& b = base_ok ? base : fixed;

    Url abs;
    if (parse_url(ref, abs)) {
        check_round_trip(abs, b);
        // An absolute URL resolves to itself against any base.
        Url r;
        FUZZ_CHECK(resolve_url(b, ref, r) && same(r, abs));
    }

    Url out;
    const bool ok = resolve_url(b, ref, out);
    if (ok) check_round_trip(out, fixed);

    // Aliasing: resolving into the base object itself.
    Url alias = b;
    FUZZ_CHECK(resolve_url(alias, ref, alias) == ok);
    if (ok) FUZZ_CHECK(same(alias, out));
    return 0;
}
