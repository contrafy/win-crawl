#include "benchsrv/behavior.h"

#include <winsock2.h>

#include <charconv>

namespace wc::benchsrv {

namespace {

// Independent decision streams per host.
constexpr uint64_t kSaltNx = 0x6E78646F6D61696EULL;
constexpr uint64_t kSaltShare = 0x7368617265697070ULL;
constexpr uint64_t kSaltDnsDelay = 0x646E7364656C6179ULL;
constexpr uint64_t kSaltRobots = 0x726F626F74733430ULL;
constexpr uint64_t kSaltStatus = 0x7374617475736373ULL;
constexpr uint64_t kSaltTemplate = 0x74656D706C617465ULL;
constexpr uint64_t kSaltChunked = 0x6368756E6B656421ULL;
constexpr uint64_t kSaltHttpDelay = 0x6874747064656C61ULL;

constexpr uint64_t kHostSpace = 0xFFFFFEu;  // 127.0.0.1 .. 127.255.255.254

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

// Strict dotted-quad parser; returns network byte order.
std::optional<uint32_t> parse_ipv4(std::string_view s) {
    uint32_t value = 0;
    size_t pos = 0;
    for (int part = 0; part < 4; ++part) {
        if (part > 0) {
            if (pos >= s.size() || s[pos] != '.') return std::nullopt;
            ++pos;
        }
        size_t start = pos;
        uint32_t octet = 0;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9' && pos - start < 3) {
            octet = octet * 10 + static_cast<uint32_t>(s[pos] - '0');
            ++pos;
        }
        if (pos == start || octet > 255) return std::nullopt;
        value = (value << 8) | octet;
    }
    if (pos != s.size()) return std::nullopt;
    return htonl(value);
}

uint64_t page_key(uint64_t n, std::string_view target) { return mix64(n) ^ fnv1a(target); }

}  // namespace

uint32_t Delay::pick(uint64_t hash) const {
    if (jitter_ms == 0) return mean_ms;
    const uint64_t span = 2ull * jitter_ms + 1;
    const int64_t v = static_cast<int64_t>(mean_ms) - jitter_ms + static_cast<int64_t>(hash % span);
    return v < 0 ? 0u : static_cast<uint32_t>(v);
}

bool parse_delay(std::string_view text, Delay& out) {
    Delay d;
    const size_t comma = text.find(',');
    std::string_view mean = text.substr(0, comma);
    auto r = std::from_chars(mean.data(), mean.data() + mean.size(), d.mean_ms);
    if (r.ec != std::errc() || r.ptr != mean.data() + mean.size()) return false;
    if (comma != std::string_view::npos) {
        std::string_view jitter = text.substr(comma + 1);
        r = std::from_chars(jitter.data(), jitter.data() + jitter.size(), d.jitter_ms);
        if (r.ec != std::errc() || r.ptr != jitter.data() + jitter.size()) return false;
    }
    out = d;
    return true;
}

uint64_t mix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

double unit(uint64_t seed, uint64_t n, uint64_t salt) {
    const uint64_t h = mix64(mix64(seed ^ salt) ^ n);
    return static_cast<double>(h >> 11) * 0x1.0p-53;
}

uint64_t fnv1a(std::string_view text) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (char c : text) {
        h ^= static_cast<unsigned char>(c);
        h *= 0x100000001B3ULL;
    }
    return h;
}

uint32_t host_unique_ip(uint64_t n) {
    const uint32_t offset = static_cast<uint32_t>(n % kHostSpace) + 1;
    return htonl(0x7F000000u | offset);
}

std::optional<uint64_t> ip_host_number(uint32_t ipv4_be) {
    const uint32_t h = ntohl(ipv4_be);
    if ((h >> 24) != 127) return std::nullopt;
    const uint32_t offset = h & 0xFFFFFFu;
    if (offset == 0 || offset == 0xFFFFFFu) return std::nullopt;
    return offset - 1;
}

std::optional<uint64_t> parse_host_name(std::string_view name, std::string_view zone) {
    if (!name.empty() && name.back() == '.') name.remove_suffix(1);
    if (name.size() < zone.size() + 3 || lower(name[0]) != 'h') return std::nullopt;
    const size_t dot = name.size() - zone.size() - 1;
    if (name[dot] != '.' || !iequals(name.substr(dot + 1), zone)) return std::nullopt;
    std::string_view digits = name.substr(1, dot - 1);
    if (digits.empty() || digits.size() > 18) return std::nullopt;
    uint64_t n = 0;
    for (char c : digits) {
        if (c < '0' || c > '9') return std::nullopt;
        n = n * 10 + static_cast<uint64_t>(c - '0');
    }
    return n;
}

std::optional<uint64_t> host_header_number(std::string_view host, std::string_view zone) {
    const size_t colon = host.rfind(':');
    if (colon != std::string_view::npos) {
        bool numeric = colon + 1 < host.size();
        for (size_t i = colon + 1; i < host.size(); ++i) numeric = numeric && host[i] >= '0' && host[i] <= '9';
        if (numeric) host = host.substr(0, colon);
    }
    if (host.empty()) return std::nullopt;
    if (auto n = parse_host_name(host, zone)) return n;
    if (auto ip = parse_ipv4(host)) {
        if (auto n = ip_host_number(*ip)) return n;
    }
    uint64_t h = 0xCBF29CE484222325ULL;
    for (char c : host) {
        h ^= static_cast<unsigned char>(lower(c));
        h *= 0x100000001B3ULL;
    }
    return h % kHostSpace;
}

bool host_nxdomain(const Behavior& b, uint64_t n) { return unit(b.seed, n, kSaltNx) < b.nxdomain; }

bool host_shares_ip(const Behavior& b, uint64_t n) {
    return n > 0 && unit(b.seed, n, kSaltShare) < b.ip_share;
}

uint32_t host_ip(const Behavior& b, uint64_t n) {
    if (!host_shares_ip(b, n)) return host_unique_ip(n);
    // Walk down to an earlier host that owns its address and actually resolves;
    // bounded so a pathological ip_share near 1 stays cheap.
    uint64_t owner = n - 1;
    for (int i = 0; i < 4096 && owner > 0 && (host_shares_ip(b, owner) || host_nxdomain(b, owner)); ++i) {
        --owner;
    }
    return host_unique_ip(owner);
}

uint32_t dns_delay_ms(const Behavior& b, uint64_t key) {
    return b.dns_delay.pick(mix64(mix64(b.seed ^ kSaltDnsDelay) ^ key));
}

bool robots_missing(const Behavior& b, uint64_t n) { return unit(b.seed, n, kSaltRobots) < b.robots_404; }

PagePlan page_plan(const Behavior& b, uint64_t n, std::string_view target) {
    PagePlan plan;
    const uint64_t key = page_key(n, target);
    plan.template_index = static_cast<uint32_t>(mix64(mix64(b.seed ^ kSaltTemplate) ^ key) % kPageTemplates);
    plan.chunked = unit(b.seed, key, kSaltChunked) < b.chunked;
    if (target.size() >= 3 && target.substr(0, 3) == "/r/") return plan;
    const double u = unit(b.seed, key, kSaltStatus);
    if (u < b.redirect) {
        plan.kind = PageKind::Redirect;
    } else if (u < b.redirect + b.not_found) {
        plan.kind = PageKind::NotFound;
    } else if (u < b.redirect + b.not_found + b.server_error) {
        plan.kind = PageKind::ServerError;
    }
    return plan;
}

uint32_t http_delay_ms(const Behavior& b, uint64_t n, std::string_view target) {
    return b.http_delay.pick(mix64(mix64(b.seed ^ kSaltHttpDelay) ^ page_key(n, target)));
}

}  // namespace wc::benchsrv
