#include "crawl/ipranges.h"

#include "parse/url.h"

#include <algorithm>
#include <charconv>
#include <iterator>

namespace wc::crawl {

// Defined in the generated cloudflare_data.cpp (src/crawl/CMakeLists.txt).
extern const std::string_view kCloudflareIpv4Text;

namespace {

uint32_t to_host_order(uint32_t be) {
    return (be & 0xFFu) << 24 | (be & 0xFF00u) << 8 | (be >> 8 & 0xFF00u) | be >> 24;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.remove_suffix(1);
    }
    return s;
}

}  // namespace

bool Ipv4Ranges::parse(std::string_view text, std::string& error) {
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    size_t line_no = 0;
    while (!text.empty()) {
        ++line_no;
        const size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
        const size_t hash = line.find('#');
        line = trim(line.substr(0, hash));
        if (line.empty()) {
            continue;
        }
        const size_t slash = line.find('/');
        uint32_t ip_be = 0;
        unsigned len = 0;
        const std::string_view len_text = slash == std::string_view::npos ? std::string_view{} : line.substr(slash + 1);
        const auto r = std::from_chars(len_text.data(), len_text.data() + len_text.size(), len);
        if (slash == std::string_view::npos || !parse::parse_ipv4_literal(line.substr(0, slash), ip_be) ||
            r.ec != std::errc() || r.ptr != len_text.data() + len_text.size() || len > 32) {
            error = "line " + std::to_string(line_no) + ": expected a.b.c.d/len";
            return false;
        }
        const uint32_t mask = len == 0 ? 0 : ~uint32_t{0} << (32 - len);
        const uint32_t first = to_host_order(ip_be) & mask;
        ranges.emplace_back(first, first | ~mask);
    }
    std::sort(ranges.begin(), ranges.end());
    ranges_.clear();
    for (const auto& r : ranges) {
        if (!ranges_.empty() && r.first <= ranges_.back().second + uint64_t{1}) {
            ranges_.back().second = std::max(ranges_.back().second, r.second);
        } else {
            ranges_.push_back(r);
        }
    }
    return true;
}

bool Ipv4Ranges::contains(uint32_t ipv4_be) const {
    const uint32_t ip = to_host_order(ipv4_be);
    // First range starting after ip; the one before it is the only candidate.
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), ip,
                               [](uint32_t v, const std::pair<uint32_t, uint32_t>& r) { return v < r.first; });
    return it != ranges_.begin() && ip <= std::prev(it)->second;
}

const Ipv4Ranges& cloudflare_ipv4() {
    static const Ipv4Ranges ranges = [] {
        Ipv4Ranges r;
        std::string error;
        r.parse(kCloudflareIpv4Text, error);  // checked by the tests; a bad file yields an empty set
        return r;
    }();
    return ranges;
}

}  // namespace wc::crawl
