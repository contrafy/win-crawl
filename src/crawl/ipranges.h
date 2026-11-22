#pragma once
// IPv4 CIDR range sets, and the Cloudflare ranges compiled in from
// data/cloudflare-ips-v4.txt (for the --record "cf_ip" field).

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace wc::crawl {

class Ipv4Ranges {
public:
    // One "a.b.c.d/len" per line; blank lines and '#' comments are skipped.
    // False with a message naming the line on malformed input.
    bool parse(std::string_view text, std::string& error);
    bool contains(uint32_t ipv4_be) const;
    size_t size() const { return ranges_.size(); }

private:
    std::vector<std::pair<uint32_t, uint32_t>> ranges_;  // [first, last] host order, sorted, merged
};

// Cloudflare's published IPv4 ranges as of the data file's fetch date.
const Ipv4Ranges& cloudflare_ipv4();

}  // namespace wc::crawl
