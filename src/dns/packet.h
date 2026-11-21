#pragma once
// DNS wire codec (RFC 1035): A-query builder and a hardened response parser.
// Pure functions, no allocation; safe on arbitrary (hostile) input.

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace wc::dns {

inline constexpr uint16_t kTypeA = 1;
inline constexpr uint16_t kTypeCname = 5;
inline constexpr uint16_t kClassIn = 1;

inline constexpr size_t kHeaderSize = 12;
inline constexpr size_t kMaxNameText = 253;  // dotted text, no trailing dot
inline constexpr size_t kMaxQuerySize = kHeaderSize + (kMaxNameText + 2) + 4;
inline constexpr unsigned kMaxCnameChain = 8;
inline constexpr size_t kMaxAddresses = 16;

enum Rcode : uint8_t {
    kNoError = 0,
    kFormErr = 1,
    kServFail = 2,
    kNxDomain = 3,
    kNotImp = 4,
    kRefused = 5,
};

struct Response {
    uint16_t id = 0;
    uint8_t rcode = 0;  // low 4 header bits (no EDNS extended rcode)
    bool qr = false;
    bool tc = false;
    bool rd = false;
    bool ra = false;

    uint16_t qtype = 0;
    uint16_t qclass = 0;
    char qname[kMaxNameText + 1] = {};  // decoded dotted text, case preserved
    uint8_t qname_len = 0;

    // A records (class IN) owned by the question name or by the end of a
    // CNAME chain starting at it, in answer-section order. Extra records
    // beyond kMaxAddresses are dropped.
    uint32_t addrs[kMaxAddresses] = {};  // network byte order
    uint8_t addr_count = 0;
    uint8_t cname_hops = 0;              // CNAMEs followed to reach addrs

    std::string_view question() const { return {qname, qname_len}; }
};

// Builds a recursive (RD=1) query with one question of class IN.
// `name` may carry one trailing dot. Returns the packet size, or 0 when the
// name is invalid (empty label, label > 63, text > 253) or `cap` too small.
size_t build_query(uint16_t id, std::string_view name, uint16_t qtype, uint8_t* out, size_t cap);

// Parses header, the single question and the answer section. Returns false on
// malformed input (bad lengths, pointer loops, qdcount != 1, records running
// past the end unless TC is set). Does not interpret rcode or the QR bit;
// callers validate those. Authority/additional sections are ignored.
bool parse_response(const uint8_t* data, size_t len, Response& out);

// ASCII case-insensitive comparison of dotted names; a single trailing dot on
// either side is ignored.
bool name_equal(std::string_view a, std::string_view b);

}  // namespace wc::dns
