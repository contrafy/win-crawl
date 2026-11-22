#pragma once
// DNS wire codec (RFC 1035): query builder (with an EDNS0 OPT record) and a
// hardened response parser for A and HTTPS (RFC 9460) answers.
// Pure functions, no allocation; safe on arbitrary (hostile) input.

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace wc::dns {

inline constexpr uint16_t kTypeA = 1;
inline constexpr uint16_t kTypeCname = 5;
inline constexpr uint16_t kTypeOpt = 41;
inline constexpr uint16_t kTypeHttps = 65;
inline constexpr uint16_t kClassIn = 1;

inline constexpr size_t kHeaderSize = 12;
inline constexpr size_t kMaxNameText = 253;  // dotted text, no trailing dot
// EDNS0 (RFC 6891) UDP payload size advertised in queries. 1232 is the DNS
// Flag Day 2020 value: large enough for HTTPS RRsets carrying ECH configs,
// small enough to avoid IP fragmentation on common paths.
inline constexpr uint16_t kEdnsUdpSize = 1232;
inline constexpr size_t kOptRecordSize = 11;  // root owner, type, class, ttl, rdlen 0
inline constexpr size_t kMaxQuerySize = kHeaderSize + (kMaxNameText + 2) + 4 + kOptRecordSize;
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

// SvcParamKeys understood by the HTTPS RR parser (RFC 9460 section 14.3.2).
enum SvcParamKey : uint16_t {
    kSvcMandatory = 0,
    kSvcAlpn = 1,
    kSvcNoDefaultAlpn = 2,
    kSvcPort = 3,
    kSvcIpv4Hint = 4,
    kSvcEch = 5,
    kSvcIpv6Hint = 6,
};

// One decoded HTTPS RR. SvcParams are reduced to the facts a measurement
// needs; values other than port are not kept.
struct HttpsRr {
    uint16_t priority = 0;  // SvcPriority; 0 = AliasMode
    uint16_t port = 0;      // "port" SvcParam; 0 = absent
    // TargetName as dotted text without the trailing dot, case preserved;
    // "." for the root name (ServiceMode: the owner itself; AliasMode: the
    // service does not exist).
    char target[kMaxNameText + 1] = {};
    uint8_t target_len = 0;
    bool alpn_h3 = false;      // alpn list contains exactly "h3"
    bool alpn_h2 = false;      // ... "h2"
    bool alpn_http11 = false;  // ... "http/1.1"
    bool no_default_alpn = false;
    bool ech = false;  // "ech" SvcParam with a well-framed ECHConfigList
    bool ipv4hint = false;
    bool ipv6hint = false;

    bool alias_mode() const { return priority == 0; }
    std::string_view target_name() const { return {target, target_len}; }
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

    // qtype != HTTPS: A records (class IN) owned by the question name or by
    // the end of a CNAME chain starting at it, in answer-section order. Extra
    // records beyond kMaxAddresses are dropped.
    uint32_t addrs[kMaxAddresses] = {};  // network byte order
    uint8_t addr_count = 0;
    uint8_t cname_hops = 0;  // CNAMEs followed to reach the answer RRset

    // qtype == HTTPS: the HTTPS RRset at the same place. https_count counts
    // its well-formed records. Any malformed record sets https_malformed and,
    // per RFC 9460 section 2.2, makes the whole RRset unusable. `https` is the
    // selected record, valid when https_count != 0 && !https_malformed: the
    // first AliasMode record if any (ServiceMode records are then ignored,
    // section 2.4.2), otherwise the lowest SvcPriority, earliest on ties.
    HttpsRr https;
    uint8_t https_count = 0;
    bool https_malformed = false;

    std::string_view question() const { return {qname, qname_len}; }
};

// Builds a recursive (RD=1) query with one question of class IN and, unless
// `edns_udp_size` is 0, an EDNS0 OPT record advertising that payload size
// (version 0, DO bit clear). `name` may carry one trailing dot. Returns the
// packet size, or 0 when the name is invalid (empty label, label > 63,
// text > 253) or `cap` too small.
size_t build_query(uint16_t id, std::string_view name, uint16_t qtype, uint8_t* out, size_t cap,
                   uint16_t edns_udp_size = kEdnsUdpSize);

// Parses header, the single question and the answer section. Returns false on
// malformed framing (bad lengths, pointer loops, qdcount != 1, records running
// past the end unless TC is set, bad A/CNAME rdata). A malformed HTTPS RR is
// not a framing error: it sets https_malformed. Does not interpret rcode or
// the QR bit; callers validate those. Authority/additional sections are
// ignored.
bool parse_response(const uint8_t* data, size_t len, Response& out);

// Decodes HTTPS RR rdata (RFC 9460 section 2.2). Returns false when the RR
// is malformed: TargetName compressed or overrunning, SvcParam overrunning
// the rdata, keys not strictly increasing, a known key with a bad value, or
// self-inconsistency (mandatory key absent, no-default-alpn without alpn).
// AliasMode SvcParams are ignored unread, as the RFC requires; unknown keys
// are skipped.
bool parse_https_rdata(const uint8_t* rdata, size_t rdlen, HttpsRr& out);

// ASCII case-insensitive comparison of dotted names; a single trailing dot on
// either side is ignored.
bool name_equal(std::string_view a, std::string_view b);

}  // namespace wc::dns
