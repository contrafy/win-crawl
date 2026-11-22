// dns::parse_response on arbitrary datagrams, plus a build_query round trip
// with the input as the query name.
//
// Invariants:
// - parsing into a fresh and into a dirty Response gives identical results
//   (every output field is reset);
// - on success the question is NUL-terminated dotted text <= 253 chars with
//   no empty label, with at most kMaxAddresses addresses and kMaxCnameChain
//   CNAME hops; addresses only for non-HTTPS questions, an HTTPS RRset only
//   for HTTPS ones;
// - any name build_query accepts parses back from the query it built, with
//   the same id, qtype, class IN, RD set and no answers; a buffer too small
//   for the query is refused, never overrun; without EDNS the query is the
//   same bytes minus the OPT record.

#include "dns/packet.h"

#include "check.h"

#include <cstring>

using namespace wc::dns;

namespace {

bool same(const HttpsRr& a, const HttpsRr& b) {
    return a.priority == b.priority && a.port == b.port && a.target_name() == b.target_name() &&
           a.alpn_h3 == b.alpn_h3 && a.alpn_h2 == b.alpn_h2 && a.alpn_http11 == b.alpn_http11 &&
           a.no_default_alpn == b.no_default_alpn && a.ech == b.ech && a.ipv4hint == b.ipv4hint &&
           a.ipv6hint == b.ipv6hint;
}

bool same(const Response& a, const Response& b) {
    return a.id == b.id && a.rcode == b.rcode && a.qr == b.qr && a.tc == b.tc && a.rd == b.rd && a.ra == b.ra &&
           a.qtype == b.qtype && a.qclass == b.qclass && a.question() == b.question() &&
           a.addr_count == b.addr_count && a.cname_hops == b.cname_hops &&
           std::memcmp(a.addrs, b.addrs, sizeof(uint32_t) * a.addr_count) == 0 &&
           a.https_count == b.https_count && a.https_malformed == b.https_malformed &&
           (a.https_count == 0 || same(a.https, b.https));
}

void check_parse(const uint8_t* data, size_t len) {
    Response fresh;
    const bool ok = parse_response(data, len, fresh);

    Response dirty;
    std::memset(&dirty, 0xA5, sizeof(dirty));
    FUZZ_CHECK(parse_response(data, len, dirty) == ok);
    if (!ok) return;
    FUZZ_CHECK(same(fresh, dirty));

    FUZZ_CHECK(fresh.qname_len <= kMaxNameText);
    FUZZ_CHECK(fresh.qname[fresh.qname_len] == '\0');
    FUZZ_CHECK(fresh.addr_count <= kMaxAddresses);
    FUZZ_CHECK(fresh.cname_hops <= kMaxCnameChain);
    if (fresh.qtype == kTypeHttps) {
        FUZZ_CHECK(fresh.addr_count == 0);
    } else {
        FUZZ_CHECK(fresh.https_count == 0 && !fresh.https_malformed);
    }
    if (fresh.https_count != 0) {
        FUZZ_CHECK(fresh.https.target_len >= 1 && fresh.https.target[fresh.https.target_len] == '\0');
    }
    const std::string_view q = fresh.question();
    FUZZ_CHECK(q.empty() || (q.front() != '.' && q.back() != '.' && q.find("..") == std::string_view::npos));
    FUZZ_CHECK(name_equal(q, q));
}

void check_query_round_trip(const uint8_t* data, size_t len) {
    if (len < 3) return;
    const uint16_t id = static_cast<uint16_t>(data[0] << 8 | data[1]);
    const uint16_t qtype = data[2];
    const std::string_view name(reinterpret_cast<const char*>(data + 3), len - 3);

    uint8_t packet[kMaxQuerySize];
    // A short buffer must be refused, never overrun (ASan guards `small`).
    uint8_t small[kHeaderSize + 4];
    const size_t n = build_query(id, name, qtype, packet, sizeof(packet));
    const size_t n_small = build_query(id, name, qtype, small, sizeof(small));
    FUZZ_CHECK(n_small == 0 || n_small == n);
    if (n == 0) return;
    FUZZ_CHECK(n <= kMaxQuerySize);

    Response r;
    FUZZ_CHECK(parse_response(packet, n, r));
    FUZZ_CHECK(r.id == id && r.qtype == qtype && r.qclass == kClassIn && r.rd && !r.qr && !r.tc);
    FUZZ_CHECK(r.addr_count == 0 && r.cname_hops == 0 && r.https_count == 0);
    FUZZ_CHECK(name_equal(r.question(), name));

    // Without EDNS the query is the same minus the OPT record.
    uint8_t plain[kMaxQuerySize];
    const size_t n_plain = build_query(id, name, qtype, plain, sizeof(plain), 0);
    FUZZ_CHECK(n_plain + kOptRecordSize == n);
    FUZZ_CHECK(std::memcmp(plain + 2, packet + 2, 8) == 0 && std::memcmp(plain + 12, packet + 12, n_plain - 12) == 0);
    FUZZ_CHECK(parse_response(plain, n_plain, r) && name_equal(r.question(), name));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    check_parse(data, size);
    check_query_round_trip(data, size);
    return 0;
}
