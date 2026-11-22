// dns::parse_https_rdata (RFC 9460 HTTPS RR rdata) on arbitrary bytes, and
// the same rdata inside full responses parsed by dns::parse_response.
//
// Invariants:
// - parsing into a fresh and into a dirty HttpsRr gives identical results;
// - on success the target is "." or dotted text <= 253 chars with no empty
//   label, NUL-terminated;
// - the prefix ending at the TargetName (no SvcParams) always parses, and for
//   AliasMode (priority 0) to the same record, since its params are ignored;
// - wrapped as the only answer (directly, and behind one CNAME), the response
//   parses, with https_count/https_malformed/https matching the bare rdata
//   parse and the right cname_hops;
// - with a second record (same rdata, fuzz-chosen priority), the selected
//   record follows RFC 9460 section 2.4: first AliasMode record, else lowest
//   SvcPriority, earliest on ties; one malformed record poisons the RRset.

#include "dns/packet.h"

#include "check.h"

#include <cstring>
#include <vector>

using namespace wc::dns;

namespace {

bool same(const HttpsRr& a, const HttpsRr& b) {
    return a.priority == b.priority && a.port == b.port && a.target_name() == b.target_name() &&
           a.alpn_h3 == b.alpn_h3 && a.alpn_h2 == b.alpn_h2 && a.alpn_http11 == b.alpn_http11 &&
           a.no_default_alpn == b.no_default_alpn && a.ech == b.ech && a.ipv4hint == b.ipv4hint &&
           a.ipv6hint == b.ipv6hint;
}

void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}

void put_name(std::vector<uint8_t>& v, const char* dotted) {
    for (const char* p = dotted; *p;) {
        const char* dot = std::strchr(p, '.');
        const size_t len = dot ? static_cast<size_t>(dot - p) : std::strlen(p);
        v.push_back(static_cast<uint8_t>(len));
        v.insert(v.end(), p, p + len);
        p += len + (dot ? 1 : 0);
    }
    v.push_back(0);
}

void put_rr(std::vector<uint8_t>& v, const std::vector<uint8_t>& owner, uint16_t type, const uint8_t* rdata,
            size_t rdlen) {
    v.insert(v.end(), owner.begin(), owner.end());
    put16(v, type);
    put16(v, kClassIn);
    put16(v, 0);
    put16(v, 300);
    put16(v, static_cast<uint16_t>(rdlen));
    v.insert(v.end(), rdata, rdata + rdlen);
}

std::vector<uint8_t> response(uint16_t ancount) {
    std::vector<uint8_t> v;
    put16(v, 0xBEEF);
    put16(v, 0x8180);
    put16(v, 1);
    put16(v, ancount);
    put16(v, 0);
    put16(v, 0);
    put_name(v, "svc.example");
    put16(v, kTypeHttps);
    put16(v, kClassIn);
    return v;
}

const std::vector<uint8_t> kQuestionPtr = {0xC0, 0x0C};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 0xFFFF) return 0;
    // Exact-size heap copy, so ASan catches reads past the rdata.
    const std::vector<uint8_t> rdata(data, data + size);

    HttpsRr rr;
    const bool ok = parse_https_rdata(rdata.data(), size, rr);
    HttpsRr dirty;
    std::memset(&dirty, 0x5A, sizeof(dirty));
    FUZZ_CHECK(parse_https_rdata(rdata.data(), size, dirty) == ok);

    if (ok) {
        FUZZ_CHECK(same(rr, dirty));
        const std::string_view t = rr.target_name();
        FUZZ_CHECK(rr.target_len >= 1 && rr.target_len <= kMaxNameText && rr.target[rr.target_len] == '\0');
        FUZZ_CHECK(t == "." || (t.front() != '.' && t.back() != '.' && t.find("..") == std::string_view::npos));

        const size_t name_end = 2 + (t == "." ? 1 : t.size() + 2);
        FUZZ_CHECK(name_end <= size);
        HttpsRr bare;
        FUZZ_CHECK(parse_https_rdata(rdata.data(), name_end, bare));
        FUZZ_CHECK(bare.priority == rr.priority && bare.target_name() == t);
        if (rr.alias_mode()) FUZZ_CHECK(same(bare, rr));
    }

    // The rdata as the only answer, owned by the question name.
    {
        std::vector<uint8_t> pkt = response(1);
        put_rr(pkt, kQuestionPtr, kTypeHttps, data, size);
        Response r;
        FUZZ_CHECK(parse_response(pkt.data(), pkt.size(), r));
        FUZZ_CHECK(r.qtype == kTypeHttps && r.cname_hops == 0 && r.addr_count == 0);
        FUZZ_CHECK(r.https_malformed == !ok);
        FUZZ_CHECK(r.https_count == (ok ? 1 : 0));
        if (ok) FUZZ_CHECK(same(r.https, rr));
    }

    // Behind a CNAME.
    {
        std::vector<uint8_t> pkt = response(2);
        std::vector<uint8_t> target;
        put_name(target, "edge.cdn.example");
        put_rr(pkt, kQuestionPtr, kTypeCname, target.data(), target.size());
        put_rr(pkt, target, kTypeHttps, data, size);
        Response r;
        FUZZ_CHECK(parse_response(pkt.data(), pkt.size(), r));
        FUZZ_CHECK(r.cname_hops == 1);
        FUZZ_CHECK(r.https_malformed == !ok && r.https_count == (ok ? 1 : 0));
        if (ok) FUZZ_CHECK(same(r.https, rr));
    }

    // Two records: this one, then a copy whose priority comes from its last bytes.
    if (size >= 2) {
        std::vector<uint8_t> second = rdata;
        second[0] = data[size - 1];
        second[1] = data[size - 2];
        HttpsRr rr2;
        const bool ok2 = parse_https_rdata(second.data(), second.size(), rr2);

        std::vector<uint8_t> pkt = response(2);
        put_rr(pkt, kQuestionPtr, kTypeHttps, data, size);
        put_rr(pkt, kQuestionPtr, kTypeHttps, second.data(), second.size());
        Response r;
        FUZZ_CHECK(parse_response(pkt.data(), pkt.size(), r));
        FUZZ_CHECK(r.https_malformed == (!ok || !ok2));
        FUZZ_CHECK(r.https_count == (ok ? 1 : 0) + (ok2 ? 1 : 0));
        if (ok && ok2) {
            const HttpsRr& expected = rr.alias_mode()    ? rr
                                      : rr2.alias_mode() ? rr2
                                      : rr2.priority < rr.priority ? rr2
                                                                   : rr;
            FUZZ_CHECK(same(r.https, expected));
        }
    }
    return 0;
}
