#include "dns/packet.h"

#include "doctest/doctest.h"

#include <cstring>
#include <initializer_list>
#include <random>
#include <string>
#include <string_view>
#include <vector>

using namespace wc::dns;

namespace {

// Hand-assembles DNS packets byte by byte.
struct Pkt {
    std::vector<uint8_t> b;

    Pkt& u8(uint8_t v) {
        b.push_back(v);
        return *this;
    }
    Pkt& u16(uint16_t v) { return u8(static_cast<uint8_t>(v >> 8)).u8(static_cast<uint8_t>(v)); }
    Pkt& u32(uint32_t v) { return u16(static_cast<uint16_t>(v >> 16)).u16(static_cast<uint16_t>(v)); }
    Pkt& header(uint16_t id, uint16_t flags, uint16_t qd, uint16_t an, uint16_t ns = 0, uint16_t ar = 0) {
        return u16(id).u16(flags).u16(qd).u16(an).u16(ns).u16(ar);
    }
    // Labels only, no terminator: callers end with zero() or ptr().
    Pkt& labels(std::string_view dotted) {
        size_t start = 0;
        while (start < dotted.size()) {
            size_t dot = dotted.find('.', start);
            if (dot == std::string_view::npos) dot = dotted.size();
            u8(static_cast<uint8_t>(dot - start));
            for (size_t i = start; i < dot; ++i) u8(static_cast<uint8_t>(dotted[i]));
            start = dot + 1;
        }
        return *this;
    }
    Pkt& name(std::string_view dotted) { return labels(dotted).u8(0); }
    Pkt& ptr(size_t off) { return u16(static_cast<uint16_t>(0xC000 | off)); }
    Pkt& question(std::string_view dotted, uint16_t type = kTypeA) { return name(dotted).u16(type).u16(kClassIn); }
    // Record fixed part after the owner name.
    Pkt& rr(uint16_t type, uint16_t rdlen, uint16_t klass = kClassIn) {
        return u16(type).u16(klass).u32(300).u16(rdlen);
    }
    Pkt& a(uint8_t x, uint8_t y, uint8_t z, uint8_t w) { return rr(kTypeA, 4).u8(x).u8(y).u8(z).u8(w); }
    // EDNS0 OPT pseudo-RR as build_query writes it.
    Pkt& opt(uint16_t udp_size = kEdnsUdpSize) { return u8(0).u16(kTypeOpt).u16(udp_size).u32(0).u16(0); }
    Pkt& str(std::string_view s) {
        for (char c : s) u8(static_cast<uint8_t>(c));
        return *this;
    }
    Pkt& append(const Pkt& other) {
        b.insert(b.end(), other.b.begin(), other.b.end());
        return *this;
    }
    size_t size() const { return b.size(); }
    const uint8_t* data() const { return b.data(); }
};

uint32_t ip(uint8_t x, uint8_t y, uint8_t z, uint8_t w) {
    const uint8_t bytes[4] = {x, y, z, w};
    uint32_t v;
    std::memcpy(&v, bytes, 4);
    return v;
}

constexpr uint16_t kResponseFlags = 0x8180;  // QR RD RA, NOERROR
constexpr size_t kQname = 12;

bool parse(const Pkt& p, Response& r) { return parse_response(p.data(), p.size(), r); }

}  // namespace

TEST_CASE("build_query encodes header, labels, question and the OPT record") {
    uint8_t buf[kMaxQuerySize];
    const size_t n = build_query(0xBEEF, "www.Example.com", kTypeA, buf, sizeof buf);
    Pkt expect;
    expect.header(0xBEEF, 0x0100, 1, 0, 0, 1).question("www.Example.com").opt(1232);
    REQUIRE(n == expect.size());
    CHECK(std::memcmp(buf, expect.data(), n) == 0);

    SUBCASE("trailing dot is the same name") {
        uint8_t dotted[kMaxQuerySize];
        CHECK(build_query(0xBEEF, "www.Example.com.", kTypeA, dotted, sizeof dotted) == n);
        CHECK(std::memcmp(buf, dotted, n) == 0);
    }
    SUBCASE("round-trips through the parser") {
        Response r;
        REQUIRE(parse_response(buf, n, r));
        CHECK(r.id == 0xBEEF);
        CHECK_FALSE(r.qr);
        CHECK(r.rd);
        CHECK(r.question() == "www.Example.com");
        CHECK(r.qtype == kTypeA);
        CHECK(r.qclass == kClassIn);
        CHECK(r.addr_count == 0);
    }
    SUBCASE("HTTPS qtype and a custom payload size") {
        uint8_t https[kMaxQuerySize];
        const size_t m = build_query(7, "example.com", kTypeHttps, https, sizeof https, 4096);
        Pkt e;
        e.header(7, 0x0100, 1, 0, 0, 1).question("example.com", kTypeHttps).opt(4096);
        REQUIRE(m == e.size());
        CHECK(std::memcmp(https, e.data(), m) == 0);
    }
    SUBCASE("EDNS can be left out") {
        uint8_t plain[kMaxQuerySize];
        const size_t m = build_query(0xBEEF, "www.Example.com", kTypeA, plain, sizeof plain, 0);
        Pkt e;
        e.header(0xBEEF, 0x0100, 1, 0).question("www.Example.com");
        REQUIRE(m == e.size());
        CHECK(std::memcmp(plain, e.data(), m) == 0);
    }
}

TEST_CASE("build_query rejects invalid names and small buffers") {
    uint8_t buf[512];
    const std::string label63(63, 'a');
    const std::string label64(64, 'a');
    // 4 labels of 63 + 3 dots = 255 > 253; trim to exactly 253.
    std::string name253 = label63 + "." + label63 + "." + label63 + "." + std::string(61, 'b');
    REQUIRE(name253.size() == 253);

    CHECK(build_query(1, "", kTypeA, buf, sizeof buf) == 0);
    CHECK(build_query(1, ".", kTypeA, buf, sizeof buf) == 0);
    CHECK(build_query(1, "a..b", kTypeA, buf, sizeof buf) == 0);
    CHECK(build_query(1, ".a", kTypeA, buf, sizeof buf) == 0);
    CHECK(build_query(1, "a.b..", kTypeA, buf, sizeof buf) == 0);
    CHECK(build_query(1, label64 + ".com", kTypeA, buf, sizeof buf) == 0);
    CHECK(build_query(1, label63 + ".com", kTypeA, buf, sizeof buf) == 12 + 64 + 5 + 4 + kOptRecordSize);
    CHECK(build_query(1, name253, kTypeA, buf, sizeof buf) == kMaxQuerySize);
    CHECK(build_query(1, name253 + ".", kTypeA, buf, sizeof buf) == kMaxQuerySize);
    CHECK(build_query(1, name253 + "b", kTypeA, buf, sizeof buf) == 0);

    const size_t need = 12 + 13 + 4 + kOptRecordSize;  // "example.com"
    CHECK(build_query(1, "example.com", kTypeA, buf, need - 1) == 0);
    CHECK(build_query(1, "example.com", kTypeA, buf, need) == need);
    CHECK(build_query(1, "example.com", kTypeA, buf, need - kOptRecordSize, 0) == need - kOptRecordSize);
    CHECK(build_query(1, "example.com", kTypeA, nullptr, 0) == 0);
}

TEST_CASE("parse_response: header flags and plain A answers") {
    Pkt p;
    p.header(0x1234, 0x8583, 1, 3).question("example.com");  // QR AA RD RA, NXDOMAIN
    p.ptr(kQname).a(93, 184, 216, 34);
    p.ptr(kQname).a(10, 0, 0, 1);
    p.ptr(kQname).rr(kTypeA, 4, 3).u32(0x01020304);  // class CH: ignored
    Response r;
    REQUIRE(parse(p, r));
    CHECK(r.id == 0x1234);
    CHECK(r.qr);
    CHECK_FALSE(r.tc);
    CHECK(r.rd);
    CHECK(r.ra);
    CHECK(r.rcode == kNxDomain);
    CHECK(r.question() == "example.com");
    REQUIRE(r.addr_count == 2);
    CHECK(r.addrs[0] == ip(93, 184, 216, 34));
    CHECK(r.addrs[1] == ip(10, 0, 0, 1));
    CHECK(r.cname_hops == 0);
}

TEST_CASE("parse_response: uncompressed owner and case-insensitive match") {
    Pkt p;
    p.header(1, kResponseFlags, 1, 2).question("WWW.Example.COM");
    p.name("www.example.com").a(1, 1, 1, 1);
    p.name("other.example.com").a(2, 2, 2, 2);  // unrelated owner
    Response r;
    REQUIRE(parse(p, r));
    CHECK(r.question() == "WWW.Example.COM");
    REQUIRE(r.addr_count == 1);
    CHECK(r.addrs[0] == ip(1, 1, 1, 1));
}

TEST_CASE("parse_response: CNAME chains") {
    SUBCASE("two hops with compressed targets, unrelated A ignored") {
        Pkt p;
        p.header(7, kResponseFlags, 1, 4).question("www.example.com");
        const size_t c1 = p.size() + 12;  // target name starts after owner ptr + rr fixed part
        p.ptr(kQname).rr(kTypeCname, 6).labels("cdn").ptr(kQname + 4);  // cdn.example.com
        p.name("decoy.example.com").a(6, 6, 6, 6);
        const size_t c2 = p.size() + 12;
        p.ptr(c1).rr(kTypeCname, 7).labels("edge").u8(0).u8(0);  // name "edge" plus one slack byte
        p.ptr(c2).a(203, 0, 113, 9);
        Response r;
        REQUIRE(parse(p, r));
        REQUIRE(r.addr_count == 1);
        CHECK(r.addrs[0] == ip(203, 0, 113, 9));
        CHECK(r.cname_hops == 2);
    }
    SUBCASE("A records listed before the CNAME that leads to them") {
        Pkt p;
        p.header(7, kResponseFlags, 1, 2).question("a.test");
        p.name("B.TEST").a(5, 5, 5, 5);
        p.ptr(kQname).rr(kTypeCname, 8).name("b.test");
        Response r;
        REQUIRE(parse(p, r));
        REQUIRE(r.addr_count == 1);
        CHECK(r.addrs[0] == ip(5, 5, 5, 5));
        CHECK(r.cname_hops == 1);
    }
    SUBCASE("CNAME without a final A yields no addresses") {
        Pkt p;
        p.header(7, kResponseFlags, 1, 1).question("a.test");
        p.ptr(kQname).rr(kTypeCname, 8).name("b.test");
        Response r;
        REQUIRE(parse(p, r));
        CHECK(r.addr_count == 0);
        CHECK(r.cname_hops == 1);
    }
    SUBCASE("CNAME loop terminates") {
        Pkt p;
        p.header(7, kResponseFlags, 1, 2).question("a.test");
        p.ptr(kQname).rr(kTypeCname, 8).name("b.test");
        p.name("b.test").rr(kTypeCname, 8).name("a.test");
        Response r;
        REQUIRE(parse(p, r));
        CHECK(r.addr_count == 0);
        CHECK(r.cname_hops == kMaxCnameChain);
    }
    SUBCASE("chain depth cap") {
        auto chain = [](unsigned hops) {
            Pkt p;
            p.header(7, kResponseFlags, 1, static_cast<uint16_t>(hops + 1)).question("n0.test");
            for (unsigned i = 0; i < hops; ++i) {
                const std::string from = "n" + std::to_string(i) + ".test";
                const std::string to = "n" + std::to_string(i + 1) + ".test";
                p.name(from).rr(kTypeCname, static_cast<uint16_t>(to.size() + 2)).name(to);
            }
            p.name("n" + std::to_string(hops) + ".test").a(9, 9, 9, 9);
            return p;
        };
        Response r;
        REQUIRE(parse(chain(kMaxCnameChain), r));
        CHECK(r.addr_count == 1);
        REQUIRE(parse(chain(kMaxCnameChain + 1), r));
        CHECK(r.addr_count == 0);
    }
}

TEST_CASE("parse_response: forward and backward compression pointers") {
    // Question name points forward to labels stored in the answer's rdata.
    Pkt p;
    p.header(9, kResponseFlags, 1, 1);
    p.labels("www").ptr(0);  // patched below
    const size_t ptr_pos = p.size() - 2;
    p.u16(kTypeA).u16(kClassIn);
    p.ptr(kQname).rr(kTypeA, 4);
    const size_t rdata = p.size();
    p.u8(1).u8(2).u8(3).u8(4);
    // Extra (ignored) record whose owner holds "example.com"; the question's
    // tail points here.
    const size_t tail = p.size();
    p.name("example.com").rr(16, 1).u8(0);
    p.b[ptr_pos] = static_cast<uint8_t>(0xC0 | (tail >> 8));
    p.b[ptr_pos + 1] = static_cast<uint8_t>(tail);
    // ancount covers only the A record; the trailing bytes are ignored.
    Response r;
    REQUIRE(parse(p, r));
    CHECK(r.question() == "www.example.com");
    REQUIRE(r.addr_count == 1);
    CHECK(std::memcmp(&r.addrs[0], p.data() + rdata, 4) == 0);
}

TEST_CASE("parse_response: hostile names") {
    Response r;
    SUBCASE("question pointer to itself") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 0).ptr(kQname).u16(kTypeA).u16(kClassIn);
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("mutual pointer loop in answer owner") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 1).question("a.test");
        const size_t owner = p.size();
        p.ptr(owner + 2).ptr(owner).a(1, 2, 3, 4);
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("pointer loop through labels exceeds name length") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 0);
        p.labels("abc").ptr(kQname).u16(kTypeA).u16(kClassIn);
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("pointer past the end") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 0).labels("a").ptr(0x3FF).u16(kTypeA).u16(kClassIn);
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("extended label types") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 0).u8(0x41).u8('x').u8(0).u16(kTypeA).u16(kClassIn);
        CHECK_FALSE(parse(p, r));
        Pkt q;
        q.header(1, kResponseFlags, 1, 0).u8(0x81).u8('x').u8(0).u16(kTypeA).u16(kClassIn);
        CHECK_FALSE(parse(q, r));
    }
    SUBCASE("name longer than 255 wire bytes") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 0);
        for (int i = 0; i < 4; ++i) p.labels(std::string(63, 'x'));
        p.u8(0).u16(kTypeA).u16(kClassIn);
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("dot inside a question label") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 0).u8(3).u8('a').u8('.').u8('b').u8(0).u16(kTypeA).u16(kClassIn);
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("qdcount must be one") {
        Pkt p;
        p.header(1, kResponseFlags, 0, 0);
        CHECK_FALSE(parse(p, r));
        Pkt q;
        q.header(1, kResponseFlags, 2, 0).question("a.test").question("b.test");
        CHECK_FALSE(parse(q, r));
    }
    SUBCASE("A record with wrong rdlength") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 1).question("a.test").ptr(kQname).rr(kTypeA, 5).u32(1).u8(0);
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("CNAME target overrunning its rdata") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 1).question("a.test").ptr(kQname).rr(kTypeCname, 2).name("b.test");
        CHECK_FALSE(parse(p, r));
    }
    SUBCASE("rdlength past the end") {
        Pkt p;
        p.header(1, kResponseFlags, 1, 1).question("a.test").ptr(kQname).rr(kTypeA, 4).u8(1);
        CHECK_FALSE(parse(p, r));
    }
}

TEST_CASE("parse_response: every truncation of a valid packet is rejected") {
    Pkt p;
    p.header(7, kResponseFlags, 1, 3).question("www.example.com");
    const size_t c1 = p.size() + 12;
    p.ptr(kQname).rr(kTypeCname, 6).labels("cdn").ptr(kQname + 4);
    p.ptr(c1).a(1, 2, 3, 4);
    p.ptr(c1).a(5, 6, 7, 8);
    Response r;
    REQUIRE(parse(p, r));
    REQUIRE(r.addr_count == 2);
    for (size_t len = 0; len < p.size(); ++len) {
        CAPTURE(len);
        CHECK_FALSE(parse_response(p.data(), len, r));
    }
    CHECK_FALSE(parse_response(nullptr, 0, r));
}

TEST_CASE("parse_response: TC tolerates a cut answer section") {
    Pkt p;
    p.header(7, 0x8380, 1, 3).question("a.test");  // TC set
    p.ptr(kQname).a(1, 2, 3, 4);
    p.ptr(kQname).rr(kTypeA, 4).u8(5);  // cut mid-rdata
    Response r;
    REQUIRE(parse(p, r));
    CHECK(r.tc);
    REQUIRE(r.addr_count == 1);
    CHECK(r.addrs[0] == ip(1, 2, 3, 4));
}

TEST_CASE("parse_response: address list is capped") {
    Pkt p;
    p.header(7, kResponseFlags, 1, 40).question("a.test");
    for (uint8_t i = 0; i < 40; ++i) p.ptr(kQname).a(10, 0, 0, i);
    Response r;
    REQUIRE(parse(p, r));
    CHECK(r.addr_count == kMaxAddresses);
    CHECK(r.addrs[kMaxAddresses - 1] == ip(10, 0, 0, static_cast<uint8_t>(kMaxAddresses - 1)));
}

TEST_CASE("parse_response survives random mutation") {
    Pkt p;
    p.header(7, kResponseFlags, 1, 3).question("www.example.com");
    const size_t c1 = p.size() + 12;
    p.ptr(kQname).rr(kTypeCname, 6).labels("cdn").ptr(kQname + 4);
    p.ptr(c1).a(1, 2, 3, 4);
    p.ptr(c1).a(5, 6, 7, 8);

    std::mt19937 rng(463);
    std::vector<uint8_t> buf;
    Response r;
    size_t accepted = 0;
    for (int iter = 0; iter < 50000; ++iter) {
        buf = p.b;
        const int flips = 1 + static_cast<int>(rng() % 4);
        for (int f = 0; f < flips; ++f) buf[rng() % buf.size()] = static_cast<uint8_t>(rng());
        buf.resize(buf.size() - rng() % 8);
        if (parse_response(buf.data(), buf.size(), r)) {
            ++accepted;
            CHECK(r.addr_count <= kMaxAddresses);
            CHECK(r.qname_len <= kMaxNameText);
            CHECK(r.qname[r.qname_len] == '\0');
        }
    }
    CHECK(accepted > 0);
}

namespace {

Pkt svc_param(uint16_t key, const Pkt& value) {
    Pkt p;
    p.u16(key).u16(static_cast<uint16_t>(value.size())).append(value);
    return p;
}

Pkt alpn(std::initializer_list<std::string_view> ids) {
    Pkt v;
    for (std::string_view id : ids) v.u8(static_cast<uint8_t>(id.size())).str(id);
    return svc_param(kSvcAlpn, v);
}

// A well-framed ECHConfigList; its contents are opaque to the parser.
Pkt ech() {
    Pkt v;
    v.u16(6).u16(0xfe0d).u16(2).u8(0xaa).u8(0xbb);
    return svc_param(kSvcEch, v);
}

Pkt ipv4hint(std::initializer_list<uint32_t> addrs) {
    Pkt v;
    for (uint32_t a : addrs) v.u32(a);
    return svc_param(kSvcIpv4Hint, v);
}

Pkt port(uint16_t value) { return svc_param(kSvcPort, Pkt().u16(value)); }

Pkt mandatory(std::initializer_list<uint16_t> keys) {
    Pkt v;
    for (uint16_t k : keys) v.u16(k);
    return svc_param(kSvcMandatory, v);
}

Pkt https_rdata(uint16_t priority, std::string_view target, std::initializer_list<Pkt> params = {}) {
    Pkt r;
    r.u16(priority);
    if (target == ".") {
        r.u8(0);
    } else {
        r.name(target);
    }
    for (const Pkt& p : params) r.append(p);
    return r;
}

Pkt https_response(std::initializer_list<Pkt> rdatas, std::string_view qname = "example.com") {
    Pkt p;
    p.header(0x4242, kResponseFlags, 1, static_cast<uint16_t>(rdatas.size())).question(qname, kTypeHttps);
    for (const Pkt& rd : rdatas) p.ptr(kQname).rr(kTypeHttps, static_cast<uint16_t>(rd.size())).append(rd);
    return p;
}

bool parse_rdata(const Pkt& rd, HttpsRr& rr) { return parse_https_rdata(rd.data(), rd.size(), rr); }

}  // namespace

TEST_CASE("HTTPS RR: ServiceMode with alpn, ipv4hint, ech and ipv6hint") {
    // The shape Cloudflare publishes: 1 . alpn=h3,h2 ipv4hint=... ech=... ipv6hint=...
    Pkt v6;
    for (int i = 0; i < 32; ++i) v6.u8(static_cast<uint8_t>(i));
    const Pkt p = https_response({https_rdata(
        1, ".", {alpn({"h3", "h2"}), ipv4hint({0x68108414, 0x68108514}), ech(), svc_param(kSvcIpv6Hint, v6)})});
    Response r;
    REQUIRE(parse(p, r));
    CHECK(r.qtype == kTypeHttps);
    CHECK(r.addr_count == 0);
    CHECK_FALSE(r.https_malformed);
    REQUIRE(r.https_count == 1);
    const HttpsRr& h = r.https;
    CHECK_FALSE(h.alias_mode());
    CHECK(h.priority == 1);
    CHECK(h.target_name() == ".");
    CHECK(h.alpn_h3);
    CHECK(h.alpn_h2);
    CHECK_FALSE(h.alpn_http11);
    CHECK_FALSE(h.no_default_alpn);
    CHECK(h.ech);
    CHECK(h.ipv4hint);
    CHECK(h.ipv6hint);
    CHECK(h.port == 0);
    CHECK(r.cname_hops == 0);
}

TEST_CASE("HTTPS RR: record selection") {
    Response r;
    SUBCASE("lowest SvcPriority wins") {
        REQUIRE(parse(https_response({https_rdata(2, "b.example.net", {alpn({"http/1.1"}), port(8443)}),
                                      https_rdata(1, "A.Example.NET", {alpn({"h2"})})}),
                      r));
        REQUIRE(r.https_count == 2);
        CHECK(r.https.priority == 1);
        CHECK(r.https.target_name() == "A.Example.NET");
        CHECK(r.https.alpn_h2);
        CHECK_FALSE(r.https.alpn_http11);
        CHECK(r.https.port == 0);
    }
    SUBCASE("ties keep the first record") {
        REQUIRE(parse(https_response({https_rdata(3, "first.test", {port(1)}), https_rdata(3, "second.test")}), r));
        CHECK(r.https.target_name() == "first.test");
        CHECK(r.https.port == 1);
    }
    SUBCASE("AliasMode wins over ServiceMode in either order") {
        REQUIRE(parse(https_response({https_rdata(1, ".", {alpn({"h3"})}), https_rdata(0, "cdn.example.net")}), r));
        REQUIRE(r.https_count == 2);
        CHECK(r.https.alias_mode());
        CHECK(r.https.target_name() == "cdn.example.net");
        CHECK_FALSE(r.https.alpn_h3);
        REQUIRE(parse(https_response({https_rdata(0, "cdn.example.net"), https_rdata(1, ".", {alpn({"h3"})})}), r));
        CHECK(r.https.alias_mode());
        CHECK(r.https.target_name() == "cdn.example.net");
    }
    SUBCASE("AliasMode SvcParams are ignored unread") {
        Pkt junk;
        junk.u16(kSvcPort).u16(40).u8(1);  // would overrun in ServiceMode
        REQUIRE(parse(https_response({https_rdata(0, ".", {junk})}), r));
        CHECK_FALSE(r.https_malformed);
        REQUIRE(r.https_count == 1);
        CHECK(r.https.alias_mode());
        CHECK(r.https.target_name() == ".");
    }
}

TEST_CASE("HTTPS RR: CNAME chain, NODATA and type separation") {
    Response r;
    SUBCASE("CNAME to the HTTPS RRset; records at other owners ignored") {
        Pkt p;
        p.header(5, kResponseFlags, 1, 3).question("www.example.com", kTypeHttps);
        p.ptr(kQname).rr(kTypeCname, 17).name("cdn.example.net");
        const Pkt decoy = https_rdata(1, "decoy.test", {alpn({"h2"})});
        p.name("other.test").rr(kTypeHttps, static_cast<uint16_t>(decoy.size())).append(decoy);
        const Pkt real = https_rdata(1, ".", {alpn({"h3", "h2"}), ech()});
        p.name("CDN.example.net").rr(kTypeHttps, static_cast<uint16_t>(real.size())).append(real);
        REQUIRE(parse(p, r));
        CHECK(r.cname_hops == 1);
        REQUIRE(r.https_count == 1);
        CHECK(r.https.target_name() == ".");
        CHECK(r.https.alpn_h3);
        CHECK(r.https.ech);
    }
    SUBCASE("NODATA") {
        Pkt p;
        p.header(5, kResponseFlags, 1, 0).question("example.com", kTypeHttps);
        REQUIRE(parse(p, r));
        CHECK(r.https_count == 0);
        CHECK_FALSE(r.https_malformed);
    }
    SUBCASE("A records do not answer an HTTPS question") {
        Pkt p;
        p.header(5, kResponseFlags, 1, 1).question("example.com", kTypeHttps).ptr(kQname).a(1, 2, 3, 4);
        REQUIRE(parse(p, r));
        CHECK(r.https_count == 0);
        CHECK(r.addr_count == 0);
    }
    SUBCASE("HTTPS records do not answer an A question") {
        const Pkt rd = https_rdata(1, ".", {alpn({"h3"})});
        Pkt p;
        p.header(5, kResponseFlags, 1, 2).question("example.com");
        p.ptr(kQname).rr(kTypeHttps, static_cast<uint16_t>(rd.size())).append(rd);
        p.ptr(kQname).a(1, 2, 3, 4);
        REQUIRE(parse(p, r));
        CHECK(r.https_count == 0);
        CHECK(r.addr_count == 1);
    }
}

TEST_CASE("HTTPS RR: valid edge cases") {
    HttpsRr rr;
    SUBCASE("unknown keys are skipped") {
        Pkt v;
        v.str("opaque");
        REQUIRE(parse_rdata(https_rdata(1, ".", {alpn({"h2"}), svc_param(65333, v)}), rr));
        CHECK(rr.alpn_h2);
    }
    SUBCASE("mandatory naming present keys, including unknown ones") {
        REQUIRE(parse_rdata(https_rdata(1, ".", {mandatory({kSvcAlpn, kSvcIpv4Hint, 65000}), alpn({"h2"}),
                                                 ipv4hint({0x01020304}), svc_param(65000, Pkt())}),
                            rr));
        CHECK(rr.ipv4hint);
    }
    SUBCASE("draft and 255-byte alpn ids are not h3") {
        const std::string long_id(255, 'x');
        REQUIRE(parse_rdata(https_rdata(1, ".", {alpn({"h3-29", long_id, "http/1.1"})}), rr));
        CHECK_FALSE(rr.alpn_h3);
        CHECK(rr.alpn_http11);
    }
    SUBCASE("no-default-alpn with alpn") {
        REQUIRE(parse_rdata(https_rdata(1, ".", {alpn({"h3"}), svc_param(kSvcNoDefaultAlpn, Pkt())}), rr));
        CHECK(rr.no_default_alpn);
    }
    SUBCASE("253-character target") {
        const std::string label63(63, 'a');
        const std::string name = label63 + "." + label63 + "." + label63 + "." + std::string(61, 'b');
        REQUIRE(parse_rdata(https_rdata(1, name, {port(443)}), rr));
        CHECK(rr.target_name() == name);
        CHECK(rr.port == 443);
    }
}

TEST_CASE("HTTPS RR: malformed records") {
    struct Case {
        const char* what;
        Pkt rdata;
    };
    Pkt v;
    std::vector<Case> cases;
    cases.push_back({"rdata shorter than priority + root", Pkt().u16(1)});
    cases.push_back({"target overruns rdata", Pkt().u16(1).u8(5).str("ab")});
    cases.push_back({"compressed target", Pkt().u16(1).ptr(kQname)});
    cases.push_back({"target longer than 255 wire bytes", [] {
                         Pkt r;
                         r.u16(1);
                         for (int i = 0; i < 4; ++i) r.labels(std::string(63, 'x'));
                         return r.u8(0);
                     }()});
    cases.push_back({"dot inside a target label", Pkt().u16(1).u8(3).str("a.b").u8(0)});
    cases.push_back({"param header truncated", https_rdata(1, ".").u16(kSvcAlpn).u8(0)});
    cases.push_back({"param value overruns rdata", https_rdata(1, ".").u16(kSvcPort).u16(4).u16(443)});
    cases.push_back({"keys out of order", https_rdata(1, ".", {port(443), alpn({"h2"})})});
    cases.push_back({"duplicate key", https_rdata(1, ".", {alpn({"h2"}), alpn({"h3"})})});
    cases.push_back({"empty alpn", https_rdata(1, ".", {svc_param(kSvcAlpn, Pkt())})});
    cases.push_back({"zero-length alpn id", https_rdata(1, ".", {svc_param(kSvcAlpn, Pkt().u8(0))})});
    cases.push_back({"alpn id overruns the value", https_rdata(1, ".", {svc_param(kSvcAlpn, Pkt().u8(5).str("h3"))})});
    cases.push_back({"oversized alpn id after a good one",
                     https_rdata(1, ".", {svc_param(kSvcAlpn, Pkt().u8(2).str("h2").u8(200).str("http/1.1"))})});
    cases.push_back({"no-default-alpn with a value",
                     https_rdata(1, ".", {alpn({"h2"}), svc_param(kSvcNoDefaultAlpn, Pkt().u8(1))})});
    cases.push_back({"no-default-alpn without alpn", https_rdata(1, ".", {svc_param(kSvcNoDefaultAlpn, Pkt())})});
    cases.push_back({"3-byte port", https_rdata(1, ".", {svc_param(kSvcPort, Pkt().u16(443).u8(0))})});
    cases.push_back({"empty ipv4hint", https_rdata(1, ".", {svc_param(kSvcIpv4Hint, Pkt())})});
    cases.push_back({"5-byte ipv4hint", https_rdata(1, ".", {svc_param(kSvcIpv4Hint, Pkt().u32(1).u8(2))})});
    cases.push_back({"4-byte ipv6hint", https_rdata(1, ".", {svc_param(kSvcIpv6Hint, Pkt().u32(1))})});
    cases.push_back({"empty ech", https_rdata(1, ".", {svc_param(kSvcEch, Pkt())})});
    cases.push_back({"ech list length mismatch", https_rdata(1, ".", {svc_param(kSvcEch, Pkt().u16(7).u32(0).u16(0))})});
    cases.push_back({"ech list too short", https_rdata(1, ".", {svc_param(kSvcEch, Pkt().u16(2).u16(0))})});
    cases.push_back({"mandatory lists itself", https_rdata(1, ".", {mandatory({kSvcMandatory, kSvcAlpn}), alpn({"h2"})})});
    cases.push_back({"mandatory of odd length", https_rdata(1, ".", {svc_param(kSvcMandatory, Pkt().u16(1).u8(0)), alpn({"h2"})})});
    cases.push_back({"mandatory not increasing",
                     https_rdata(1, ".", {mandatory({kSvcIpv4Hint, kSvcAlpn}), alpn({"h2"}), ipv4hint({1})})});
    cases.push_back({"mandatory key absent", https_rdata(1, ".", {mandatory({kSvcIpv4Hint}), alpn({"h2"})})});

    for (const Case& c : cases) {
        CAPTURE(c.what);
        HttpsRr rr;
        CHECK_FALSE(parse_rdata(c.rdata, rr));
        CHECK(rr.target_len <= kMaxNameText);

        // In a response the bad record taints the whole RRset but is not a
        // framing error.
        Response r;
        REQUIRE(parse(https_response({https_rdata(1, ".", {alpn({"h3"})}), c.rdata}), r));
        CHECK(r.https_malformed);
        CHECK(r.https_count == 1);
    }
}

TEST_CASE("HTTPS RR: truncation and random mutation") {
    Pkt p;
    p.header(7, kResponseFlags, 1, 3).question("www.example.com", kTypeHttps);
    p.ptr(kQname).rr(kTypeCname, 6).labels("cdn").ptr(kQname + 4);
    const size_t cdn = p.size() - 6;
    const Pkt a = https_rdata(1, ".", {alpn({"h3", "h2"}), ipv4hint({1, 2}), ech()});
    const Pkt b = https_rdata(2, "alt.example.net", {mandatory({kSvcPort}), alpn({"h2"}), port(8443)});
    p.ptr(cdn).rr(kTypeHttps, static_cast<uint16_t>(a.size())).append(a);
    p.ptr(cdn).rr(kTypeHttps, static_cast<uint16_t>(b.size())).append(b);
    Response r;
    REQUIRE(parse(p, r));
    REQUIRE(r.https_count == 2);
    CHECK_FALSE(r.https_malformed);
    CHECK(r.https.priority == 1);
    for (size_t len = 0; len < p.size(); ++len) {
        CAPTURE(len);
        CHECK_FALSE(parse_response(p.data(), len, r));
    }

    std::mt19937 rng(9460);
    std::vector<uint8_t> buf;
    size_t accepted = 0;
    size_t usable = 0;
    for (int iter = 0; iter < 50000; ++iter) {
        buf = p.b;
        const int flips = 1 + static_cast<int>(rng() % 4);
        for (int f = 0; f < flips; ++f) buf[rng() % buf.size()] = static_cast<uint8_t>(rng());
        buf.resize(buf.size() - rng() % 8);
        if (parse_response(buf.data(), buf.size(), r)) {
            ++accepted;
            usable += r.https_count != 0 && !r.https_malformed;
            CHECK(r.https.target_len <= kMaxNameText);
            CHECK(r.https.target[r.https.target_len] == '\0');
        }
    }
    CHECK(accepted > 0);
    CHECK(usable > 0);
}

TEST_CASE("name_equal") {
    CHECK(name_equal("Example.COM", "example.com"));
    CHECK(name_equal("example.com.", "EXAMPLE.com"));
    CHECK_FALSE(name_equal("example.com", "example.co"));
    CHECK_FALSE(name_equal("example.com", "exbmple.com"));
    CHECK(name_equal("", "."));
}
