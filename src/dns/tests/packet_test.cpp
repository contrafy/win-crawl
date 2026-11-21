#include "dns/packet.h"

#include "doctest/doctest.h"

#include <cstring>
#include <random>
#include <string>
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

TEST_CASE("build_query encodes header, labels and question") {
    uint8_t buf[kMaxQuerySize];
    const size_t n = build_query(0xBEEF, "www.Example.com", kTypeA, buf, sizeof buf);
    Pkt expect;
    expect.header(0xBEEF, 0x0100, 1, 0).question("www.Example.com");
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
    CHECK(build_query(1, label63 + ".com", kTypeA, buf, sizeof buf) == 12 + 64 + 5 + 4);
    CHECK(build_query(1, name253, kTypeA, buf, sizeof buf) == kMaxQuerySize);
    CHECK(build_query(1, name253 + ".", kTypeA, buf, sizeof buf) == kMaxQuerySize);
    CHECK(build_query(1, name253 + "b", kTypeA, buf, sizeof buf) == 0);

    const size_t need = 12 + 13 + 4;  // "example.com"
    CHECK(build_query(1, "example.com", kTypeA, buf, need - 1) == 0);
    CHECK(build_query(1, "example.com", kTypeA, buf, need) == need);
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

TEST_CASE("name_equal") {
    CHECK(name_equal("Example.COM", "example.com"));
    CHECK(name_equal("example.com.", "EXAMPLE.com"));
    CHECK_FALSE(name_equal("example.com", "example.co"));
    CHECK_FALSE(name_equal("example.com", "exbmple.com"));
    CHECK(name_equal("", "."));
}
