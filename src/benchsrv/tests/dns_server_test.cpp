#include "benchsrv/dns_server.h"

#include "net/loop.h"
#include "raw_client.h"

#include "doctest/doctest.h"

#include <chrono>

using namespace wc::benchsrv;
using namespace wc::benchsrv::test;

namespace {

constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeAaaa = 28;

uint64_t first_host(const Behavior& b, bool nx) {
    for (uint64_t n = 0;; ++n) {
        if (host_nxdomain(b, n) == nx) return n;
    }
}

std::string host_name(uint64_t n) { return "h" + std::to_string(n) + ".bench.test"; }

DnsReply ask(UdpClient& client, const sockaddr_in& server, uint16_t id, const std::string& name,
             uint16_t qtype = kTypeA) {
    REQUIRE(client.send(server, make_query(id, name, qtype)));
    return client.receive();
}

}  // namespace

TEST_CASE("dns server answers, NXDOMAIN, NODATA and REFUSED") {
    wc::net::startup();
    Behavior b;
    DnsServer server(b);
    REQUIRE(server.start(loopback(0)) == 0);
    const sockaddr_in addr = server.local_address();
    REQUIRE(addr.sin_port != 0);
    UdpClient client;

    SUBCASE("A record for every resolving host, deterministic and IP-shared") {
        size_t shared = 0;
        for (uint64_t n = 0; n < 200; ++n) {
            const DnsReply r = ask(client, addr, static_cast<uint16_t>(1000 + n), host_name(n));
            REQUIRE(r.ok);
            CHECK(r.id == 1000 + n);
            CHECK((r.flags & 0x8000) != 0);  // QR
            CHECK((r.flags & 0x0100) != 0);  // RD echoed
            if (host_nxdomain(b, n)) {
                CHECK(r.rcode() == 3);
                CHECK(r.ancount == 0);
            } else {
                CHECK(r.rcode() == 0);
                CHECK((r.flags & 0x0400) != 0);  // AA
                REQUIRE(r.ancount == 1);
                CHECK(r.ipv4_be == host_ip(b, n));
                shared += host_shares_ip(b, n) ? 1 : 0;
            }
        }
        CHECK(shared > 0);  // the sample exercises IP sharing
        const uint64_t n = first_host(b, false);
        // Mixed case (0x20 randomisation) resolves the same.
        const DnsReply upper = ask(client, addr, 7, "H" + std::to_string(n) + ".BENCH.test");
        CHECK(upper.rcode() == 0);
        CHECK(upper.ipv4_be == host_ip(b, n));
    }

    SUBCASE("NXDOMAIN, NODATA and REFUSED") {
        CHECK(ask(client, addr, 1, host_name(first_host(b, true))).rcode() == 3);
        CHECK(ask(client, addr, 2, "www.bench.test").rcode() == 3);
        const DnsReply refused = ask(client, addr, 3, "example.com");
        CHECK(refused.rcode() == 5);
        CHECK((refused.flags & 0x0400) == 0);
        const DnsReply nodata = ask(client, addr, 4, host_name(first_host(b, false)), kTypeAaaa);
        CHECK(nodata.rcode() == 0);
        CHECK(nodata.ancount == 0);
    }

    SUBCASE("malformed queries get FORMERR or are dropped") {
        std::string q = make_query(9, "h1.bench.test", kTypeA);
        q.resize(q.size() - 3);  // truncated question
        REQUIRE(client.send(addr, q));
        DnsReply r = client.receive();
        CHECK(r.ok);
        CHECK(r.rcode() == 1);
        // A response (QR set) must not be answered; the next query still is.
        std::string resp = make_query(10, "h1.bench.test", kTypeA);
        resp[2] = static_cast<char>(resp[2] | 0x80);
        REQUIRE(client.send(addr, resp));
        r = ask(client, addr, 11, "example.org");
        CHECK(r.id == 11);
    }

    server.stop();
    const DnsCounters c = server.counters();
    CHECK(c.queries > 0);
}

TEST_CASE("dns reply builder") {
    Behavior b;
    std::vector<char> out;
    uint64_t key = 0;
    const std::string q = make_query(5, "h42.bench.test", kTypeA);
    CHECK(build_dns_reply(b, q.data(), 11, out, key) == DnsOutcome::Drop);
    const DnsOutcome o = build_dns_reply(b, q.data(), q.size(), out, key);
    CHECK(key == 42);
    CHECK((o == DnsOutcome::Answered || o == DnsOutcome::NxDomain));
    std::string notimp = q;
    notimp[2] = static_cast<char>(notimp[2] | (2 << 3));  // opcode 2 (STATUS)
    CHECK(build_dns_reply(b, notimp.data(), notimp.size(), out, key) == DnsOutcome::Error);
    CHECK((out[3] & 0xF) == 4);
}

TEST_CASE("dns reply delay follows the per-name schedule") {
    wc::net::startup();
    Behavior b;
    b.nxdomain = 0;
    b.dns_delay = Delay{100, 90};  // 10..190 ms
    // One fast and one slow host, chosen from the deterministic schedule.
    uint64_t fast = UINT64_MAX, slow = UINT64_MAX;
    for (uint64_t n = 0; fast == UINT64_MAX || slow == UINT64_MAX; ++n) {
        const uint32_t d = dns_delay_ms(b, n);
        CHECK(d == dns_delay_ms(b, n));
        if (d <= 30 && fast == UINT64_MAX) fast = n;
        if (d >= 150 && slow == UINT64_MAX) slow = n;
    }
    DnsServer server(b);
    REQUIRE(server.start(loopback(0)) == 0);
    UdpClient client;

    // Send the slow query first: the fast reply must still arrive first.
    const auto t0 = std::chrono::steady_clock::now();
    REQUIRE(client.send(server.local_address(), make_query(1, host_name(slow), kTypeA)));
    REQUIRE(client.send(server.local_address(), make_query(2, host_name(fast), kTypeA)));
    const DnsReply first = client.receive();
    const auto t1 = std::chrono::steady_clock::now();
    const DnsReply second = client.receive();
    const auto t2 = std::chrono::steady_clock::now();
    REQUIRE(first.ok);
    REQUIRE(second.ok);
    CHECK(first.id == 2);
    CHECK(second.id == 1);
    const auto ms = [](auto d) { return std::chrono::duration_cast<std::chrono::milliseconds>(d).count(); };
    // Timer resolution on Windows is ~15.6 ms; allow for it on the early side.
    CHECK(ms(t1 - t0) >= static_cast<long long>(dns_delay_ms(b, fast)) - 16);
    CHECK(ms(t2 - t0) >= static_cast<long long>(dns_delay_ms(b, slow)) - 16);
    CHECK(ms(t2 - t0) < 1500);
    server.stop();
}
