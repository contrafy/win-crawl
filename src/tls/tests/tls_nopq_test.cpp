// StartupOptions{.post_quantum = false} is process-wide and first-call-wins, so it
// gets its own test executable.
#include "tls/tls.h"

#include "test_server.h"
#include "tls/sspi_include.h"
#include "wire.h"

#include "doctest/doctest.h"

#include <string>
#include <vector>

using wc::tls::ClientSession;
using wc::tls::Verify;
using State = ClientSession::State;

namespace {

bool is_pq_group(uint16_t g) {
    return wc::tls::is_pq_hybrid_group(g) || (g >= 0x0200 && g <= 0x0202);
}

}  // namespace

TEST_CASE("post_quantum = false keeps ML-KEM groups out of the ClientHello") {
    REQUIRE(wc::tls::startup(wc::tls::StartupOptions{.post_quantum = false}));
    CHECK(!wc::tls::post_quantum_available());
    CHECK(wc::tls::startup());  // later default options do not turn it back on
    CHECK(!wc::tls::post_quantum_available());

    ClientSession c("nopq.localhost", Verify::None);
    std::vector<char> wire;
    REQUIRE(c.start(wire) == State::Handshaking);
    const wc::tls::test::ClientHelloGroups hello = wc::tls::test::parse_client_hello(wire);
    REQUIRE(hello.ok);
    CHECK(!hello.supported.empty());  // the classical groups are still offered
    for (uint16_t g : hello.supported)
        CHECK(!is_pq_group(g));
    for (uint16_t g : hello.key_shares)
        CHECK(!is_pq_group(g));
}

TEST_CASE("post_quantum = false negotiates a classical group with TLS 1.3") {
    REQUIRE(wc::tls::test::server_identity_ready());
    REQUIRE(wc::tls::startup(wc::tls::StartupOptions{.post_quantum = false}));
    ClientSession client("nopq-hs.localhost", Verify::None);
    wc::tls::test::Server server(wc::tls::test::ServerProto::Tls13);
    REQUIRE(server.ok());
    std::vector<char> c2s, s2c, flight, plain;
    REQUIRE(client.start(c2s) == State::Handshaking);
    for (int i = 0; i < 10 && client.state() == State::Handshaking; ++i) {
        REQUIRE(server.feed(c2s.data(), c2s.size(), s2c, plain));
        c2s.clear();
        flight.insert(flight.end(), s2c.begin(), s2c.end());
        client.feed(s2c.data(), s2c.size(), c2s, plain);
        s2c.clear();
    }
    REQUIRE(client.state() == State::Established);
    const ClientSession::Info info = client.info();
    CHECK(info.protocol == SP_PROT_TLS1_3_CLIENT);
    CHECK(info.group == wc::tls::test::parse_server_flight(flight).group);
    CHECK(info.group != 0);
    CHECK(!info.pq_hybrid);
    CHECK(!is_pq_group(info.group));
}
