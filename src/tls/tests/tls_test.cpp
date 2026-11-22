#include "tls/tls.h"

#include "test_server.h"
#include "tls/sspi_include.h"
#include "wire.h"

#include "doctest/doctest.h"

#include <algorithm>
#include <random>
#include <string>
#include <vector>

using wc::tls::ClientSession;
using wc::tls::Failure;
using wc::tls::Verify;
using wc::tls::test::Server;
using wc::tls::test::ServerOptions;
using wc::tls::test::ServerProto;
using State = ClientSession::State;

namespace {

// Schannel caches client sessions per (credential, target name) and every test
// server has fresh credentials, so a reused name would make the client offer a
// session the new server cannot resume. Each harness gets its own name.
std::string unique_name() {
    static int counter = 0;
    return "h" + std::to_string(++counter) + ".localhost";
}

// Client and server connected by two in-memory byte pipes. Each delivery splits the
// in-flight bytes into chunks of 1..max_chunk bytes (0 = deliver everything at once).
struct Harness {
    ClientSession client;
    Server server;
    std::vector<char> c2s, s2c;
    std::vector<char> client_plain, server_plain;
    std::vector<char> client_hello;   // the client's first flight
    std::vector<char> server_flight;  // everything the server sent before the client finished
    std::mt19937 rng;
    size_t max_chunk;

    Harness(ServerProto proto, Verify verify, size_t max_chunk_, unsigned seed = 1)
        : client(unique_name(), verify), server(proto), rng(seed), max_chunk(max_chunk_) {}
    Harness(ServerProto proto, const std::string& name, const ServerOptions& options)
        : client(name, Verify::None), server(proto, options), rng(1), max_chunk(0) {}

    size_t next_chunk(size_t remaining) {
        if (max_chunk == 0)
            return remaining;
        return std::min(remaining, 1 + static_cast<size_t>(rng() % max_chunk));
    }

    bool client_live() const { return client.state() == State::Handshaking || client.state() == State::Established; }

    void pump() {
        while (!c2s.empty() || !s2c.empty()) {
            std::vector<char> batch;
            batch.swap(c2s);
            for (size_t off = 0; off < batch.size() && server.ok() && !server.closed();) {
                const size_t n = next_chunk(batch.size() - off);
                server.feed(batch.data() + off, n, s2c, server_plain);
                off += n;
            }
            batch.clear();
            batch.swap(s2c);
            if (client.state() == State::Handshaking)
                server_flight.insert(server_flight.end(), batch.begin(), batch.end());
            for (size_t off = 0; off < batch.size() && client_live();) {
                const size_t n = next_chunk(batch.size() - off);
                client.feed(batch.data() + off, n, c2s, client_plain);
                off += n;
            }
            if (!server.ok() || !client_live())
                break;
        }
    }

    void handshake() {
        REQUIRE(wc::tls::test::server_identity_ready());
        REQUIRE(server.ok());
        REQUIRE(client.start(c2s) == State::Handshaking);
        REQUIRE(!c2s.empty());
        client_hello = c2s;
        pump();
    }
};

std::vector<char> random_bytes(size_t n, unsigned seed) {
    std::mt19937 rng(seed);
    std::vector<char> v(n);
    for (char& c : v)
        c = static_cast<char>(rng());
    return v;
}

uint32_t expected_protocol(ServerProto proto) {
    return proto == ServerProto::Tls13 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
}

// Sends `payload` both ways and checks it arrives intact.
void round_trip(Harness& h, const std::vector<char>& payload) {
    h.client_plain.clear();
    h.server_plain.clear();
    REQUIRE(h.client.encrypt(payload.data(), payload.size(), h.c2s));
    h.pump();
    REQUIRE(h.server.ok());
    CHECK(h.server_plain == payload);

    REQUIRE(h.server.encrypt(payload.data(), payload.size(), h.s2c));
    h.pump();
    REQUIRE(h.client.state() == State::Established);
    CHECK(h.client_plain == payload);
    CHECK(h.client.pending_input() == 0);
}

bool is_pq_group(uint16_t g) {
    return wc::tls::is_pq_hybrid_group(g) || (g >= 0x0200 && g <= 0x0202);  // pure MLKEM512/768/1024
}

std::string group_list(const std::vector<uint16_t>& groups) {
    std::string out;
    for (uint16_t g : groups) {
        const char* name = wc::tls::group_name(g);
        out += (out.empty() ? "" : " ") + (*name != 0 ? std::string(name) : std::to_string(g));
    }
    return out;
}

// Checks info() against the ServerHello / ServerKeyExchange that crossed the wire.
wc::tls::ClientSession::Info checked_info(const Harness& h, ServerProto proto) {
    const ClientSession::Info info = h.client.info();
    const wc::tls::test::ServerKeyExchange server = wc::tls::test::parse_server_flight(h.server_flight);
    CHECK(info.protocol == expected_protocol(proto));
    CHECK(info.cipher.rfind("TLS_", 0) == 0);
    REQUIRE(server.ok);
    CHECK(!server.hello_retry);
    CHECK(info.group != 0);
    CHECK(info.group == server.group);
    CHECK(!info.key_exchange.empty());
    CHECK(info.key_exchange == wc::tls::group_name(info.group));
    CHECK(info.pq_hybrid == wc::tls::is_pq_hybrid_group(info.group));
    if (proto == ServerProto::Tls12)
        CHECK(!info.pq_hybrid);  // TLS 1.2 has no hybrid groups
    return info;
}

}  // namespace

TEST_CASE("startup is idempotent") {
    CHECK(wc::tls::startup());
    CHECK(wc::tls::startup());
    // The first call's options win: asking for no PQ now changes nothing.
    const bool pq = wc::tls::post_quantum_available();
    CHECK(wc::tls::startup(wc::tls::StartupOptions{.post_quantum = false}));
    CHECK(wc::tls::post_quantum_available() == pq);
}

TEST_CASE("group names and hybrid classification") {
    CHECK(std::string(wc::tls::group_name(0x001d)) == "x25519");
    CHECK(std::string(wc::tls::group_name(0x0017)) == "secp256r1");
    CHECK(std::string(wc::tls::group_name(0x0018)) == "secp384r1");
    CHECK(std::string(wc::tls::group_name(0x11ec)) == "X25519MLKEM768");
    CHECK(std::string(wc::tls::group_name(0x11eb)) == "SecP256r1MLKEM768");
    CHECK(std::string(wc::tls::group_name(0x11ed)) == "SecP384r1MLKEM1024");
    CHECK(std::string(wc::tls::group_name(0x0201)) == "MLKEM768");
    CHECK(std::string(wc::tls::group_name(0)).empty());
    CHECK(std::string(wc::tls::group_name(0x1234)).empty());
    CHECK(wc::tls::is_pq_hybrid_group(0x11ec));
    CHECK(wc::tls::is_pq_hybrid_group(0x11eb));
    CHECK(wc::tls::is_pq_hybrid_group(0x6399));
    CHECK(!wc::tls::is_pq_hybrid_group(0x001d));
    CHECK(!wc::tls::is_pq_hybrid_group(0x0201));  // pure ML-KEM is post-quantum but not hybrid
    CHECK(!wc::tls::is_pq_hybrid_group(0));
}

TEST_CASE("post_quantum_available() matches the ClientHello on the wire") {
    REQUIRE(wc::tls::startup());
    ClientSession c(unique_name(), Verify::None);
    std::vector<char> wire;
    REQUIRE(c.start(wire) == State::Handshaking);
    const wc::tls::test::ClientHelloGroups hello = wc::tls::test::parse_client_hello(wire);
    REQUIRE(hello.ok);
    CHECK(!hello.supported.empty());
    CHECK(!hello.key_shares.empty());
    const bool pq = std::any_of(hello.supported.begin(), hello.supported.end(), is_pq_group);
    CHECK(pq == wc::tls::post_quantum_available());
    MESSAGE("ClientHello ", wire.size(), " bytes; supported_groups: ", group_list(hello.supported),
            "; key_share: ", group_list(hello.key_shares));
}

TEST_CASE("info() is empty until the handshake completes") {
    ClientSession c(unique_name(), Verify::None);
    CHECK(c.info().protocol == 0);
    std::vector<char> wire;
    REQUIRE(c.start(wire) == State::Handshaking);
    const ClientSession::Info info = c.info();
    CHECK(info.protocol == 0);
    CHECK(info.cipher.empty());
    CHECK(info.key_exchange.empty());
    CHECK(info.group == 0);
    CHECK(!info.pq_hybrid);
    CHECK(!info.resumed);
}

TEST_CASE("info() reports the negotiated protocol, cipher and group") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        Harness h(proto, Verify::None, 0);
        h.handshake();
        REQUIRE(h.client.state() == State::Established);
        const ClientSession::Info info = checked_info(h, proto);
        CHECK(!info.resumed);
        MESSAGE(std::string(wc::tls::protocol_name(info.protocol)), " ", info.cipher, " ", info.key_exchange,
                " (machine offers PQ: ", wc::tls::post_quantum_available(), ")");
    }
}

TEST_CASE("info() follows the group the server is restricted to") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        ServerOptions options;
        // The server's own preference order decides, so leave it only secp256r1.
        options.disabled_key_exchange = {L"curve25519", L"ECDH_P384", L"X25519_MLKEM768", L"SecP256r1_MLKEM768",
                                         L"SecP384r1_MLKEM1024"};
        Harness h(proto, unique_name(), options);
        h.handshake();
        REQUIRE(h.client.state() == State::Established);
        const ClientSession::Info info = checked_info(h, proto);
        CHECK(info.group == 0x0017);
        CHECK(info.key_exchange == "secp256r1");
        CHECK(!info.pq_hybrid);
    }
}

TEST_CASE("TLS 1.3 negotiates a hybrid group when the server allows nothing else") {
    REQUIRE(wc::tls::startup());
    if (!wc::tls::post_quantum_available()) {
        MESSAGE("skipped: this machine's Schannel configuration offers no ML-KEM group (see docs/tls-notes.md)");
        return;
    }
    ServerOptions options;
    options.disabled_key_exchange = {L"curve25519", L"ECDH_P256", L"ECDH_P384"};
    Harness h(ServerProto::Tls13, unique_name(), options);
    h.handshake();
    REQUIRE(h.client.state() == State::Established);
    const ClientSession::Info info = checked_info(h, ServerProto::Tls13);
    CHECK(info.pq_hybrid);
    MESSAGE("hybrid group: ", info.key_exchange);
}

TEST_CASE("info().resumed after an abbreviated handshake") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        const std::string name = unique_name();
        Harness first(proto, name, ServerOptions{});
        first.handshake();
        REQUIRE(first.client.state() == State::Established);
        CHECK(!first.client.info().resumed);
        round_trip(first, std::vector<char>{'x'});  // lets the client take in a TLS 1.3 NewSessionTicket

        ServerOptions options;
        options.share_credential_with = &first.server;
        Harness second(proto, name, options);
        second.handshake();
        REQUIRE(second.client.state() == State::Established);
        const ClientSession::Info info = second.client.info();
        const wc::tls::test::ServerKeyExchange server = wc::tls::test::parse_server_flight(second.server_flight);
        CHECK(info.resumed);
        CHECK(info.protocol == expected_protocol(proto));
        if (proto == ServerProto::Tls13) {
            CHECK(server.psk);
            CHECK(info.group == server.group);  // PSK with (EC)DHE still runs a key exchange
        } else {
            // No key exchange on the wire; Schannel reports the resumed session's group.
            CHECK(server.group == 0);
            CHECK(info.group == first.client.info().group);
        }
        MESSAGE(std::string(wc::tls::protocol_name(info.protocol)), " resumed, group reported: ", info.key_exchange,
                " (wire: ", server.group, ")");
    }
}

TEST_CASE("handshake and application data, whole-buffer delivery") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        Harness h(proto, Verify::None, 0);
        h.handshake();
        REQUIRE(h.client.state() == State::Established);
        REQUIRE(h.server.established());
        CHECK(h.client.protocol() == expected_protocol(proto));
        CHECK(!h.client.info().cipher.empty());
        CHECK(h.client.failure() == Failure::None);

        round_trip(h, std::vector<char>{'h', 'i'});
        round_trip(h, random_bytes(100 * 1024 + 7, 42));  // spans several max-size records
    }
}

TEST_CASE("handshake with byte-at-a-time delivery in both directions") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        Harness h(proto, Verify::None, 1);
        h.handshake();
        REQUIRE(h.client.state() == State::Established);
        REQUIRE(h.server.established());
        CHECK(h.client.protocol() == expected_protocol(proto));
        round_trip(h, random_bytes(20000, 7));
    }
}

TEST_CASE("handshake and >16 KB payloads with random chunking") {
    for (unsigned seed = 1; seed <= 8; ++seed) {
        for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
            CAPTURE(seed);
            CAPTURE(static_cast<int>(proto));
            Harness h(proto, Verify::None, 1 + seed * 97, seed);
            h.handshake();
            REQUIRE(h.client.state() == State::Established);
            REQUIRE(h.server.established());
            round_trip(h, random_bytes(70000 + seed, seed));
            round_trip(h, random_bytes(1, seed));
        }
    }
}

TEST_CASE("application data in the same read as the final handshake flight") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        Harness h(proto, Verify::None, 0);
        REQUIRE(wc::tls::test::server_identity_ready());
        REQUIRE(h.client.start(h.c2s) == State::Handshaking);

        // Step the handshake manually until the server is established, then append
        // server application data to its last flight before the client sees it.
        std::vector<char> plain;
        for (int i = 0; i < 10 && !h.server.established(); ++i) {
            std::vector<char> to_server;
            to_server.swap(h.c2s);
            REQUIRE(h.server.feed(to_server.data(), to_server.size(), h.s2c, plain));
            if (h.server.established())
                break;
            std::vector<char> to_client;
            to_client.swap(h.s2c);
            h.client.feed(to_client.data(), to_client.size(), h.c2s, h.client_plain);
        }
        REQUIRE(h.server.established());
        const std::string msg = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        REQUIRE(h.server.encrypt(msg.data(), msg.size(), h.s2c));

        std::vector<char> to_client;
        to_client.swap(h.s2c);
        CHECK(h.client.feed(to_client.data(), to_client.size(), h.c2s, h.client_plain) == State::Established);
        CHECK(std::string(h.client_plain.begin(), h.client_plain.end()) == msg);
        CHECK(h.client.pending_input() == 0);
    }
}

TEST_CASE("close_notify from the server closes the session") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        Harness h(proto, Verify::None, 0);
        h.handshake();
        REQUIRE(h.client.state() == State::Established);

        // Data followed by close_notify in one read: the data must still be delivered.
        const std::string body = "last bytes before close";
        REQUIRE(h.server.encrypt(body.data(), body.size(), h.s2c));
        REQUIRE(h.server.shutdown(h.s2c));
        std::vector<char> to_client;
        to_client.swap(h.s2c);
        CHECK(h.client.feed(to_client.data(), to_client.size(), h.c2s, h.client_plain) == State::Closed);
        CHECK(std::string(h.client_plain.begin(), h.client_plain.end()) == body);

        // Further input is ignored, and the client can still answer with its own close_notify.
        CHECK(h.client.feed("xyz", 3, h.c2s, h.client_plain) == State::Closed);
        std::vector<char> close;
        CHECK(h.client.shutdown(close));
        CHECK(!close.empty());
        CHECK(!h.client.shutdown(close));
        CHECK(h.client.state() == State::Closed);
        CHECK(h.client.failure() == Failure::None);
    }
}

TEST_CASE("client close_notify reaches the server") {
    Harness h(ServerProto::Tls13, Verify::None, 0);
    h.handshake();
    REQUIRE(h.client.state() == State::Established);
    REQUIRE(h.client.shutdown(h.c2s));
    CHECK(h.client.state() == State::Closed);
    h.pump();
    CHECK(h.server.closed());
    std::vector<char> out;
    CHECK(!h.client.encrypt("x", 1, out));
    CHECK(h.client.state() == State::Closed);
    CHECK(out.empty());
}

TEST_CASE("Verify::Chain rejects a self-signed certificate") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        Harness h(proto, Verify::Chain, 0);
        h.handshake();
        CHECK(h.client.state() == State::Failed);
        CHECK(h.client.failure() == Failure::Certificate);
        CHECK(h.client.last_status() == CERT_E_UNTRUSTEDROOT);
        // The handshake itself completed, so what was negotiated is still reported.
        const ClientSession::Info info = h.client.info();
        CHECK(info.protocol == expected_protocol(proto));
        CHECK(!info.cipher.empty());
        CHECK(info.group == wc::tls::test::parse_server_flight(h.server_flight).group);
        CHECK(!info.key_exchange.empty());
        std::vector<char> out;
        CHECK(!h.client.encrypt("x", 1, out));
        CHECK(h.client.failure() == Failure::Certificate);  // misuse after failure keeps the original reason
    }
}

TEST_CASE("garbage input fails the session") {
    SUBCASE("plain HTTP instead of a ServerHello") {
        ClientSession c("localhost", Verify::None);
        std::vector<char> wire, plain;
        REQUIRE(c.start(wire) == State::Handshaking);
        const std::string reply = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        CHECK(c.feed(reply.data(), reply.size(), wire, plain) == State::Failed);
        CHECK(c.failure() == Failure::Handshake);
        CHECK(c.last_status() < 0);
        CHECK(plain.empty());
    }
    SUBCASE("corrupted record after the handshake") {
        Harness h(ServerProto::Tls13, Verify::None, 0);
        h.handshake();
        REQUIRE(h.client.state() == State::Established);
        const std::string msg(300, 'a');
        REQUIRE(h.server.encrypt(msg.data(), msg.size(), h.s2c));
        h.s2c[h.s2c.size() / 2] ^= 0x5a;
        std::vector<char> to_client;
        to_client.swap(h.s2c);
        CHECK(h.client.feed(to_client.data(), to_client.size(), h.c2s, h.client_plain) == State::Failed);
        CHECK(h.client.failure() == Failure::Record);
        CHECK(h.client_plain.empty());
    }
}

TEST_CASE("encrypt before the handshake completes is rejected") {
    ClientSession c("localhost", Verify::None);
    std::vector<char> wire;
    CHECK(!c.encrypt("x", 1, wire));
    CHECK(c.state() == State::Failed);
    CHECK(c.failure() == Failure::Misuse);
    CHECK(wire.empty());
}

TEST_CASE("many tiny feeds of one large record are buffered, not reprocessed") {
    Harness h(ServerProto::Tls13, Verify::None, 0);
    h.handshake();
    REQUIRE(h.client.state() == State::Established);
    const std::vector<char> payload = random_bytes(16 * 1024, 99);
    REQUIRE(h.server.encrypt(payload.data(), payload.size(), h.s2c));
    std::vector<char> to_client;
    to_client.swap(h.s2c);
    for (size_t i = 0; i + 1 < to_client.size(); ++i) {
        REQUIRE(h.client.feed(&to_client[i], 1, h.c2s, h.client_plain) == State::Established);
        REQUIRE(h.client.pending_input() == i + 1);
    }
    CHECK(h.client_plain.empty());
    CHECK(h.client.feed(&to_client.back(), 1, h.c2s, h.client_plain) == State::Established);
    CHECK(h.client_plain == payload);
    CHECK(h.client.pending_input() == 0);
}
