#include "tls/tls.h"

#include "test_server.h"
#include "tls/sspi_include.h"

#include "doctest/doctest.h"

#include <algorithm>
#include <random>
#include <string>
#include <vector>

using wc::tls::ClientSession;
using wc::tls::Failure;
using wc::tls::Verify;
using wc::tls::test::Server;
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
    std::mt19937 rng;
    size_t max_chunk;

    Harness(ServerProto proto, Verify verify, size_t max_chunk_, unsigned seed = 1)
        : client(unique_name(), verify), server(proto), rng(seed), max_chunk(max_chunk_) {}

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

}  // namespace

TEST_CASE("startup is idempotent") {
    CHECK(wc::tls::startup());
    CHECK(wc::tls::startup());
}

TEST_CASE("handshake and application data, whole-buffer delivery") {
    for (ServerProto proto : {ServerProto::Tls13, ServerProto::Tls12}) {
        CAPTURE(static_cast<int>(proto));
        Harness h(proto, Verify::None, 0);
        h.handshake();
        REQUIRE(h.client.state() == State::Established);
        REQUIRE(h.server.established());
        CHECK(h.client.protocol() == expected_protocol(proto));
        CHECK(!h.client.cipher_suite().empty());
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
