#include "net/udp.h"

#include "doctest/doctest.h"
#include "net/addr.h"
#include "net/tests/test_util.h"

#include <cstring>
#include <string>
#include <vector>

using namespace wc::net;
using wc::net::test::run_for;
using wc::net::test::run_until;

namespace {

const sockaddr_in kLoopbackAny = make_addr(htonl(INADDR_LOOPBACK), 0);

struct Echo : UdpHandler {
    size_t received = 0;
    void on_datagram(UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) override {
        ++received;
        socket.send_to(from, data, len);
    }
};

// Keeps a window of datagrams in flight so loopback buffers never overflow,
// which keeps the test deterministic.
struct Client : UdpHandler {
    Loop& loop;
    sockaddr_in server{};
    int total = 0;
    int window = 0;
    int sent = 0;
    int received = 0;
    bool content_ok = true;
    UdpSocket* socket = nullptr;

    Client(Loop& l, int total_, int window_) : loop(l), total(total_), window(window_) {}

    void send_next() {
        std::string payload = "seq=" + std::to_string(sent) + std::string(static_cast<size_t>(sent % 900), 'x');
        CHECK(socket->send_to(server, payload.data(), payload.size()));
        ++sent;
    }
    void start() {
        while (sent < total && sent - received < window) {
            send_next();
        }
    }
    void on_datagram(UdpSocket&, const char* data, size_t len, const sockaddr_in& from) override {
        content_ok = content_ok && from.sin_port == server.sin_port && len >= 4 && std::memcmp(data, "seq=", 4) == 0;
        if (++received == total) {
            loop.stop();
            return;
        }
        start();
    }
};

}  // namespace

TEST_CASE("UDP loopback echo of many datagrams") {
    Loop loop;
    Echo echo;
    UdpSocket server(loop, echo);
    REQUIRE(server.open(kLoopbackAny) == 0);
    CHECK(server.local_address().sin_port != 0);
    CHECK(server.local_address().sin_addr.s_addr == htonl(INADDR_LOOPBACK));

    Client client(loop, 5000, 64);
    UdpSocket client_socket(loop, client);
    REQUIRE(client_socket.open(kLoopbackAny, 4) == 0);
    client.socket = &client_socket;
    client.server = server.local_address();
    loop.post([&] { client.start(); });

    REQUIRE(run_for(loop, 4000));
    CHECK(client.received == 5000);
    CHECK(echo.received == 5000);
    CHECK(client.content_ok);

    server.close();
    client_socket.close();
    CHECK_FALSE(server.send_to(client.server, "x", 1));
    REQUIRE(run_until(loop, [&] { return !server.busy() && !client_socket.busy(); }, 2000));
}

TEST_CASE("UDP drops oversize datagrams and keeps receiving") {
    Loop loop;
    struct Sink : UdpHandler {
        std::vector<size_t> sizes;
        Loop* loop = nullptr;
        void on_datagram(UdpSocket&, const char*, size_t len, const sockaddr_in&) override {
            sizes.push_back(len);
            if (len == 3) {
                loop->stop();
            }
        }
    } sink;
    sink.loop = &loop;
    Echo unused;
    UdpSocket rx(loop, sink);
    UdpSocket tx(loop, unused);
    REQUIRE(rx.open(kLoopbackAny, 1) == 0);
    REQUIRE(tx.open(kLoopbackAny, 1) == 0);
    const std::vector<char> big(UdpSocket::kRecvBufferSize + 1, 'b');
    const std::vector<char> exact(UdpSocket::kRecvBufferSize, 'e');
    REQUIRE(tx.send_to(rx.local_address(), big.data(), big.size()));
    REQUIRE(tx.send_to(rx.local_address(), exact.data(), exact.size()));
    REQUIRE(tx.send_to(rx.local_address(), "end", 3));
    REQUIRE(run_for(loop, 2000));
    CHECK(sink.sizes == std::vector<size_t>{UdpSocket::kRecvBufferSize, 3});

    rx.close();
    tx.close();
    REQUIRE(run_until(loop, [&] { return !rx.busy() && !tx.busy(); }, 2000));
}

TEST_CASE("UDP ICMP port unreachable does not break receives") {
    Loop loop;
    Echo echo;
    struct Once : UdpHandler {
        Loop* loop = nullptr;
        int got = 0;
        void on_datagram(UdpSocket&, const char*, size_t, const sockaddr_in&) override {
            ++got;
            loop->stop();
        }
    } once;
    once.loop = &loop;

    // Reserve a port nobody listens on by binding and closing a socket.
    UdpSocket dead(loop, echo);
    REQUIRE(dead.open(kLoopbackAny, 1) == 0);
    const sockaddr_in dead_addr = dead.local_address();
    dead.close();

    UdpSocket server(loop, echo);
    UdpSocket client(loop, once);
    REQUIRE(server.open(kLoopbackAny) == 0);
    REQUIRE(client.open(kLoopbackAny) == 0);
    REQUIRE(client.send_to(dead_addr, "lost", 4));
    loop.add_timer(20, [&] { client.send_to(server.local_address(), "ping", 4); });
    REQUIRE(run_for(loop, 2000));
    CHECK(once.got == 1);

    server.close();
    client.close();
    REQUIRE(run_until(loop, [&] { return !dead.busy() && !server.busy() && !client.busy(); }, 2000));
}

TEST_CASE("UDP open reports bind errors") {
    Loop loop;
    Echo echo;
    UdpSocket s(loop, echo);
    // TEST-NET-3 is never a local address.
    CHECK(s.open(make_addr(htonl(0xCB007101), 0)) == WSAEADDRNOTAVAIL);
    CHECK_FALSE(s.busy());
    CHECK_FALSE(s.send_to(make_addr(htonl(INADDR_LOOPBACK), 9), "x", 1));
}
