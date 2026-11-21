#include "net/tcp.h"

#include "doctest/doctest.h"
#include "net/addr.h"
#include "net/tests/test_util.h"

#include <mstcpip.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

using namespace wc::net;
using wc::net::test::run_for;
using wc::net::test::run_until;

namespace {

// Handler whose callbacks are lambdas, so each test reads top to bottom.
struct Callbacks : TcpHandler {
    std::function<void(TcpSocket&, DWORD)> connect;
    std::function<void(TcpSocket&, DWORD)> send;
    std::function<void(TcpSocket&, size_t, DWORD)> recv;
    void on_connect(TcpSocket& s, DWORD error) override { connect(s, error); }
    void on_send(TcpSocket& s, DWORD error) override { send(s, error); }
    void on_recv(TcpSocket& s, size_t bytes, DWORD error) override { recv(s, bytes, error); }
};

sockaddr_in loopback(uint32_t host = INADDR_LOOPBACK) {
    return make_addr(htonl(host), 0);
}

// Accepted sockets are adopted on the same loop into `server`.
struct OneShotServer {
    Callbacks handler;
    TcpSocket socket;
    TcpListener listener;
    bool accepted = false;

    explicit OneShotServer(Loop& loop)
        : socket(loop, handler), listener(loop, [this](SOCKET s) {
              accepted = true;
              REQUIRE(socket.adopt(s) == 0);
              on_accepted();
          }) {}
    std::function<void()> on_accepted = [] {};
};

void drain(Loop& loop, const std::vector<const TcpSocket*>& sockets, TcpListener* listener) {
    if (listener != nullptr) {
        listener->close();
    }
    REQUIRE(run_until(
        loop,
        [&] {
            for (const TcpSocket* s : sockets) {
                if (s->busy()) {
                    return false;
                }
            }
            return listener == nullptr || !listener->busy();
        },
        2000));
}

}  // namespace

TEST_CASE("TCP connect, request/response and FIN on loopback") {
    Loop loop;
    OneShotServer server(loop);
    REQUIRE(server.listener.listen(loopback(), SOMAXCONN, 4) == 0);
    const sockaddr_in server_addr = server.listener.local_address();
    REQUIRE(server_addr.sin_port != 0);

    char server_buf[64];
    char client_buf[64];
    std::string server_got;
    std::string client_got;
    bool client_saw_fin = false;
    bool peer_name_ok = false;

    server.on_accepted = [&] {
        sockaddr_in peer{};
        int len = sizeof(peer);
        peer_name_ok = getpeername(server.socket.native_handle(), reinterpret_cast<sockaddr*>(&peer), &len) == 0 &&
                       peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
        server.socket.recv(server_buf, sizeof(server_buf));
    };
    server.handler.recv = [&](TcpSocket& s, size_t bytes, DWORD error) {
        REQUIRE(error == 0);
        server_got.assign(server_buf, bytes);
        s.send("world", 5);
    };
    server.handler.send = [&](TcpSocket& s, DWORD error) {
        CHECK(error == 0);
        s.close(false);  // graceful: the client must see data, then FIN
    };

    Callbacks ch;
    TcpSocket client(loop, ch);
    ch.connect = [&](TcpSocket& s, DWORD error) {
        REQUIRE(error == 0);
        s.send("hello", 5);
    };
    ch.send = [&](TcpSocket& s, DWORD error) {
        CHECK(error == 0);
        s.recv(client_buf, sizeof(client_buf));
    };
    ch.recv = [&](TcpSocket& s, size_t bytes, DWORD error) {
        REQUIRE(error == 0);
        if (bytes == 0) {
            client_saw_fin = true;
            loop.stop();
            return;
        }
        client_got.append(client_buf, bytes);
        s.recv(client_buf, sizeof(client_buf));
    };
    REQUIRE(client.open() == 0);
    client.connect(server_addr);

    REQUIRE(run_for(loop, 3000));
    CHECK(server.accepted);
    CHECK(peer_name_ok);
    CHECK(server_got == "hello");
    CHECK(client_got == "world");
    CHECK(client_saw_fin);
    client.close();
    drain(loop, {&client, &server.socket}, &server.listener);
}

TEST_CASE("TCP multi-megabyte transfer in a single send") {
    Loop loop;
    OneShotServer server(loop);
    REQUIRE(server.listener.listen(loopback(), SOMAXCONN, 1) == 0);

    constexpr size_t kSize = (size_t{8} << 20) + 12345;  // several send slices plus a ragged tail
    std::vector<char> payload(kSize);
    for (size_t i = 0; i < kSize; ++i) {
        payload[i] = static_cast<char>((i * 31) ^ (i >> 13));
    }
    std::vector<char> rx(64 * 1024);
    size_t received = 0;
    bool intact = true;
    int send_callbacks = 0;

    server.on_accepted = [&] { server.socket.recv(rx.data(), rx.size()); };
    server.handler.recv = [&](TcpSocket& s, size_t bytes, DWORD error) {
        REQUIRE(error == 0);
        REQUIRE(bytes > 0);
        intact = intact && std::equal(rx.begin(), rx.begin() + static_cast<ptrdiff_t>(bytes),
                                      payload.begin() + static_cast<ptrdiff_t>(received));
        received += bytes;
        if (received == kSize) {
            loop.stop();
        } else {
            s.recv(rx.data(), rx.size());
        }
    };

    Callbacks ch;
    TcpSocket client(loop, ch);
    ch.connect = [&](TcpSocket& s, DWORD error) {
        REQUIRE(error == 0);
        s.send(payload.data(), payload.size());
    };
    ch.send = [&](TcpSocket&, DWORD error) {
        CHECK(error == 0);
        ++send_callbacks;
    };
    REQUIRE(client.open() == 0);
    client.connect(server.listener.local_address());

    REQUIRE(run_for(loop, 4000));
    // The final slice's completion may still be queued when the receiver finishes.
    REQUIRE(run_until(loop, [&] { return send_callbacks == 1; }, 2000));
    CHECK(received == kSize);
    CHECK(intact);
    client.close();
    server.socket.close();
    drain(loop, {&client, &server.socket}, &server.listener);
}

TEST_CASE("TCP connect to a closed port fails with WSAECONNREFUSED") {
    Loop loop;
    // A bound but non-listening socket reserves a port that answers SYN with RST.
    SOCKET reserve = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(reserve != INVALID_SOCKET);
    sockaddr_in addr = loopback();
    REQUIRE(bind(reserve, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
    int len = sizeof(addr);
    REQUIRE(getsockname(reserve, reinterpret_cast<sockaddr*>(&addr), &len) == 0);

    Callbacks ch;
    TcpSocket client(loop, ch);
    DWORD result = 0;
    int calls = 0;
    ch.connect = [&](TcpSocket&, DWORD error) {
        result = error;
        ++calls;
        loop.stop();
    };
    REQUIRE(client.open() == 0);
    // Windows retries a refused SYN by default (~2 s on loopback); drop the
    // retries so the test stays fast. Not something TcpSocket does itself.
    TCP_INITIAL_RTO_PARAMETERS rto{TCP_INITIAL_RTO_UNSPECIFIED_RTT, TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS};
    DWORD bytes = 0;
    WSAIoctl(client.native_handle(), SIO_TCP_INITIAL_RTO, &rto, sizeof(rto), nullptr, 0, &bytes, nullptr, nullptr);
    client.connect(addr);
    CHECK(calls == 0);  // never inline
    REQUIRE(run_for(loop, 4000));
    CHECK(calls == 1);
    CHECK(result == WSAECONNREFUSED);
    closesocket(reserve);
}

TEST_CASE("TCP close() with a pending recv reports ERROR_OPERATION_ABORTED once") {
    Loop loop;
    OneShotServer server(loop);
    REQUIRE(server.listener.listen(loopback(), SOMAXCONN, 1) == 0);
    server.on_accepted = [] {};

    Callbacks ch;
    auto client = std::make_unique<TcpSocket>(loop, ch);
    char buf[16];
    int recv_calls = 0;
    DWORD recv_error = 0;
    ch.connect = [&](TcpSocket& s, DWORD error) {
        REQUIRE(error == 0);
        s.recv(buf, sizeof(buf));
        CHECK(s.busy());
        loop.add_timer(5, [&] { client->close(); });
    };
    ch.recv = [&](TcpSocket& s, size_t bytes, DWORD error) {
        ++recv_calls;
        recv_error = error;
        CHECK(bytes == 0);
        CHECK_FALSE(s.busy());
        client.reset();  // destroying from inside the callback is allowed once !busy()
        loop.add_timer(30, [&] { loop.stop(); });
    };
    REQUIRE(client->open() == 0);
    client->connect(server.listener.local_address());
    REQUIRE(run_for(loop, 3000));
    CHECK(recv_calls == 1);
    CHECK(recv_error == ERROR_OPERATION_ABORTED);
    CHECK(client == nullptr);
    server.socket.close();
    drain(loop, {&server.socket}, &server.listener);
}

TEST_CASE("TCP close() right after connect() reports the connect aborted") {
    Loop loop;
    OneShotServer server(loop);
    REQUIRE(server.listener.listen(loopback(), SOMAXCONN, 1) == 0);
    Callbacks ch;
    TcpSocket client(loop, ch);
    int calls = 0;
    DWORD result = 0;
    ch.connect = [&](TcpSocket&, DWORD error) {
        ++calls;
        result = error;
        loop.stop();
    };
    REQUIRE(client.open() == 0);
    client.connect(server.listener.local_address());
    client.close();
    CHECK(client.busy());
    REQUIRE(run_for(loop, 2000));
    CHECK(calls == 1);
    CHECK(result == ERROR_OPERATION_ABORTED);
    CHECK_FALSE(client.busy());
    server.socket.close();
    drain(loop, {&client, &server.socket}, &server.listener);
}

TEST_CASE("TCP operations on an unopened socket fail asynchronously") {
    Loop loop;
    Callbacks ch;
    TcpSocket s(loop, ch);
    std::vector<std::string> events;
    ch.connect = [&](TcpSocket&, DWORD error) { events.push_back("connect " + std::to_string(error)); };
    ch.recv = [&](TcpSocket&, size_t, DWORD error) { events.push_back("recv " + std::to_string(error)); };
    char buf[4];
    s.connect(make_addr(htonl(INADDR_LOOPBACK), 9));
    s.recv(buf, sizeof(buf));
    CHECK(events.empty());
    CHECK(s.busy());
    REQUIRE(run_until(loop, [&] { return !s.busy(); }, 2000));
    CHECK(events == std::vector<std::string>{"connect 10038", "recv 10038"});  // WSAENOTSOCK
}

TEST_CASE("TCP open() binds the wildcard address; connect fixes the local endpoint") {
    Loop loop;
    OneShotServer server(loop);
    REQUIRE(server.listener.listen(loopback(), SOMAXCONN, 1) == 0);
    Callbacks ch;
    TcpSocket client(loop, ch);
    REQUIRE(client.open() == 0);
    REQUIRE(client.is_open());

    // SO_REUSE_UNICASTPORT always reads back 0 on Windows 11 (even on
    // implicitly bound sockets, where it is documented as on), so the option
    // itself is not observable here.
    sockaddr_in local{};
    int len = sizeof(local);
    REQUIRE(getsockname(client.native_handle(), reinterpret_cast<sockaddr*>(&local), &len) == 0);
    CHECK(local.sin_addr.s_addr == INADDR_ANY);

    ch.connect = [&](TcpSocket& s, DWORD error) {
        REQUIRE(error == 0);
        sockaddr_in bound{};
        int n = sizeof(bound);
        REQUIRE(getsockname(s.native_handle(), reinterpret_cast<sockaddr*>(&bound), &n) == 0);
        CHECK(bound.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        CHECK(bound.sin_port != 0);
        loop.stop();
    };
    client.connect(server.listener.local_address());
    REQUIRE(run_for(loop, 2000));
    client.close();
    server.socket.close();
    drain(loop, {&client, &server.socket}, &server.listener);
}

TEST_CASE("TCP loopback aliases: 127.0.0.2 is reachable") {
    Loop loop;
    OneShotServer server(loop);
    REQUIRE(server.listener.listen(loopback(0x7f000002), SOMAXCONN, 1) == 0);
    sockaddr_in local_of_accepted{};
    server.on_accepted = [&] {
        int len = sizeof(local_of_accepted);
        getsockname(server.socket.native_handle(), reinterpret_cast<sockaddr*>(&local_of_accepted), &len);
        loop.stop();
    };
    Callbacks ch;
    TcpSocket client(loop, ch);
    DWORD result = ~DWORD{0};
    ch.connect = [&](TcpSocket&, DWORD error) { result = error; };
    REQUIRE(client.open() == 0);
    client.connect(server.listener.local_address());
    REQUIRE(run_for(loop, 2000));
    REQUIRE(run_until(loop, [&] { return !client.busy(); }, 2000));
    CHECK(result == 0);
    CHECK(local_of_accepted.sin_addr.s_addr == htonl(0x7f000002));
    client.close();
    server.socket.close();
    drain(loop, {&client, &server.socket}, &server.listener);
}
