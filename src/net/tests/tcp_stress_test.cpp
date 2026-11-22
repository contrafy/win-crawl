// Two loops on two threads drive ~2000 concurrent loopback connections doing
// one request/response each. The listener lives on loop 0 and hands accepted
// sockets to both loops, exercising adopt() onto a different completion port.

#include "net/tcp.h"

#include "doctest/doctest.h"
#include "net/addr.h"
#include "net/tests/test_util.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace wc::net;

namespace {

constexpr int kConnections = 2000;
constexpr size_t kMsg = 64;

std::atomic<int> g_clients_left{0};
std::atomic<int> g_servers_live{0};
std::atomic<int> g_failures{0};
std::atomic<int> g_port_retries{0};
std::array<Loop*, 2> g_loops{};
std::mutex g_failure_mutex;
std::string g_failure_log;  // first few failures, for diagnosis

void record_failure(const char* stage, DWORD error) {
    if (g_failures.fetch_add(1) < 8) {
        std::lock_guard lock(g_failure_mutex);
        g_failure_log += std::string(stage) + " error " + std::to_string(error) + "; ";
    }
}

// Done once every client has finished and every accepted connection has been
// torn down. A client whose connect failed never had a server side, so the
// two populations are counted separately.
void maybe_stop() {
    if (g_clients_left.load() == 0 && g_servers_live.load() == 0) {
        for (Loop* loop : g_loops) {
            loop->stop();
        }
    }
}

void client_finished() {
    g_clients_left.fetch_sub(1);
    maybe_stop();
}

void server_finished() {
    g_servers_live.fetch_sub(1);
    maybe_stop();
}

// The machine-wide ephemeral port range is shared with whatever else runs
// (other test processes, crawls); an explicit bind takes a unique port even
// with SO_REUSE_UNICASTPORT unless an auto-reuse range is configured. Port
// pressure is environmental, so the client backs off and retries instead.
bool is_port_pressure(DWORD error) {
    return error == WSAENOBUFS || error == WSAEADDRINUSE;
}

// Server side: read the request, echo it back, then wait for the client to
// go away (its abortive close arrives as an error or FIN) and self-destruct.
class ServerConn final : TcpHandler {
public:
    explicit ServerConn(Loop& loop) : socket_(loop, *this) {}

    void start(SOCKET s) {
        if (const DWORD err = socket_.adopt(s); err != 0) {
            fail("server adopt", err);
            return;
        }
        socket_.recv(buf_, sizeof(buf_));
    }

private:
    void on_connect(TcpSocket&, DWORD) override {}
    void on_send(TcpSocket& s, DWORD error) override {
        if (error != 0) {
            fail("server send", error);
            return;
        }
        s.recv(buf_, sizeof(buf_));
    }
    void on_recv(TcpSocket& s, size_t bytes, DWORD error) override {
        if (replied_) {
            s.close();
            if (!s.busy()) {
                delete this;
                server_finished();
            }
            return;
        }
        if (error != 0 || bytes == 0) {
            fail("server recv", error);
            return;
        }
        got_ += bytes;
        if (got_ < kMsg) {
            s.recv(buf_ + got_, sizeof(buf_) - got_);
            return;
        }
        replied_ = true;
        s.send(buf_, kMsg);
    }
    void fail(const char* stage, DWORD error) {
        record_failure(stage, error);
        socket_.close();
        if (!socket_.busy()) {
            delete this;
            server_finished();
        }
    }

    TcpSocket socket_;
    char buf_[kMsg];
    size_t got_ = 0;
    bool replied_ = false;
};

class ClientConn final : TcpHandler {
public:
    ClientConn(Loop& loop, int id) : socket_(loop, *this) {
        std::memset(request_, 'a' + id % 26, sizeof(request_));
        std::memcpy(request_, &id, sizeof(id));
    }

    void start(const sockaddr_in& server) {
        server_ = server;
        if (const DWORD err = socket_.open(); err != 0) {
            if (is_port_pressure(err) && retry_later()) {
                return;
            }
            fail("client open", err);
            return;
        }
        socket_.connect(server);
    }
    bool ok() const { return ok_; }
    bool busy() const { return socket_.busy(); }

private:
    void on_connect(TcpSocket& s, DWORD error) override {
        if (error != 0) {
            if (is_port_pressure(error) && retry_later()) {
                return;
            }
            fail("client connect", error);
            return;
        }
        s.send(request_, sizeof(request_));
    }
    void on_send(TcpSocket& s, DWORD error) override {
        if (error != 0) {
            fail("client send", error);
            return;
        }
        s.recv(response_, sizeof(response_));
    }
    void on_recv(TcpSocket& s, size_t bytes, DWORD error) override {
        if (error != 0 || bytes == 0) {
            fail("client recv", error);
            return;
        }
        got_ += bytes;
        if (got_ < kMsg) {
            s.recv(response_ + got_, sizeof(response_) - got_);
            return;
        }
        if (std::memcmp(request_, response_, kMsg) != 0) {
            fail("client compare", 0);
            return;
        }
        ok_ = true;
        finish();
    }
    bool retry_later() {
        if (++retries_ > 100) {  // ~1.5 s at the default 15.6 ms timer tick
            return false;
        }
        g_port_retries.fetch_add(1);
        socket_.close(true);
        socket_.loop().add_timer(5, [this] { start(server_); });
        return true;
    }
    void fail(const char* stage, DWORD error) {
        record_failure(stage, error);
        finish();
    }
    void finish() {
        socket_.close(true);  // RST: no TIME_WAIT left behind by thousands of runs
        client_finished();
    }

    TcpSocket socket_;
    sockaddr_in server_{};
    int retries_ = 0;
    char request_[kMsg];
    char response_[kMsg];
    size_t got_ = 0;
    bool ok_ = false;
};

}  // namespace

TEST_CASE("TCP stress: 2000 concurrent loopback request/response across two loops") {
    Loop loop0;
    Loop loop1;
    g_loops = {&loop0, &loop1};
    g_clients_left = kConnections;
    g_servers_live = 0;
    g_failures = 0;
    g_port_retries = 0;

    int accepted = 0;
    TcpListener listener(loop0, [&](SOCKET s) {
        Loop& target = *g_loops[static_cast<size_t>(accepted++ % 2)];
        g_servers_live.fetch_add(1);
        auto* conn = new ServerConn(target);
        if (&target == &loop0) {
            conn->start(s);
        } else {
            target.post([conn, s] { conn->start(s); });
        }
    });
    REQUIRE(listener.listen(make_addr(htonl(INADDR_LOOPBACK), 0), SOMAXCONN_HINT(kConnections), 256) == 0);
    const sockaddr_in server = listener.local_address();

    std::array<std::vector<std::unique_ptr<ClientConn>>, 2> clients;
    for (int i = 0; i < kConnections; ++i) {
        const size_t which = static_cast<size_t>(i % 2);
        clients[which].push_back(std::make_unique<ClientConn>(*g_loops[which], i));
    }

    const auto t0 = std::chrono::steady_clock::now();
    for (size_t which = 0; which < 2; ++which) {
        g_loops[which]->post([&, which] {
            for (auto& c : clients[which]) {
                c->start(server);
            }
        });
    }
    std::atomic<bool> loop1_timed_out{false};
    std::thread worker([&] { loop1_timed_out = !test::run_for(loop1, 4500); });
    const bool loop0_ok = test::run_for(loop0, 4500);
    loop1.stop();
    worker.join();
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    CHECK(loop0_ok);
    CHECK_FALSE(loop1_timed_out.load());
    CHECK(g_clients_left.load() == 0);
    CHECK(g_servers_live.load() == 0);
    CHECK_MESSAGE(g_failures.load() == 0, g_failure_log);
    CHECK(accepted == kConnections);
    int ok = 0;
    for (auto& per_loop : clients) {
        for (auto& c : per_loop) {
            ok += c->ok() ? 1 : 0;
        }
    }
    CHECK(ok == kConnections);
    MESSAGE(kConnections << " connections (connect + 64 B request/response + close) in " << seconds * 1000.0
                         << " ms = " << kConnections / seconds << " conn/s; port-pressure retries "
                         << g_port_retries.load());

    // Let aborted completions drain before anything is destroyed.
    listener.close();
    auto idle = [&](size_t which) {
        for (auto& c : clients[which]) {
            if (c->busy()) {
                return false;
            }
        }
        return which != 0 || !listener.busy();
    };
    REQUIRE(test::run_until(loop0, [&] { return idle(0); }, 2000));
    REQUIRE(test::run_until(loop1, [&] { return idle(1); }, 2000));
}
