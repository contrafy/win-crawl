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
#include <thread>
#include <vector>

using namespace wc::net;

namespace {

constexpr int kConnections = 2000;
constexpr size_t kMsg = 64;

std::atomic<int> g_outstanding{0};
std::atomic<int> g_failures{0};
std::array<Loop*, 2> g_loops{};

void finish_one() {
    if (g_outstanding.fetch_sub(1) == 1) {
        for (Loop* loop : g_loops) {
            loop->stop();
        }
    }
}

// Server side: read the request, echo it back, then wait for the client to
// go away (its abortive close arrives as an error or FIN) and self-destruct.
class ServerConn : TcpHandler {
public:
    explicit ServerConn(Loop& loop) : socket_(loop, *this) {}

    void start(SOCKET s) {
        if (socket_.adopt(s) != 0) {
            fail();
            return;
        }
        socket_.recv(buf_, sizeof(buf_));
    }

private:
    void on_connect(TcpSocket&, DWORD) override {}
    void on_send(TcpSocket& s, DWORD error) override {
        if (error != 0) {
            fail();
            return;
        }
        s.recv(buf_, sizeof(buf_));
    }
    void on_recv(TcpSocket& s, size_t bytes, DWORD error) override {
        if (replied_) {
            s.close();
            if (!s.busy()) {
                delete this;
                finish_one();
            }
            return;
        }
        if (error != 0 || bytes == 0) {
            fail();
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
    void fail() {
        g_failures.fetch_add(1);
        socket_.close();
        if (!socket_.busy()) {
            delete this;
            finish_one();
        }
    }

    TcpSocket socket_;
    char buf_[kMsg];
    size_t got_ = 0;
    bool replied_ = false;
};

class ClientConn : TcpHandler {
public:
    ClientConn(Loop& loop, int id) : socket_(loop, *this) {
        std::memset(request_, 'a' + id % 26, sizeof(request_));
        std::memcpy(request_, &id, sizeof(id));
    }

    void start(const sockaddr_in& server) {
        if (socket_.open() != 0) {
            done(false);
            return;
        }
        socket_.connect(server);
    }
    bool ok() const { return ok_; }
    bool busy() const { return socket_.busy(); }

private:
    void on_connect(TcpSocket& s, DWORD error) override {
        if (error != 0) {
            done(false);
            return;
        }
        s.send(request_, sizeof(request_));
    }
    void on_send(TcpSocket& s, DWORD error) override {
        if (error != 0) {
            done(false);
            return;
        }
        s.recv(response_, sizeof(response_));
    }
    void on_recv(TcpSocket& s, size_t bytes, DWORD error) override {
        if (error != 0 || bytes == 0) {
            done(false);
            return;
        }
        got_ += bytes;
        if (got_ < kMsg) {
            s.recv(response_ + got_, sizeof(response_) - got_);
            return;
        }
        done(std::memcmp(request_, response_, kMsg) == 0);
    }
    void done(bool ok) {
        ok_ = ok;
        if (!ok) {
            g_failures.fetch_add(1);
        }
        socket_.close(true);  // RST: no TIME_WAIT left behind by thousands of runs
        finish_one();
    }

    TcpSocket socket_;
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
    g_outstanding = 2 * kConnections;  // every client and every server connection
    g_failures = 0;

    int accepted = 0;
    TcpListener listener(loop0, [&](SOCKET s) {
        Loop& target = *g_loops[static_cast<size_t>(accepted++ % 2)];
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
    CHECK(g_outstanding.load() == 0);
    CHECK(g_failures.load() == 0);
    CHECK(accepted == kConnections);
    int ok = 0;
    for (auto& per_loop : clients) {
        for (auto& c : per_loop) {
            ok += c->ok() ? 1 : 0;
        }
    }
    CHECK(ok == kConnections);
    MESSAGE(kConnections << " connections (connect + 64 B request/response + close) in " << seconds * 1000.0
                         << " ms = " << kConnections / seconds << " conn/s");

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
