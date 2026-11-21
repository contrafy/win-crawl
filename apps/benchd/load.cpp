#include "load.h"

#include "benchsrv/behavior.h"
#include "cpu_meter.h"
#include "net/addr.h"
#include "net/loop.h"
#include "net/tcp.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

namespace wc::benchd {

namespace {

constexpr size_t kBuffer = 64 * 1024;

void bump(std::atomic<uint64_t>& counter, uint64_t by = 1) {
    counter.store(counter.load(std::memory_order_relaxed) + by, std::memory_order_relaxed);
}

// Case-insensitive search for `needle` (lowercase) in `hay`.
const char* find_ci(const char* hay, size_t len, std::string_view needle) {
    for (size_t i = 0; i + needle.size() <= len; ++i) {
        size_t j = 0;
        while (j < needle.size()) {
            char c = hay[i + j];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            if (c != needle[j]) break;
            ++j;
        }
        if (j == needle.size()) return hay + i;
    }
    return nullptr;
}

class LoadWorker;

class Client final : public net::TcpHandler {
public:
    Client(LoadWorker& worker, net::Loop& loop, uint64_t first_host)
        : worker_(worker), socket_(loop, *this), buf_(new char[kBuffer]), host_(first_host) {
        request_.reserve(256);
    }

    void start();
    void stop() {
        if (socket_.is_open()) socket_.close(true);
    }
    bool busy() const { return socket_.busy(); }

    void on_connect(net::TcpSocket&, DWORD error) override;
    void on_send(net::TcpSocket&, DWORD error) override;
    void on_recv(net::TcpSocket&, size_t bytes, DWORD error) override;

private:
    void send_request();
    void complete();
    void fail();
    void update_tail(const char* data, size_t len);

    LoadWorker& worker_;
    net::TcpSocket socket_;
    std::unique_ptr<char[]> buf_;
    std::string request_;
    uint64_t host_;
    size_t have_ = 0;  // header bytes buffered
    bool header_done_ = false;
    bool chunked_ = false;
    uint64_t content_length_ = 0;
    uint64_t body_have_ = 0;
    uint64_t response_bytes_ = 0;
    char tail_[7] = {};
};

class LoadWorker {
public:
    LoadWorker(const LoadOptions& options, uint32_t index, uint32_t clients) : options_(options) {
        for (uint32_t i = 0; i < clients; ++i) {
            clients_.push_back(std::make_unique<Client>(*this, loop_, (static_cast<uint64_t>(index) << 32) + i * 7919));
        }
    }

    net::Loop& loop() { return loop_; }
    const LoadOptions& options() const { return options_; }
    bool stopping() const { return stopping_; }

    void start_all() {
        for (auto& c : clients_) c->start();
    }

    void shutdown() {
        stopping_ = true;
        for (auto& c : clients_) c->stop();
        drain();
    }

    struct Stats {
        std::atomic<uint64_t> responses{0}, bytes{0}, errors{0}, connects{0};
    } stats;

    uint64_t next_host() { return host_counter_++; }

private:
    void drain() {
        for (auto& c : clients_) {
            if (c->busy()) {
                loop_.add_timer(1, [this] { drain(); });
                return;
            }
        }
        loop_.stop();
    }

    const LoadOptions& options_;
    net::Loop loop_;
    std::vector<std::unique_ptr<Client>> clients_;
    bool stopping_ = false;
    uint64_t host_counter_ = 0;
};

void Client::start() {
    if (worker_.stopping()) return;
    const LoadOptions& o = worker_.options();
    if (socket_.open() != 0) {
        // Typically WSAENOBUFS: the machine ran out of ephemeral ports. Retry later.
        bump(worker_.stats.errors);
        worker_.loop().add_timer(50, [this] { start(); });
        return;
    }
    sockaddr_in to = o.target;
    if (o.spread_ips) to.sin_addr.s_addr = benchsrv::host_unique_ip(host_ % o.hosts);
    bump(worker_.stats.connects);
    socket_.connect(to);
}

void Client::send_request() {
    const LoadOptions& o = worker_.options();
    char line[192];
    std::snprintf(line, sizeof(line), "%s %s HTTP/1.1\r\nHost: h%llu.%s\r\nUser-Agent: wincrawl-benchd-load\r\n",
                  o.head ? "HEAD" : "GET", o.path.c_str(), static_cast<unsigned long long>(host_ % o.hosts),
                  o.zone.c_str());
    request_.assign(line);
    if (o.close) request_ += "Connection: close\r\n";
    request_ += "\r\n";
    have_ = 0;
    header_done_ = false;
    body_have_ = 0;
    response_bytes_ = 0;
    std::memset(tail_, 0, sizeof(tail_));
    socket_.send(request_.data(), request_.size());
}

void Client::on_connect(net::TcpSocket&, DWORD error) {
    if (worker_.stopping()) return;
    if (error != 0) {
        fail();
        return;
    }
    send_request();
}

void Client::on_send(net::TcpSocket&, DWORD error) {
    if (worker_.stopping()) return;
    if (error != 0) {
        fail();
        return;
    }
    socket_.recv(buf_.get(), kBuffer);
}

void Client::update_tail(const char* data, size_t len) {
    constexpr size_t n = sizeof(tail_);
    if (len >= n) {
        std::memcpy(tail_, data + len - n, n);
    } else {
        std::memmove(tail_, tail_ + len, n - len);
        std::memcpy(tail_ + n - len, data, len);
    }
}

void Client::on_recv(net::TcpSocket&, size_t bytes, DWORD error) {
    if (worker_.stopping()) return;
    if (error != 0 || bytes == 0) {
        fail();
        return;
    }
    response_bytes_ += bytes;
    const LoadOptions& o = worker_.options();
    if (!header_done_) {
        have_ += bytes;
        const char* end = find_ci(buf_.get(), have_, "\r\n\r\n");
        if (end == nullptr) {
            if (have_ == kBuffer) {
                fail();
                return;
            }
            socket_.recv(buf_.get() + have_, kBuffer - have_);
            return;
        }
        header_done_ = true;
        const size_t head_len = static_cast<size_t>(end - buf_.get()) + 4;
        if (o.head) {
            complete();
            return;
        }
        chunked_ = find_ci(buf_.get(), head_len, "transfer-encoding: chunked") != nullptr;
        content_length_ = 0;
        if (const char* cl = find_ci(buf_.get(), head_len, "content-length:")) {
            content_length_ = std::strtoull(cl + 15, nullptr, 10);
        }
        body_have_ = have_ - head_len;
        update_tail(buf_.get() + head_len, body_have_);
    } else {
        body_have_ += bytes;
        update_tail(buf_.get(), bytes);
    }
    const bool done = chunked_ ? std::memcmp(tail_, "\r\n0\r\n\r\n", 7) == 0 : body_have_ >= content_length_;
    if (done) {
        complete();
        return;
    }
    socket_.recv(buf_.get(), kBuffer);
}

void Client::complete() {
    bump(worker_.stats.responses);
    bump(worker_.stats.bytes, response_bytes_);
    host_ = worker_.next_host() * 104729 + host_;
    if (worker_.options().close) {
        socket_.close(true);  // RST: neither side keeps TIME_WAIT
        start();
        return;
    }
    send_request();
}

void Client::fail() {
    bump(worker_.stats.errors);
    socket_.close(true);
    // One operation at a time, so nothing is outstanding now; back off briefly
    // so a missing server does not turn into a busy reconnect loop.
    worker_.loop().add_timer(10, [this] { start(); });
}

}  // namespace

int run_load(const LoadOptions& options) {
    net::startup();
    const uint32_t threads = options.threads == 0 ? 1 : options.threads;
    std::vector<std::unique_ptr<LoadWorker>> workers;
    for (uint32_t t = 0; t < threads; ++t) {
        const uint32_t clients = options.connections / threads + (t < options.connections % threads ? 1 : 0);
        workers.push_back(std::make_unique<LoadWorker>(options, t, clients));
    }
    std::printf("load: %u connections on %u threads -> %s %s%s%s for %u s\n", options.connections, threads,
                net::to_string(options.target).c_str(), options.head ? "HEAD " : "GET ", options.path.c_str(),
                options.close ? " (Connection: close)" : " (keep-alive)", options.duration_s);
    std::vector<std::thread> pool;
    for (auto& w : workers) {
        LoadWorker* wp = w.get();
        wp->loop().post([wp] { wp->start_all(); });
        pool.emplace_back([wp] { wp->loop().run(); });
    }

    auto totals = [&] {
        uint64_t r = 0, b = 0, e = 0, c = 0;
        for (auto& w : workers) {
            r += w->stats.responses.load(std::memory_order_relaxed);
            b += w->stats.bytes.load(std::memory_order_relaxed);
            e += w->stats.errors.load(std::memory_order_relaxed);
            c += w->stats.connects.load(std::memory_order_relaxed);
        }
        return std::array<uint64_t, 4>{r, b, e, c};
    };

    CpuMeter cpu;
    const auto t0 = std::chrono::steady_clock::now();
    auto last = t0;
    auto prev = totals();
    const auto end = t0 + std::chrono::seconds(options.duration_s);
    while (std::chrono::steady_clock::now() < end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(options.stats_interval_ms));
        const auto now = std::chrono::steady_clock::now();
        const auto cur = totals();
        const double dt = std::chrono::duration<double>(now - last).count();
        std::printf("[%5.1fs] %9.0f resp/s %8.1f Mbit/s %7.0f conn/s  errors %llu  cpu %.0f%%\n",
                    std::chrono::duration<double>(now - t0).count(), (cur[0] - prev[0]) / dt,
                    (cur[1] - prev[1]) * 8.0 / dt / 1e6, (cur[3] - prev[3]) / dt,
                    static_cast<unsigned long long>(cur[2]), cpu.sample_percent());
        std::fflush(stdout);
        prev = cur;
        last = now;
    }
    const auto final_totals = totals();
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    for (auto& w : workers) {
        LoadWorker* wp = w.get();
        wp->loop().post([wp] { wp->shutdown(); });
    }
    for (auto& t : pool) t.join();
    std::printf("load total: %llu responses in %.1f s = %.0f resp/s, %.1f MB, %llu errors, %llu connects\n",
                static_cast<unsigned long long>(final_totals[0]), elapsed, final_totals[0] / elapsed,
                final_totals[1] / 1e6, static_cast<unsigned long long>(final_totals[2]),
                static_cast<unsigned long long>(final_totals[3]));
    return 0;
}

}  // namespace wc::benchd
