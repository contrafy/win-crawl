#pragma once
// In-process fake DNS and HTTP servers for the crawl end-to-end tests. They run
// on their own Loop thread so the engine under test owns its loops unchanged.
// Configure (records, routes, listeners) before the client starts; counters
// are safe to read from any thread. Destroy the servers before their thread.

#include "net/loop.h"
#include "net/tcp.h"
#include "net/udp.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace wc::crawl::test {

// 127.0.0.<n> in network byte order.
uint32_t loopback_ip(uint8_t n);

// Runs `loop` on the calling thread until `done()` holds (checked every 1 ms).
// False if `timeout_ms` passed first.
bool run_until(net::Loop& loop, const std::function<bool()>& done, uint32_t timeout_ms);

// A Loop running on a background thread.
class ServerThread {
public:
    ServerThread();
    ~ServerThread();
    ServerThread(const ServerThread&) = delete;
    ServerThread& operator=(const ServerThread&) = delete;

    net::Loop& loop() { return loop_; }
    // Runs `fn` on the loop thread and waits for it.
    void call(const std::function<void()>& fn);
    // Calls `busy` on the loop thread until it returns false.
    void wait_idle(const std::function<bool()>& busy);

private:
    net::Loop loop_;
    std::thread thread_;
};

class FakeDns final : private net::UdpHandler {
public:
    explicit FakeDns(ServerThread& thread);
    ~FakeDns();

    void add(const std::string& host, uint32_t ipv4_be);  // A record; other names get NXDOMAIN
    // HTTPS record (type 65) with this raw RDATA for a name added with add();
    // names without one answer HTTPS queries with NODATA.
    void add_https(const std::string& host, std::string rdata);

    // Binds 127.0.0.1:0; returns the bound port (host order).
    uint16_t start();
    uint64_t queries() const { return queries_.load(); }

private:
    void on_datagram(net::UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) override;

    ServerThread& thread_;
    std::unique_ptr<net::UdpSocket> socket_;
    std::map<std::string, uint32_t> records_;
    std::map<std::string, std::string> https_;
    std::atomic<uint64_t> queries_{0};
};

struct Route {
    std::string response;      // full raw reply (status line onwards)
    uint32_t delay_ms = 0;     // wait before replying
    bool hang = false;         // never reply
    bool close_after = false;  // close the connection after this reply
};

// "HTTP/1.1 <status> X" + Content-Length + `extra_headers` (CRLF-terminated
// lines) + optional "Connection: close" + body.
std::string reply(int status, std::string_view body, std::string_view extra_headers = {}, bool close = false);
std::string chunked_reply(int status, const std::vector<std::string>& chunks, std::string_view extra_headers = {});

class FakeHttp {
public:
    explicit FakeHttp(ServerThread& thread);
    ~FakeHttp();

    // Listens on ip:0 and returns the port (host order).
    uint16_t listen(uint32_t ipv4_be);
    // Routes by the Host header's host (lowercase, port stripped) and path.
    // Unrouted requests get an empty 404.
    void route(const std::string& host, const std::string& path, Route r);

    uint64_t accepts(uint32_t ipv4_be) const;
    uint64_t requests(const std::string& host, const std::string& path) const;
    uint64_t total_requests() const { return total_requests_.load(); }

    class Conn;

private:
    friend class Conn;
    struct Listener;
    const Route* find(const std::string& host, const std::string& path) const;
    void count(const std::string& host, const std::string& path);

    ServerThread& thread_;
    std::vector<std::unique_ptr<Listener>> listeners_;
    std::vector<std::unique_ptr<Conn>> conns_;
    std::map<std::string, Route> routes_;  // key: host + ' ' + path
    mutable std::mutex mutex_;
    std::map<std::string, uint64_t> hits_;
    std::atomic<uint64_t> total_requests_{0};
};

}  // namespace wc::crawl::test
