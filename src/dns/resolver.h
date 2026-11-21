#pragma once
// Asynchronous stub resolver for A records over UDP, one per net::Loop.
//
// Every method is loop-thread only, including construction. Callbacks always
// run later on the loop thread, never inside resolve(). No TCP fallback: a
// truncated (TC) reply resolves as NoAnswer.
//
// Lifetime: call shutdown(), keep running the loop until busy() is false, then
// destroy. Callbacks must not destroy the Resolver.

#include "dns/packet.h"
#include "net/loop.h"
#include "net/udp.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace wc::dns {

enum class Status : uint8_t {
    Ok,        // ipv4_be holds the first A record
    NxDomain,  // authoritative "no such name"
    NoAnswer,  // NOERROR without a usable A record, or a truncated reply
    ServFail,  // SERVFAIL/REFUSED/other rcode on every attempt, or no usable socket/servers
    Timeout,   // no reply within attempts * timeout_ms, or cancelled by shutdown()
    Invalid,   // host is not a valid DNS name
};

const char* status_name(Status status);

struct ResolverConfig {
    std::vector<sockaddr_in> servers;  // empty: system_dns_servers()
    uint32_t timeout_ms = 1500;        // per attempt
    uint32_t attempts = 3;             // total sends per query, rotating servers
    uint32_t max_inflight = 512;       // further requests wait in a FIFO; clamped to [1, 32768]
};

class Resolver final : private net::UdpHandler {
public:
    using Callback = std::function<void(Status status, uint32_t ipv4_be)>;

    struct Counters {
        uint64_t queries_sent = 0;      // datagrams sent, retries included
        uint64_t retries = 0;           // attempts after the first
        uint64_t attempt_timeouts = 0;  // attempts that expired without a reply
        uint64_t send_errors = 0;
        uint64_t ok = 0;
        uint64_t nxdomain = 0;
        uint64_t noanswer = 0;
        uint64_t servfail = 0;
        uint64_t timeouts = 0;   // queries that exhausted all attempts
        uint64_t truncated = 0;  // TC replies (included in noanswer; no TCP fallback)
        uint64_t cancelled = 0;  // failed by shutdown()
        uint64_t invalid = 0;
        uint64_t literals = 0;    // IPv4 literals answered without a query
        uint64_t late = 0;        // replies whose txid is no longer in flight
        uint64_t mismatched = 0;  // other well-formed rejects: source, QR, question
        uint64_t malformed = 0;   // replies that failed to parse
    };

    Resolver(net::Loop& loop, ResolverConfig config);
    ~Resolver();
    Resolver(const Resolver&) = delete;
    Resolver& operator=(const Resolver&) = delete;

    // 0, or the WinSock error that left the resolver without a socket (every
    // resolve() then fails with ServFail).
    DWORD open_error() const { return open_error_; }
    const std::vector<sockaddr_in>& servers() const { return config_.servers; }

    void resolve(std::string_view host, Callback cb);

    // Fails every pending and later request with Timeout and closes the socket.
    void shutdown();
    bool busy() const { return socket_.busy(); }

    const Counters& counters() const { return counters_; }
    size_t inflight() const { return slots_.size() - free_slots_.size(); }
    size_t queued() const { return queue_.size(); }

private:
    struct Slot {
        std::string host;  // lowercased, no trailing dot
        Callback cb;
        net::TimerId timer = 0;
        uint32_t attempt = 0;
        uint32_t server = 0;
        uint16_t txid = 0;
        bool active = false;
    };
    struct Pending {
        std::string host;
        Callback cb;
    };

    void on_datagram(net::UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) override;
    void start(std::string&& host, Callback&& cb);
    void send_attempt(uint32_t index);
    void on_timeout(uint32_t index, uint16_t txid);
    void retry_or_fail(uint32_t index, Status final_status);
    void finish(uint32_t index, Status status, uint32_t ipv4_be);
    void post_result(Callback&& cb, Status status, uint32_t ipv4_be);

    net::Loop& loop_;
    ResolverConfig config_;
    net::UdpSocket socket_;
    std::vector<Slot> slots_;
    std::vector<uint32_t> free_slots_;
    std::vector<uint16_t> by_txid_;  // txid -> slot index + 1, 0 = free
    std::deque<Pending> queue_;
    std::mt19937 rng_;
    Response response_;
    Counters counters_;
    uint32_t next_server_ = 0;
    DWORD open_error_ = 0;
    bool shut_down_ = false;
};

}  // namespace wc::dns
