#pragma once
// Asynchronous stub resolver for A and HTTPS (RFC 9460) records over UDP,
// one per net::Loop.
//
// Every method is loop-thread only, including construction. Callbacks always
// run later on the loop thread, never inside resolve()/resolve_https(). No
// TCP fallback: a truncated (TC) reply resolves as NoAnswer. Queries carry an
// EDNS0 OPT record (kEdnsUdpSize); a FORMERR reply makes the remaining
// attempts of that query go out without it (RFC 6891 section 7).
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
    Ok,        // A: ipv4_be holds the first A record; HTTPS: a usable RRset (present = true)
    NxDomain,  // authoritative "no such name"
    NoAnswer,  // NOERROR without a usable record (NODATA, malformed HTTPS RRset), or a truncated reply
    ServFail,  // SERVFAIL/REFUSED/other rcode on every attempt, or no usable socket/servers
    Timeout,   // no reply within attempts * timeout_ms, or cancelled by shutdown()
    Invalid,   // host is not a valid DNS name
};

const char* status_name(Status status);

// Result of resolve_https(): the HTTPS RR selected from the RRset at the host
// (after any CNAME chain). AliasMode targets are reported, not followed.
struct HttpsRecord {
    bool present = false;  // Status::Ok; every field below is meaningful only then
    bool alias_mode = false;
    uint16_t priority = 0;  // SvcPriority of the selected record (lowest among ServiceMode records)
    std::string target;     // TargetName without the trailing dot; "." = the root name
    bool alpn_h3 = false;
    bool alpn_h2 = false;
    bool alpn_http11 = false;
    bool ech = false;
    uint16_t port = 0;  // 0 = no "port" SvcParam
    bool no_default_alpn = false;
    bool ipv4hint = false;
    bool ipv6hint = false;
    uint8_t rrset_size = 0;  // well-formed records in the RRset
    uint8_t cname_hops = 0;  // CNAMEs followed from the host to the RRset
    // An HTTPS RRset exists but a record in it is malformed, so RFC 9460
    // section 2.2 makes the whole set unusable: Status::NoAnswer, present false.
    bool malformed = false;
};

struct ResolverConfig {
    std::vector<sockaddr_in> servers;  // empty: system_dns_servers()
    uint32_t timeout_ms = 1500;        // per attempt
    uint32_t attempts = 3;             // total sends per query, rotating servers
    uint32_t max_inflight = 512;       // further requests wait in a FIFO; clamped to [1, 32768]
};

class Resolver final : private net::UdpHandler {
public:
    using Callback = std::function<void(Status status, uint32_t ipv4_be)>;
    using HttpsCallback = std::function<void(Status status, const HttpsRecord& record)>;

    // Outcome counters cover both query types; https_* break HTTPS out.
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
        uint64_t literals = 0;        // IPv4 literals answered without a query
        uint64_t late = 0;            // replies whose txid is no longer in flight
        uint64_t mismatched = 0;      // other well-formed rejects: source, QR, question
        uint64_t malformed = 0;       // replies that failed to parse
        uint64_t edns_fallbacks = 0;  // FORMERR replies that turned EDNS off for the query's later attempts
        uint64_t https_requests = 0;  // resolve_https() calls
        uint64_t https_present = 0;   // ... that found a usable HTTPS RRset
        uint64_t https_malformed = 0; // ... whose RRset held a malformed record
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
    // HTTPS RR (type 65) lookup for `host` itself, i.e. the https origin on
    // port 443. NODATA is the normal "no record" answer: NoAnswer with
    // present false. An IPv4 literal answers NoAnswer without a query.
    void resolve_https(std::string_view host, HttpsCallback cb);

    // Fails every pending and later request with Timeout and closes the socket.
    void shutdown();
    bool busy() const { return socket_.busy(); }

    const Counters& counters() const { return counters_; }
    size_t inflight() const { return slots_.size() - free_slots_.size(); }
    size_t queued() const { return queue_.size(); }

private:
    // Exactly one of cb/https_cb is set, matching qtype.
    struct Slot {
        std::string host;  // lowercased, no trailing dot
        Callback cb;
        HttpsCallback https_cb;
        net::TimerId timer = 0;
        uint32_t attempt = 0;
        uint32_t server = 0;
        uint16_t txid = 0;
        uint16_t qtype = 0;
        bool edns = true;
        bool active = false;
    };
    struct Pending {
        std::string host;
        uint16_t qtype;
        Callback cb;
        HttpsCallback https_cb;
    };

    void on_datagram(net::UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) override;
    void submit(std::string_view host, uint16_t qtype, Callback&& cb, HttpsCallback&& https_cb);
    void start(Pending&& request);
    void send_attempt(uint32_t index);
    void on_timeout(uint32_t index, uint16_t txid);
    void retry_or_fail(uint32_t index, Status final_status);
    // `reply` is the parsed answer behind Ok/NoAnswer, null otherwise.
    void finish(uint32_t index, Status status, const Response* reply);
    void post_result(Callback&& cb, HttpsCallback&& https_cb, Status status, uint32_t ipv4_be);

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
