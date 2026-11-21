#pragma once
// Fake authoritative DNS server for benchmarks and tests.
//
// Answers A queries for "h<N>.<zone>" from the deterministic Behavior model
// (NXDOMAIN for a hash-selected fraction, IP sharing, per-name reply delay),
// NODATA for other types of existing names, NXDOMAIN for other names inside
// the zone and REFUSED outside it. It deliberately carries its own minimal
// codec instead of using wc_dns, so it stays an independent oracle.
//
// Runs on its own Loop and thread; start()/stop() are called from the owner thread.

#include "benchsrv/behavior.h"
#include "net/loop.h"
#include "net/udp.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

namespace wc::benchsrv {

struct DnsCounters {
    uint64_t queries = 0;
    uint64_t answered = 0;  // NOERROR with an A record
    uint64_t nodata = 0;
    uint64_t nxdomain = 0;
    uint64_t refused = 0;
    uint64_t errors = 0;  // FORMERR / NOTIMP / unparseable
};

enum class DnsOutcome : uint8_t { Drop, Answered, NoData, NxDomain, Refused, Error };

// Builds the reply for one query datagram into `out` (cleared first). Drop
// means the datagram gets no reply (shorter than a header, or a response).
// `delay_key` receives N when the name is h<N>.<zone>, otherwise a hash of the
// name; it keys the deterministic reply delay. Exposed for tests.
DnsOutcome build_dns_reply(const Behavior& behavior, const char* query, size_t len, std::vector<char>& out,
                           uint64_t& delay_key);

class DnsServer final : private net::UdpHandler {
public:
    explicit DnsServer(const Behavior& behavior);
    ~DnsServer();
    DnsServer(const DnsServer&) = delete;
    DnsServer& operator=(const DnsServer&) = delete;

    // Binds `local` (port 0 = ephemeral) and starts the loop thread. Returns 0 or a WinSock error.
    DWORD start(const sockaddr_in& local);
    // Closes the socket, drains pending delayed replies and joins. Idempotent.
    void stop();

    sockaddr_in local_address() const { return local_; }
    DnsCounters counters() const;  // any thread

private:
    struct Pending {
        sockaddr_in to{};
        uint32_t next_free = 0;
        uint16_t len = 0;
        char data[512];
    };

    void on_datagram(net::UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) override;
    void send_pending(uint32_t index);
    void shutdown_on_loop();

    const Behavior behavior_;
    net::Loop loop_;
    std::optional<net::UdpSocket> socket_;
    std::thread thread_;
    sockaddr_in local_{};
    std::vector<char> reply_;
    std::vector<std::unique_ptr<Pending>> pending_;
    uint32_t free_head_ = UINT32_MAX;
    std::vector<net::TimerId> pending_timers_;
    bool stopping_ = false;

    // Written by the loop thread only; relaxed loads from stats readers.
    struct AtomicCounters {
        std::atomic<uint64_t> queries{0}, answered{0}, nodata{0}, nxdomain{0}, refused{0}, errors{0};
    } stats_;
};

}  // namespace wc::benchsrv
