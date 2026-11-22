#pragma once
// Per-target politeness shared by every event loop (docs/politeness.md).
//
// One gate per IPv4 address, in a table of 256 independently locked shards
// (the same layout as the dedupe sets), holds:
//   - the per-IP host budget (--hosts-per-ip; 1 = the assignment's IP dedupe);
//   - a cap on concurrent connections to the IP and a minimum spacing between
//     connection starts to it;
//   - a back-off penalty after 429/503 replies that lengthens that spacing;
//   - a breaker: after N consecutive failed connections (connect failure or
//     timeout, no reply) the IP counts as unreachable and its remaining hosts
//     are skipped instead of each burning a connect timeout.
// IPs inside the configured CDN ranges get their own limits: per-IP caps
// protect origin servers, and an anycast edge fronts many unrelated origins.
//
// Waiting: a connection the gate cannot admit right away queues in the gate's
// FIFO as a GateWaiter that the caller owns. Whoever frees room later (a
// release on any loop, or a spacing timer) pops it under the shard lock and
// reports it through GateEvents after unlocking; the engine forwards it to
// the loop that owns the waiter. Sites already under way queue ahead of new
// sites, so a site that started finishes before the IP takes on more work.
//
// The gate clock (gate_clock_ms) is QueryPerformanceCounter based, finer than
// the loops' 15.6 ms tick: a timer that fires early just re-arms, so spacing
// is never shorter than configured.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace wc::crawl {

class Ipv4Ranges;

// Limits for one class of IPs. 0 means unlimited for hosts and concurrency.
struct IpLimits {
    uint32_t hosts = 1;          // hosts fetched per IP
    uint32_t concurrency = 2;    // connections open at once per IP
    uint32_t interval_ms = 250;  // minimum time between connection starts
    bool backoff = true;         // 429/503 lengthen the IP's spacing
};

struct GatePolicy {
    IpLimits ip;
    IpLimits cdn;
    const Ipv4Ranges* cdn_ranges = nullptr;  // IPs in these ranges use `cdn`; null: none do
    uint32_t fail_limit = 5;                 // consecutive failed connections before an IP is unreachable; 0 = never
    uint32_t max_penalty_ms = 60000;         // cap on the back-off penalty and on a Retry-After push
};

// Monotonic milliseconds for gate decisions (QueryPerformanceCounter).
uint64_t gate_clock_ms();

// A party waiting for a connection slot at one IP. Owned by the caller; while
// queued it is linked into the gate and touched only under the gate's lock.
// The engine derives from it to carry its own payload.
struct GateWaiter {
    enum class State : uint8_t {
        Idle,         // not at any gate
        Queued,       // in a gate's FIFO
        Admitted,     // woken with a connection slot: the owner must release() it
        Unreachable,  // woken because the IP's breaker tripped: holds nothing
        Cancelled,    // removed by cancel()
    };
    GateWaiter* prev = nullptr;
    GateWaiter* next = nullptr;
    uint32_t ip = 0;
    State state = State::Idle;
    bool priority = false;
};

// Callbacks of a gate decision, made on the deciding thread after the shard
// lock is released.
class GateEvents {
public:
    // `waiter` left its gate's FIFO as Admitted or Unreachable.
    virtual void on_wake(GateWaiter* waiter) = 0;
    // The gate of `ip` has waiters and room, but its spacing has not elapsed:
    // call IpGates::on_timer(ip, ...) after `delay_ms`.
    virtual void arm_gate_timer(uint32_t ip, uint32_t delay_ms) = 0;

protected:
    ~GateEvents() = default;
};

enum class Budget : uint8_t {
    First,        // the first host of this IP
    Extra,        // a further host within the budget
    Over,         // the IP's host budget is spent: skip the host (IP dedupe)
    Unreachable,  // the IP's breaker tripped: skip the host
};

enum class Admit : uint8_t {
    Now,          // holds a connection slot: connect, later release()
    Queued,       // waiter queued; GateEvents::on_wake reports the outcome
    Busy,         // acquire(): too many sites already wait at this IP
    Unreachable,  // the IP's breaker tripped
};

// How the connection that is being released (or replaced) went.
enum class Outcome : uint8_t {
    None,       // nothing conclusive (aborted, TLS failure, reset, local port shortage)
    Replied,    // the server answered (any status but 429/503)
    Failed,     // connect failure or timeout without any reply
    Throttled,  // 429 or 503
};

struct SeedResult {
    Budget budget = Budget::First;
    Admit admit = Admit::Now;  // meaningful for First and Extra
    bool cdn = false;          // the IP uses the CDN limits
};

class IpGates {
public:
    // `expected_ips` sizes the index up front (like the dedupe sets).
    IpGates(const GatePolicy& policy, size_t expected_ips);
    ~IpGates();
    IpGates(const IpGates&) = delete;
    IpGates& operator=(const IpGates&) = delete;

    // A new site resolved to `ip`: charges the IP's host budget and, within
    // it, asks for a connection slot. On Queued `waiter` is linked in behind
    // every earlier waiter.
    SeedResult seed(uint32_t ip, GateWaiter* waiter, uint64_t now, GateEvents& events);

    // A site under way needs a connection to `ip` and holds no slot there
    // (redirect to another IP, reconnect after a crawl-delay or Retry-After
    // wait). Queues ahead of new sites; Busy when `max_waiters` such sites
    // wait already.
    Admit acquire(uint32_t ip, GateWaiter* waiter, uint32_t max_waiters, uint64_t now, GateEvents& events);

    // The holder of a slot at `ip` closed its connection (`outcome`) and opens
    // another one there. Returns how long to wait before connecting; that
    // start is reserved.
    uint32_t restart(uint32_t ip, Outcome outcome, uint32_t retry_after_ms, uint64_t now);

    // Gives a connection slot back; `outcome` feeds the back-off and breaker.
    // `retry_after_ms` (Throttled only) pushes the IP's next start out.
    void release(uint32_t ip, Outcome outcome, uint32_t retry_after_ms, uint64_t now, GateEvents& events);

    // Removes a queued waiter. False when it was already woken: its on_wake
    // has been or is being delivered.
    bool cancel(GateWaiter* waiter);

    // The spacing timer armed through GateEvents::arm_gate_timer fired.
    void on_timer(uint32_t ip, uint64_t now, GateEvents& events);

    // Whether `ip` uses the CDN limits.
    bool is_cdn(uint32_t ip) const;
    // Distinct IPs seen (any thread; diagnostics and tests).
    size_t size() const;

private:
    struct Gate;
    struct Shard;
    static constexpr size_t kShards = 256;

    Shard& shard_of(uint32_t ip) const;
    const IpLimits& limits(const Gate& gate) const;
    bool has_room(const Gate& gate) const;
    uint32_t spacing(const Gate& gate) const;
    void admit(Gate& gate, uint64_t now);
    void enqueue(Gate& gate, GateWaiter* waiter, bool priority);
    void unlink(Gate& gate, GateWaiter* waiter);
    void note(Gate& gate, Outcome outcome, uint32_t retry_after_ms, uint64_t now);
    // Pops what the gate can admit now (or everything when it is dead) into
    // the `woken` chain; returns a spacing timer delay to arm, or 0.
    uint32_t dispatch(Gate& gate, uint64_t now, GateWaiter*& woken);
    static void deliver(GateWaiter* woken, uint32_t ip, uint32_t timer_ms, GateEvents& events);

    GatePolicy policy_;
    std::unique_ptr<Shard[]> shards_;
};

// Retry-After (RFC 9110 §10.2.3): delay-seconds or an HTTP-date, as a delay
// in seconds from `now_unix` (seconds since 1970, UTC). Past dates give 0;
// absurd values saturate. nullopt when the value is neither.
std::optional<uint64_t> parse_retry_after(std::string_view value, int64_t now_unix);

// HTTP-date (RFC 9110 §5.6.7: IMF-fixdate, and the obsolete RFC 850 and
// asctime forms recipients must accept) as seconds since 1970, UTC.
std::optional<int64_t> parse_http_date(std::string_view value);

}  // namespace wc::crawl
