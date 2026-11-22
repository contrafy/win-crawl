#include "crawl/politeness.h"

#include "crawl/ipranges.h"
#include "doctest/doctest.h"

#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace wc::crawl;

namespace {

uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return static_cast<uint32_t>(a) | static_cast<uint32_t>(b) << 8 | static_cast<uint32_t>(c) << 16 |
           static_cast<uint32_t>(d) << 24;
}

// Records what the gates report instead of acting on it.
struct Events final : GateEvents {
    std::vector<GateWaiter*> woken;
    std::vector<std::pair<uint32_t, uint32_t>> timers;  // ip, delay
    void on_wake(GateWaiter* w) override { woken.push_back(w); }
    void arm_gate_timer(uint32_t gate_ip, uint32_t delay_ms) override { timers.emplace_back(gate_ip, delay_ms); }
};

GatePolicy policy(uint32_t hosts, uint32_t concurrency, uint32_t interval_ms) {
    GatePolicy p;
    p.ip = IpLimits{hosts, concurrency, interval_ms, true};
    p.cdn = p.ip;
    return p;
}

const uint32_t kA = ip(10, 0, 0, 1);
const uint32_t kB = ip(10, 0, 0, 2);

// For the multi-threaded test: a waiter that knows its "loop".
struct Inbox;
struct Owned : GateWaiter {
    Inbox* owner = nullptr;
};
// Stands in for an event loop: wakes land in its inbox, as the engine posts them.
struct Inbox final : GateEvents {
    std::mutex mutex;
    std::deque<Owned*> queue;
    void on_wake(GateWaiter* w) override {
        auto* o = static_cast<Owned*>(w);
        std::lock_guard lock(o->owner->mutex);
        o->owner->queue.push_back(o);
    }
    void arm_gate_timer(uint32_t, uint32_t) override {}  // interval 0: never armed
};

}  // namespace

TEST_CASE("politeness: the host budget is the IP dedupe at 1 and a cap above it") {
    Events ev;
    GateWaiter w;
    SUBCASE("budget 1: the assignment's IP dedupe") {
        IpGates gates(policy(1, 0, 0), 16);
        const SeedResult first = gates.seed(kA, &w, 0, ev);
        CHECK(first.budget == Budget::First);
        CHECK(first.admit == Admit::Now);
        CHECK(gates.seed(kA, &w, 0, ev).budget == Budget::Over);
        CHECK(gates.seed(kB, &w, 0, ev).budget == Budget::First);
        CHECK(gates.size() == 2);
    }
    SUBCASE("budget 3") {
        IpGates gates(policy(3, 0, 0), 16);
        CHECK(gates.seed(kA, &w, 0, ev).budget == Budget::First);
        CHECK(gates.seed(kA, &w, 0, ev).budget == Budget::Extra);
        CHECK(gates.seed(kA, &w, 0, ev).budget == Budget::Extra);
        CHECK(gates.seed(kA, &w, 0, ev).budget == Budget::Over);
    }
    SUBCASE("unlimited") {
        IpGates gates(policy(0, 0, 0), 16);
        for (int i = 0; i < 1000; ++i) {
            const SeedResult r = gates.seed(kA, &w, 0, ev);
            CHECK(r.budget == (i == 0 ? Budget::First : Budget::Extra));
            CHECK(r.admit == Admit::Now);  // no concurrency cap, no spacing
        }
    }
    CHECK(ev.woken.empty());
}

TEST_CASE("politeness: the gate table grows past its expectation") {
    IpGates gates(policy(1, 0, 0), 1);
    Events ev;
    GateWaiter w;
    for (uint32_t i = 0; i < 50000; ++i) {
        CHECK(gates.seed(i * 2654435761u, &w, 0, ev).budget == Budget::First);
    }
    for (uint32_t i = 0; i < 50000; i += 7) {
        CHECK(gates.seed(i * 2654435761u, &w, 0, ev).budget == Budget::Over);
    }
    CHECK(gates.size() == 50000);
}

TEST_CASE("politeness: concurrency cap and connection spacing") {
    IpGates gates(policy(0, 2, 100), 16);
    Events ev;
    GateWaiter a, b, c;
    CHECK(gates.seed(kA, &a, 1000, ev).admit == Admit::Now);
    // Room for a second connection, but not before the spacing: queued, with
    // a timer for when the spacing ends.
    CHECK(gates.seed(kA, &b, 1000, ev).admit == Admit::Queued);
    REQUIRE(ev.timers.size() == 1);
    CHECK(ev.timers[0] == std::make_pair(kA, 100u));
    // A timer that fires early (coarse loop clock) just re-arms.
    gates.on_timer(kA, 1090, ev);
    CHECK(ev.woken.empty());
    REQUIRE(ev.timers.size() == 2);
    CHECK(ev.timers[1].second == 10u);
    gates.on_timer(kA, 1100, ev);
    REQUIRE(ev.woken.size() == 1);
    CHECK(ev.woken[0] == &b);
    CHECK(b.state == GateWaiter::State::Admitted);
    // b connects (late, as a busy owner loop would): the spacing counts from
    // there, not from its admission at 1100.
    gates.started(kA, 1130, ev);
    // Both slots held: the next site waits for a release, not a timer.
    CHECK(gates.seed(kA, &c, 1250, ev).admit == Admit::Queued);
    CHECK(ev.timers.size() == 2);
    gates.release(kA, Outcome::Replied, false, 1210, ev);  // a, admitted at once: nothing pending
    REQUIRE(ev.timers.size() == 3);
    CHECK(ev.timers[2].second == 20u);  // 1130 + 100
    gates.on_timer(kA, 1230, ev);
    REQUIRE(ev.woken.size() == 2);
    CHECK(ev.woken[1] == &c);
    // Other IPs are independent.
    GateWaiter d;
    CHECK(gates.seed(kB, &d, 1260, ev).admit == Admit::Now);
}

TEST_CASE("politeness: a woken start blocks the next one until it connects") {
    IpGates gates(policy(0, 3, 100), 16);
    Events ev;
    GateWaiter a, b, c;
    CHECK(gates.seed(kA, &a, 0, ev).admit == Admit::Now);
    CHECK(gates.seed(kA, &b, 0, ev).admit == Admit::Queued);
    CHECK(gates.seed(kA, &c, 0, ev).admit == Admit::Queued);
    gates.on_timer(kA, 100, ev);
    REQUIRE(ev.woken.size() == 1);  // b; c would be due at 200
    // b's owner has not connected by 300: c must not start, and no timer runs.
    const size_t timers = ev.timers.size();
    gates.on_timer(kA, 300, ev);
    CHECK(ev.woken.size() == 1);
    CHECK(ev.timers.size() == timers);
    // b connects at 300; c follows 100 ms later.
    gates.started(kA, 300, ev);
    REQUIRE(ev.timers.size() == timers + 1);
    CHECK(ev.timers.back().second == 100u);
    gates.on_timer(kA, 400, ev);
    REQUIRE(ev.woken.size() == 2);
    CHECK(ev.woken[1] == &c);
    // A woken slot given back unused unblocks too.
    GateWaiter d;
    CHECK(gates.seed(kA, &d, 400, ev).admit == Admit::Queued);
    gates.release(kA, Outcome::None, true, 450, ev);  // c never connected
    gates.on_timer(kA, 500, ev);
    REQUIRE(ev.woken.size() == 3);
    CHECK(ev.woken[2] == &d);
}

TEST_CASE("politeness: a released slot waits out the spacing") {
    IpGates gates(policy(0, 1, 100), 16);
    Events ev;
    GateWaiter a, b;
    CHECK(gates.seed(kA, &a, 0, ev).admit == Admit::Now);
    CHECK(gates.seed(kA, &b, 10, ev).admit == Admit::Queued);
    CHECK(ev.timers.empty());  // no room: the release decides
    gates.release(kA, Outcome::Replied, false, 40, ev);
    CHECK(ev.woken.empty());
    REQUIRE(ev.timers.size() == 1);
    CHECK(ev.timers[0].second == 60u);
    gates.on_timer(kA, 100, ev);
    REQUIRE(ev.woken.size() == 1);
    CHECK(ev.woken[0] == &b);
}

TEST_CASE("politeness: sites under way queue ahead of new sites") {
    IpGates gates(policy(0, 1, 0), 16);
    Events ev;
    GateWaiter holder, s1, s2, p1, p2, p3;
    CHECK(gates.seed(kA, &holder, 0, ev).admit == Admit::Now);
    CHECK(gates.seed(kA, &s1, 0, ev).admit == Admit::Queued);
    CHECK(gates.seed(kA, &s2, 0, ev).admit == Admit::Queued);
    CHECK(gates.acquire(kA, &p1, 2, 0, ev) == Admit::Queued);
    CHECK(gates.acquire(kA, &p2, 2, 0, ev) == Admit::Queued);
    CHECK(gates.acquire(kA, &p3, 2, 0, ev) == Admit::Busy);  // two already wait
    std::vector<GateWaiter*> order;
    for (int i = 0; i < 4; ++i) {
        gates.release(kA, Outcome::Replied, false, 0, ev);
        REQUIRE(ev.woken.size() == static_cast<size_t>(i + 1));
        order.push_back(ev.woken.back());
    }
    CHECK(order == std::vector<GateWaiter*>{&p1, &p2, &s1, &s2});
}

TEST_CASE("politeness: a holder's reconnect only waits for the spacing") {
    IpGates gates(policy(0, 1, 100), 16);
    Events ev;
    GateWaiter a;
    CHECK(gates.seed(kA, &a, 0, ev).admit == Admit::Now);
    CHECK(gates.restart(kA, Outcome::Replied, 30) == 70u);   // reserved at 100
    CHECK(gates.restart(kA, Outcome::Replied, 30) == 170u);  // the next one at 200
    CHECK(gates.restart(kA, Outcome::Replied, 1000) == 0u);
}

TEST_CASE("politeness: 429/503 back off the IP, replies relax it") {
    IpGates gates(policy(0, 1, 200), 16);
    Events ev;
    GateWaiter a, b;
    CHECK(gates.seed(kA, &a, 0, ev).admit == Admit::Now);
    // Throttled: nothing starts there for a penalty of at least 1 s, and the
    // spacing grows by it. The server's Retry-After is the host's business
    // (the engine's one retry), not the whole IP's.
    gates.release(kA, Outcome::Throttled, false, 100, ev);
    CHECK(gates.seed(kA, &b, 100, ev).admit == Admit::Queued);
    REQUIRE(ev.timers.size() == 1);
    CHECK(ev.timers[0].second == 1000u);
    gates.on_timer(kA, 1100, ev);
    REQUIRE(ev.woken.size() == 1);
    // Spacing is now interval + penalty = 200 + 1000.
    CHECK(gates.restart(kA, Outcome::None, 1100) == 1200u);
    // A further throttle doubles the penalty (2000) and pushes the next start
    // out by it; each normal reply halves it again.
    CHECK(gates.restart(kA, Outcome::Throttled, 10000) == 2000u);
    CHECK(gates.restart(kA, Outcome::Replied, 100000) == 0u);     // penalty 1000: next at +1200
    CHECK(gates.restart(kA, Outcome::Replied, 100000) == 1200u);  // penalty 500
    CHECK(gates.restart(kA, Outcome::Replied, 200000) == 0u);     // penalty 250: next at +450
    CHECK(gates.restart(kA, Outcome::Replied, 200000) == 450u);   // penalty 125
    CHECK(gates.restart(kA, Outcome::Replied, 300000) == 0u);     // under 100 ms: gone
    CHECK(gates.restart(kA, Outcome::Replied, 300000) == 200u);
}

TEST_CASE("politeness: CDN ranges get their own limits and no back-off") {
    Ipv4Ranges cdn;
    std::string error;
    REQUIRE(cdn.parse("10.0.0.2/32\n", error));
    GatePolicy p = policy(1, 1, 500);
    p.cdn = IpLimits{0, 3, 0, false};
    p.cdn_ranges = &cdn;
    IpGates gates(p, 16);
    Events ev;
    GateWaiter w[5];
    CHECK_FALSE(gates.is_cdn(kA));
    CHECK(gates.is_cdn(kB));
    CHECK(gates.seed(kB, &w[0], 0, ev).cdn);
    CHECK(gates.seed(kB, &w[1], 0, ev).admit == Admit::Now);
    CHECK(gates.seed(kB, &w[2], 0, ev).admit == Admit::Now);
    const SeedResult fourth = gates.seed(kB, &w[3], 0, ev);
    CHECK(fourth.budget == Budget::Extra);  // no host budget there
    CHECK(fourth.admit == Admit::Queued);   // but a concurrency cap
    gates.release(kB, Outcome::Throttled, false, 0, ev);
    REQUIRE(ev.woken.size() == 1);  // no penalty: admitted at once
    CHECK(ev.woken[0] == &w[3]);
    // The ordinary IP keeps the ordinary limits.
    CHECK_FALSE(gates.seed(kA, &w[4], 0, ev).cdn);
    CHECK(gates.seed(kA, &w[4], 0, ev).budget == Budget::Over);
}

TEST_CASE("politeness: an IP that keeps failing is skipped") {
    GatePolicy p = policy(0, 1, 0);
    p.fail_limit = 3;
    IpGates gates(p, 16);
    Events ev;
    GateWaiter a, queued1, queued2, late;
    CHECK(gates.seed(kA, &a, 0, ev).admit == Admit::Now);
    CHECK(gates.seed(kA, &queued1, 0, ev).admit == Admit::Queued);
    CHECK(gates.seed(kA, &queued2, 0, ev).admit == Admit::Queued);
    gates.release(kA, Outcome::Failed, false, 0, ev);   // 1; queued1 admitted
    gates.release(kA, Outcome::Replied, false, 0, ev);  // a reply resets the count; queued2 admitted
    CHECK(ev.woken.size() == 2);
    CHECK(gates.seed(kA, &late, 0, ev).admit == Admit::Queued);
    gates.release(kA, Outcome::Failed, false, 0, ev);  // 1; late admitted
    CHECK(ev.woken.size() == 3);
    GateWaiter w1, w2;
    CHECK(gates.seed(kA, &w1, 0, ev).admit == Admit::Queued);
    CHECK(gates.seed(kA, &w2, 0, ev).admit == Admit::Queued);
    gates.release(kA, Outcome::Failed, false, 0, ev);  // 2; w1 admitted
    gates.release(kA, Outcome::Failed, false, 0, ev);  // 3: dead, w2 woken unreachable
    REQUIRE(ev.woken.size() == 5);
    CHECK(ev.woken[3] == &w1);
    CHECK(w1.state == GateWaiter::State::Admitted);
    CHECK(ev.woken[4] == &w2);
    CHECK(w2.state == GateWaiter::State::Unreachable);
    GateWaiter after;
    CHECK(gates.seed(kA, &after, 0, ev).budget == Budget::Unreachable);
    CHECK(gates.acquire(kA, &after, 0, 0, ev) == Admit::Unreachable);
}

TEST_CASE("politeness: cancel removes a queued waiter only") {
    IpGates gates(policy(0, 1, 0), 16);
    Events ev;
    GateWaiter a, b, c;
    CHECK(gates.seed(kA, &a, 0, ev).admit == Admit::Now);
    CHECK(gates.seed(kA, &b, 0, ev).admit == Admit::Queued);
    CHECK(gates.acquire(kA, &c, 0, 0, ev) == Admit::Queued);
    CHECK(gates.cancel(&c));
    CHECK(c.state == GateWaiter::State::Cancelled);
    CHECK_FALSE(gates.cancel(&c));
    gates.release(kA, Outcome::Replied, false, 0, ev);
    REQUIRE(ev.woken.size() == 1);
    CHECK(ev.woken[0] == &b);
    CHECK_FALSE(gates.cancel(&b));  // already woken
}

TEST_CASE("politeness: concurrent loops never exceed an IP's cap") {
    // Threads play event loops: each starts sites on four IPs, holds every
    // admitted slot briefly and releases it; wakes go to the waiter's owning
    // thread, the way the engine posts them.
    constexpr int kThreads = 8;
    constexpr int kSitesPerThread = 2000;
    constexpr uint32_t kCap = 3;
    IpGates gates(policy(0, kCap, 0), 64);
    std::atomic<int> open[4] = {};
    std::atomic<bool> over{false};
    std::atomic<bool> bad_wake{false};
    std::atomic<int> done{0};
    Inbox loops[kThreads];
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            Inbox& me = loops[t];
            std::vector<Owned> waiters(kSitesPerThread);
            int started = 0;
            int finished = 0;
            const auto hold = [&](uint32_t gate_ip, bool woken) {
                if (open[gate_ip].fetch_add(1) + 1 > static_cast<int>(kCap)) {
                    over = true;
                }
                std::this_thread::yield();
                open[gate_ip].fetch_sub(1);
                gates.release(gate_ip, Outcome::Replied, woken, 0, me);
                ++finished;
            };
            while (finished < kSitesPerThread) {
                if (started < kSitesPerThread) {
                    Owned& w = waiters[static_cast<size_t>(started)];
                    w.owner = &me;
                    const auto gate_ip = static_cast<uint32_t>((started * 7 + t) & 3);
                    ++started;
                    if (gates.seed(gate_ip, &w, 0, me).admit == Admit::Now) {
                        hold(gate_ip, false);
                    }
                }
                Owned* next = nullptr;
                {
                    std::lock_guard lock(me.mutex);
                    if (!me.queue.empty()) {
                        next = me.queue.front();
                        me.queue.pop_front();
                    }
                }
                if (next != nullptr) {
                    if (next->state != GateWaiter::State::Admitted) {
                        bad_wake = true;  // no breaker here: every wake is an admission
                    }
                    hold(next->ip, true);
                } else if (started == kSitesPerThread) {
                    std::this_thread::yield();
                }
            }
            done.fetch_add(1);
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    CHECK(done.load() == kThreads);
    CHECK_FALSE(over.load());
    CHECK_FALSE(bad_wake.load());
}

TEST_CASE("politeness: HTTP-date forms") {
    // RFC 9110 §5.6.7's example instant in all three forms.
    CHECK(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT") == 784111777);
    CHECK(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT") == 784111777);
    CHECK(parse_http_date("Sun Nov  6 08:49:37 1994") == 784111777);
    CHECK(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT") == 0);
    CHECK(parse_http_date("Tue, 29 Feb 2028 12:00:00 GMT") == 1835438400);
    CHECK(parse_http_date("Wednesday, 01-Jan-31 00:00:00 GMT") == 1924992000);  // 2031
    CHECK_FALSE(parse_http_date(""));
    CHECK_FALSE(parse_http_date("Sun, 06 Nov 1994 08:49:37"));  // no zone
    CHECK_FALSE(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT x"));
    CHECK_FALSE(parse_http_date("Sun, 6 Nov 1994 08:49:37 GMT"));  // the day needs two digits
    CHECK_FALSE(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"));
    CHECK_FALSE(parse_http_date("Sun, 06 Nov 1994 24:00:00 GMT"));
    CHECK_FALSE(parse_http_date("Sun, 00 Nov 1994 08:49:37 GMT"));
    CHECK_FALSE(parse_http_date("Funday, 06-Nov-94 08:49:37 GMT"));
}

TEST_CASE("politeness: Retry-After") {
    const int64_t now = 784111777;
    CHECK(parse_retry_after("120", now) == 120u);
    CHECK(parse_retry_after(" 0 ", now) == 0u);
    CHECK(parse_retry_after("99999999999999999999999", now) == 4294967295u);  // saturates
    CHECK(parse_retry_after("Sun, 06 Nov 1994 08:50:07 GMT", now) == 30u);
    CHECK(parse_retry_after("Sun, 06 Nov 1994 08:00:00 GMT", now) == 0u);  // in the past
    CHECK_FALSE(parse_retry_after("", now));
    CHECK_FALSE(parse_retry_after("1.5", now));
    CHECK_FALSE(parse_retry_after("-1", now));
    CHECK_FALSE(parse_retry_after("soon", now));
}
