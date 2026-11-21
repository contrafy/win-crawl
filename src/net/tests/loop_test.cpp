#include "net/loop.h"

#include "doctest/doctest.h"
#include "net/tests/test_util.h"

#include <atomic>
#include <random>
#include <thread>
#include <vector>

using namespace wc::net;
using wc::net::test::run_for;

TEST_CASE("timers fire in deadline order, FIFO for equal deadlines") {
    Loop loop;
    std::vector<int> order;
    loop.add_timer(30, [&] { order.push_back(30); });
    loop.add_timer(10, [&] { order.push_back(10); });
    loop.add_timer(20, [&] { order.push_back(20); });
    loop.add_timer(0, [&] { order.push_back(0); });
    for (int i = 0; i < 5; ++i) {
        loop.add_timer(15, [&, i] { order.push_back(100 + i); });
    }
    loop.add_timer(40, [&] { loop.stop(); });
    REQUIRE(run_for(loop, 2000));
    CHECK(order == std::vector<int>{0, 10, 100, 101, 102, 103, 104, 20, 30});
}

TEST_CASE("timer never fires before its delay has elapsed on now()") {
    Loop loop;
    const uint64_t start = loop.now();
    uint64_t fired_at = 0;
    loop.add_timer(50, [&] {
        fired_at = loop.now();
        loop.stop();
    });
    REQUIRE(run_for(loop, 2000));
    CHECK(fired_at >= start + 50);
}

TEST_CASE("cancel_timer") {
    Loop loop;
    int fired = 0;

    SUBCASE("cancelled timer does not fire; repeated and bogus cancels are no-ops") {
        const TimerId id = loop.add_timer(5, [&] { ++fired; });
        CHECK(id != 0);
        loop.cancel_timer(id);
        loop.cancel_timer(id);
        loop.cancel_timer(0);
        loop.cancel_timer(~TimerId{0});
        loop.add_timer(20, [&] { loop.stop(); });
        REQUIRE(run_for(loop, 2000));
        CHECK(fired == 0);
    }

    SUBCASE("a stale id does not cancel the timer that reused its slot") {
        const TimerId old_id = loop.add_timer(0, [&] { fired += 100; });
        loop.cancel_timer(old_id);
        const TimerId fresh = loop.add_timer(5, [&] {
            ++fired;
            loop.stop();
        });
        CHECK(fresh != old_id);
        CHECK(static_cast<uint32_t>(fresh) == static_cast<uint32_t>(old_id));  // same slot
        loop.cancel_timer(old_id);
        REQUIRE(run_for(loop, 2000));
        CHECK(fired == 1);
    }

    SUBCASE("cancel from inside another timer, including one due in the same batch") {
        TimerId same_batch = 0;
        TimerId later = 0;
        loop.add_timer(5, [&] {
            loop.cancel_timer(same_batch);
            loop.cancel_timer(later);
        });
        same_batch = loop.add_timer(5, [&] { ++fired; });
        later = loop.add_timer(30, [&] { ++fired; });
        loop.add_timer(60, [&] { loop.stop(); });
        REQUIRE(run_for(loop, 2000));
        CHECK(fired == 0);
    }

    SUBCASE("a timer cancelling itself while running is harmless") {
        TimerId self = 0;
        self = loop.add_timer(1, [&] {
            loop.cancel_timer(self);
            ++fired;
            loop.stop();
        });
        REQUIRE(run_for(loop, 2000));
        CHECK(fired == 1);
    }
}

TEST_CASE("a zero-delay timer re-arming itself does not starve posted tasks") {
    Loop loop;
    int ticks = 0;
    bool posted_ran = false;
    std::function<void()> tick = [&] {
        ++ticks;
        if (!posted_ran) {
            loop.add_timer(0, tick);
        }
    };
    loop.add_timer(0, tick);
    loop.post([&] {
        posted_ran = true;
        loop.stop();
    });
    REQUIRE(run_for(loop, 2000));
    CHECK(posted_ran);
    CHECK(ticks <= 2);
}

TEST_CASE("timer heap stays consistent under heavy add/cancel churn") {
    Loop loop;
    std::mt19937 rng(463);
    std::vector<TimerId> ids;
    uint64_t last_deadline = 0;
    bool ordered = true;
    bool early = false;
    int fired = 0;
    int expected = 0;
    const uint64_t base = loop.now();
    for (int i = 0; i < 100000; ++i) {
        const uint32_t delay = rng() % 40;
        const uint64_t deadline = base + delay;
        const TimerId id = loop.add_timer(delay, [&, deadline] {
            ordered = ordered && deadline >= last_deadline;
            early = early || loop.now() < deadline;
            last_deadline = deadline;
            ++fired;
        });
        if (rng() % 2 == 0) {
            ids.push_back(id);
        } else {
            ++expected;
        }
    }
    for (const TimerId id : ids) {
        loop.cancel_timer(id);
    }
    loop.add_timer(60, [&] { loop.stop(); });
    REQUIRE(run_for(loop, 3000));
    CHECK(fired == expected);
    CHECK(ordered);
    CHECK_FALSE(early);
}

TEST_CASE("post() from many threads runs every task on the loop thread") {
    Loop loop;
    constexpr int kThreads = 4;
    constexpr int kPerThread = 20000;
    const auto loop_thread = std::this_thread::get_id();
    int count = 0;  // touched only on the loop thread
    bool wrong_thread = false;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kPerThread; ++i) {
                loop.post([&] {
                    wrong_thread = wrong_thread || std::this_thread::get_id() != loop_thread;
                    if (++count == kThreads * kPerThread) {
                        loop.stop();
                    }
                });
            }
        });
    }
    const bool ok = run_for(loop, 4000);
    for (auto& t : threads) {
        t.join();
    }
    REQUIRE(ok);
    CHECK(count == kThreads * kPerThread);
    CHECK_FALSE(wrong_thread);
}

TEST_CASE("a task posted from a running task runs on a later iteration") {
    Loop loop;
    std::vector<int> order;
    loop.post([&] {
        order.push_back(1);
        loop.post([&] {
            order.push_back(3);
            loop.stop();
        });
    });
    loop.post([&] { order.push_back(2); });
    REQUIRE(run_for(loop, 2000));
    CHECK(order == std::vector<int>{1, 2, 3});
}

TEST_CASE("stop() from another thread wakes an idle loop; run() can be re-entered") {
    Loop loop;
    std::thread stopper([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        loop.stop();
    });
    loop.run();  // no timers: blocks until the cross-thread stop
    stopper.join();

    bool ran = false;
    loop.post([&] {
        ran = true;
        loop.stop();
    });
    REQUIRE(run_for(loop, 2000));
    CHECK(ran);
}

TEST_CASE("associate rejects an invalid handle") {
    Loop loop;
    CHECK(loop.associate(INVALID_HANDLE_VALUE) != 0);
}
