#pragma once

#include "net/loop.h"

#include <functional>

namespace wc::net::test {

// Runs `loop` until something calls stop(); a watchdog stops it after
// `timeout_ms` so a broken test fails instead of hanging. False on timeout.
inline bool run_for(Loop& loop, uint32_t timeout_ms) {
    bool timed_out = false;
    const TimerId watchdog = loop.add_timer(timeout_ms, [&] {
        timed_out = true;
        loop.stop();
    });
    loop.run();
    loop.cancel_timer(watchdog);
    return !timed_out;
}

// Runs `loop` until `done()` holds (polled from a 1 ms timer).
inline bool run_until(Loop& loop, const std::function<bool()>& done, uint32_t timeout_ms) {
    TimerId poll_id = 0;
    std::function<void()> poll = [&] {
        if (done()) {
            loop.stop();
        } else {
            poll_id = loop.add_timer(1, poll);
        }
    };
    poll_id = loop.add_timer(0, poll);
    const bool ok = run_for(loop, timeout_ms);
    loop.cancel_timer(poll_id);
    return ok;
}

}  // namespace wc::net::test
