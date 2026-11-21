#pragma once
// Single-threaded I/O completion port event loop.
//
// Threading model: one Loop per worker thread, share-nothing. Everything that
// belongs to a loop (sockets, timers, per-connection state) is touched only on
// that loop's thread. The only thread-safe entry points are post() and stop().

#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

namespace wc::net {

// Process-wide WinSock 2.2 initialisation and extension-function lookup
// (ConnectEx, AcceptEx, GetAcceptExSockaddrs). Idempotent and thread-safe;
// every socket constructor calls it, callers may call it early.
void startup();

// Every overlapped operation embeds one IoRequest. The loop recovers it from
// the dequeued OVERLAPPED and calls `complete` on the loop thread.
//   bytes: bytes transferred
//   error: 0 on success, otherwise a Win32/WinSock error code
//          (ERROR_OPERATION_ABORTED after close()/CancelIoEx).
struct IoRequest {
    OVERLAPPED ov{};
    void (*complete)(IoRequest* req, DWORD bytes, DWORD error) = nullptr;
};

using TimerId = uint64_t;  // 0 is never a valid id

class Loop {
public:
    Loop();
    ~Loop();
    Loop(const Loop&) = delete;
    Loop& operator=(const Loop&) = delete;

    // Associates a socket or file handle with this loop's completion port.
    // Returns 0 or a Win32 error.
    DWORD associate(HANDLE handle);

    // Runs on the calling thread until stop(). Each iteration dequeues a batch
    // of completions (GetQueuedCompletionStatusEx), dispatches them, runs due
    // timers, then runs posted tasks. Blocks no longer than the next timer.
    void run();

    // Thread-safe. run() returns after the current iteration.
    void stop();

    // Thread-safe. Runs `fn` on the loop thread during a later iteration.
    void post(std::function<void()> fn);

    // Loop thread only. Monotonic milliseconds, refreshed once per iteration.
    uint64_t now() const;

    // Loop thread only. Runs `fn` once, no earlier than delay_ms from now().
    TimerId add_timer(uint32_t delay_ms, std::function<void()> fn);

    // Loop thread only. No-op when the timer already fired or was cancelled.
    void cancel_timer(TimerId id);

    HANDLE port() const;

private:
    // Timers live in a slot table (stable ids: generation << 32 | slot) and an
    // indexed binary min-heap over (deadline, seq), so cancel is O(log n) and
    // never leaves stale heap entries behind. seq keeps equal deadlines FIFO.
    static constexpr uint32_t kNotQueued = UINT32_MAX;
    struct TimerSlot {
        std::function<void()> fn;
        uint32_t gen = 1;
        uint32_t heap_pos = kNotQueued;
    };
    struct TimerEntry {
        uint64_t deadline;
        uint64_t seq;
        uint32_t slot;
    };

    DWORD wait_timeout_ms() const;
    void dispatch(const OVERLAPPED_ENTRY* entries, ULONG count);
    void run_timers();
    void run_posted();
    bool heap_less(const TimerEntry& a, const TimerEntry& b) const;
    void heap_place(size_t pos, const TimerEntry& entry);
    void heap_sift_up(size_t pos, TimerEntry entry);
    void heap_sift_down(size_t pos, TimerEntry entry);
    void heap_remove(size_t pos);
    void release_slot(uint32_t slot);

    HANDLE port_ = nullptr;
    uint64_t now_ = 0;
    std::atomic<bool> stop_{false};
    std::vector<OVERLAPPED_ENTRY> entries_;

    std::vector<TimerSlot> timer_slots_;
    std::vector<uint32_t> free_timer_slots_;
    std::vector<TimerEntry> timer_heap_;
    uint64_t timer_seq_ = 0;

    std::mutex post_mutex_;
    std::vector<std::function<void()>> posted_;   // guarded by post_mutex_
    bool wake_pending_ = false;                   // guarded by post_mutex_
    std::vector<std::function<void()>> running_;  // loop thread only
};

}  // namespace wc::net
