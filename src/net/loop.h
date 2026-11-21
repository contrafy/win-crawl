#pragma once
// Single-threaded I/O completion port event loop.
//
// Threading model: one Loop per worker thread, share-nothing. Everything that
// belongs to a loop (sockets, timers, per-connection state) is touched only on
// that loop's thread. The only thread-safe entry points are post() and stop().

#include <winsock2.h>
#include <windows.h>

#include <cstdint>
#include <functional>

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
};

}  // namespace wc::net
