#include "net/loop.h"

#include "net/detail.h"

#include <winternl.h>

#include <cassert>
#include <mutex>
#include <utility>

namespace wc::net {

namespace {

constexpr ULONG kBatch = 256;

// A wake packet carries no OVERLAPPED; real I/O always does.
constexpr ULONG_PTR kWakeKey = 1;

detail::Extensions g_extensions;

template <typename Fn>
bool load_extension(SOCKET s, GUID guid, Fn& out) {
    DWORD bytes = 0;
    return WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &out, sizeof(out), &bytes,
                    nullptr, nullptr) == 0;
}

}  // namespace

void startup() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            return;
        }
        // Extension pointers are per provider; every wincrawl socket is IPv4 TCP
        // from the default provider, so one lookup serves the whole process.
        SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (s == INVALID_SOCKET) {
            return;
        }
        load_extension(s, WSAID_CONNECTEX, g_extensions.connect_ex);
        load_extension(s, WSAID_ACCEPTEX, g_extensions.accept_ex);
        load_extension(s, WSAID_GETACCEPTEXSOCKADDRS, g_extensions.get_accept_ex_sockaddrs);
        closesocket(s);
    });
}

const detail::Extensions& detail::extensions() {
    return g_extensions;
}

Loop::Loop() : entries_(kBatch) {
    startup();
    port_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    now_ = GetTickCount64();
}

Loop::~Loop() {
    if (port_ != nullptr) {
        CloseHandle(port_);
    }
}

DWORD Loop::associate(HANDLE handle) {
    if (CreateIoCompletionPort(handle, port_, 0, 0) == nullptr) {
        return GetLastError();
    }
    // Completion is always reported through the port; skipping the event
    // signal saves a kernel object touch per operation.
    if (!SetFileCompletionNotificationModes(handle, FILE_SKIP_SET_EVENT_ON_HANDLE)) {
        return GetLastError();
    }
    return 0;
}

HANDLE Loop::port() const {
    return port_;
}

uint64_t Loop::now() const {
    return now_;
}

void Loop::stop() {
    stop_.store(true, std::memory_order_release);
    PostQueuedCompletionStatus(port_, 0, kWakeKey, nullptr);
}

void Loop::post(std::function<void()> fn) {
    bool wake = false;
    {
        std::lock_guard lock(post_mutex_);
        posted_.push_back(std::move(fn));
        if (!wake_pending_) {
            wake_pending_ = true;
            wake = true;
        }
    }
    // One packet per drain, however many tasks pile up before the loop runs.
    if (wake) {
        PostQueuedCompletionStatus(port_, 0, kWakeKey, nullptr);
    }
}

void Loop::run() {
    while (!stop_.load(std::memory_order_acquire)) {
        ULONG count = 0;
        if (!GetQueuedCompletionStatusEx(port_, entries_.data(), kBatch, &count, wait_timeout_ms(), FALSE)) {
            count = 0;  // WAIT_TIMEOUT: timers are due
        }
        now_ = GetTickCount64();
        dispatch(entries_.data(), count);
        run_timers();
        run_posted();
    }
    stop_.store(false, std::memory_order_relaxed);
}

DWORD Loop::wait_timeout_ms() const {
    if (timer_heap_.empty()) {
        return INFINITE;
    }
    const uint64_t deadline = timer_heap_.front().deadline;
    const uint64_t now = GetTickCount64();
    if (deadline <= now) {
        return 0;
    }
    const uint64_t wait = deadline - now;
    return wait >= INFINITE ? INFINITE - 1 : static_cast<DWORD>(wait);
}

void Loop::dispatch(const OVERLAPPED_ENTRY* entries, ULONG count) {
    for (ULONG i = 0; i < count; ++i) {
        OVERLAPPED* ov = entries[i].lpOverlapped;
        if (ov == nullptr) {
            continue;  // wake packet; posted tasks run below
        }
        auto* req = CONTAINING_RECORD(ov, IoRequest, ov);
        const auto status = static_cast<NTSTATUS>(ov->Internal);
        const DWORD error = status == 0 ? 0 : RtlNtStatusToDosError(status);
        req->complete(req, entries[i].dwNumberOfBytesTransferred, error);
    }
}

// --- timers -----------------------------------------------------------------

TimerId Loop::add_timer(uint32_t delay_ms, std::function<void()> fn) {
    uint32_t slot;
    if (!free_timer_slots_.empty()) {
        slot = free_timer_slots_.back();
        free_timer_slots_.pop_back();
    } else {
        slot = static_cast<uint32_t>(timer_slots_.size());
        timer_slots_.emplace_back();
    }
    TimerSlot& s = timer_slots_[slot];
    s.fn = std::move(fn);
    timer_heap_.emplace_back();
    heap_sift_up(timer_heap_.size() - 1, TimerEntry{now_ + delay_ms, timer_seq_++, slot});
    return (static_cast<TimerId>(s.gen) << 32) | slot;
}

void Loop::cancel_timer(TimerId id) {
    const auto slot = static_cast<uint32_t>(id);
    const auto gen = static_cast<uint32_t>(id >> 32);
    if (slot >= timer_slots_.size()) {
        return;
    }
    TimerSlot& s = timer_slots_[slot];
    if (s.gen != gen || s.heap_pos == kNotQueued) {
        return;
    }
    heap_remove(s.heap_pos);
    // Destroy the callable after the slot is consistent: its captures'
    // destructors may legitimately call back into the timer API.
    std::function<void()> dead = std::move(s.fn);
    release_slot(slot);
}

void Loop::run_timers() {
    // Timers added by callbacks get a later seq; stopping there keeps a
    // zero-delay timer that re-arms itself from monopolising the iteration.
    const uint64_t seq_limit = timer_seq_;
    while (!timer_heap_.empty()) {
        const TimerEntry top = timer_heap_.front();
        if (top.deadline > now_ || top.seq >= seq_limit) {
            break;
        }
        heap_remove(0);
        std::function<void()> fn = std::move(timer_slots_[top.slot].fn);
        release_slot(top.slot);
        fn();
    }
}

void Loop::release_slot(uint32_t slot) {
    TimerSlot& s = timer_slots_[slot];
    s.fn = nullptr;
    s.heap_pos = kNotQueued;
    if (++s.gen == 0) {
        s.gen = 1;  // keep ids non-zero
    }
    free_timer_slots_.push_back(slot);
}

bool Loop::heap_less(const TimerEntry& a, const TimerEntry& b) const {
    return a.deadline != b.deadline ? a.deadline < b.deadline : a.seq < b.seq;
}

void Loop::heap_place(size_t pos, const TimerEntry& entry) {
    timer_heap_[pos] = entry;
    timer_slots_[entry.slot].heap_pos = static_cast<uint32_t>(pos);
}

void Loop::heap_sift_up(size_t pos, TimerEntry entry) {
    while (pos > 0) {
        const size_t parent = (pos - 1) / 2;
        if (!heap_less(entry, timer_heap_[parent])) {
            break;
        }
        heap_place(pos, timer_heap_[parent]);
        pos = parent;
    }
    heap_place(pos, entry);
}

void Loop::heap_sift_down(size_t pos, TimerEntry entry) {
    const size_t n = timer_heap_.size();
    for (;;) {
        size_t child = 2 * pos + 1;
        if (child >= n) {
            break;
        }
        if (child + 1 < n && heap_less(timer_heap_[child + 1], timer_heap_[child])) {
            ++child;
        }
        if (!heap_less(timer_heap_[child], entry)) {
            break;
        }
        heap_place(pos, timer_heap_[child]);
        pos = child;
    }
    heap_place(pos, entry);
}

void Loop::heap_remove(size_t pos) {
    timer_slots_[timer_heap_[pos].slot].heap_pos = kNotQueued;
    const TimerEntry last = timer_heap_.back();
    timer_heap_.pop_back();
    if (pos == timer_heap_.size()) {
        return;
    }
    if (pos > 0 && heap_less(last, timer_heap_[(pos - 1) / 2])) {
        heap_sift_up(pos, last);
    } else {
        heap_sift_down(pos, last);
    }
}

// --- posted tasks -------------------------------------------------------------

void Loop::run_posted() {
    {
        std::lock_guard lock(post_mutex_);
        if (posted_.empty()) {
            return;
        }
        running_.swap(posted_);
        wake_pending_ = false;
    }
    // Tasks posted while these run land in posted_ and trigger a fresh wake,
    // so they run next iteration rather than starving I/O.
    for (auto& fn : running_) {
        fn();
    }
    running_.clear();
}

}  // namespace wc::net
