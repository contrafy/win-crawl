#include "crawl/politeness.h"

#include "crawl/ipranges.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <vector>

namespace wc::crawl {

namespace {

// MurmurHash3 finalizer: a bijection with full avalanche, so the top bits
// pick a shard and the low bits a slot.
uint64_t mix_ip(uint32_t ip) {
    uint64_t k = static_cast<uint64_t>(ip) + 1;
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdull;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ull;
    k ^= k >> 33;
    return k;
}

size_t initial_capacity(size_t expected_per_shard) {
    size_t cap = 64;
    while (cap < expected_per_shard * 2) {
        cap <<= 1;
    }
    return cap;
}

}  // namespace

uint64_t gate_clock_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

struct IpGates::Gate {
    uint64_t next_ms = 0;  // earliest next connection start (gate clock)
    GateWaiter* head = nullptr;
    GateWaiter* tail = nullptr;
    GateWaiter* prio_tail = nullptr;  // last priority waiter; priority waiters form a prefix
    uint32_t ip = 0;
    uint32_t hosts = 0;   // hosts charged to the budget
    uint32_t active = 0;  // connection slots held
    uint32_t prio_waiting = 0;
    uint32_t penalty_ms = 0;
    uint16_t fails = 0;  // consecutive failed connections
    bool cdn = false;
    bool dead = false;
    bool timer_armed = false;
};

// Each shard owns its cache line(s) so loops on different shards never
// bounce a shared line; the padding C4324 reports is the point.
#pragma warning(push)
#pragma warning(disable : 4324)
struct alignas(64) IpGates::Shard {
    SRWLOCK lock = SRWLOCK_INIT;
    size_t mask = 0;
    // 0 = empty, else ip << 32 | (index into gates + 1).
    std::vector<uint64_t> slots;
    std::vector<Gate> gates;

    void init(size_t capacity) {
        slots.assign(capacity, 0);
        mask = capacity - 1;
    }

    Gate* find(uint32_t ip) {
        size_t i = static_cast<size_t>(mix_ip(ip)) & mask;
        for (;;) {
            const uint64_t slot = slots[i];
            if (slot == 0) {
                return nullptr;
            }
            if (static_cast<uint32_t>(slot >> 32) == ip) {
                return &gates[static_cast<uint32_t>(slot) - 1];
            }
            i = (i + 1) & mask;
        }
    }

    void place(uint32_t ip, size_t index) {
        size_t i = static_cast<size_t>(mix_ip(ip)) & mask;
        while (slots[i] != 0) {
            i = (i + 1) & mask;
        }
        slots[i] = static_cast<uint64_t>(ip) << 32 | (index + 1);
    }

    // Gate pointers stay valid only until the next insert (the vector may
    // grow); callers use them inside one locked section.
    Gate& get(uint32_t ip, const GatePolicy& policy) {
        if (Gate* g = find(ip)) {
            return *g;
        }
        // Grow at 5/8 load so probe chains stay short.
        if ((gates.size() + 1) * 8 > slots.size() * 5) {
            init(slots.size() * 2);
            for (size_t k = 0; k < gates.size(); ++k) {
                place(gates[k].ip, k);
            }
        }
        gates.emplace_back();
        Gate& g = gates.back();
        g.ip = ip;
        g.cdn = policy.cdn_ranges != nullptr && policy.cdn_ranges->contains(ip);
        place(ip, gates.size() - 1);
        return g;
    }
};
#pragma warning(pop)

namespace {

class ShardLock {
public:
    explicit ShardLock(SRWLOCK& lock) : lock_(lock) { AcquireSRWLockExclusive(&lock_); }
    ~ShardLock() { ReleaseSRWLockExclusive(&lock_); }
    ShardLock(const ShardLock&) = delete;
    ShardLock& operator=(const ShardLock&) = delete;

private:
    SRWLOCK& lock_;
};

}  // namespace

IpGates::IpGates(const GatePolicy& policy, size_t expected_ips) : policy_(policy), shards_(new Shard[kShards]) {
    const size_t cap = initial_capacity(expected_ips / kShards + 1);
    for (size_t i = 0; i < kShards; ++i) {
        shards_[i].init(cap);
    }
}

IpGates::~IpGates() = default;

IpGates::Shard& IpGates::shard_of(uint32_t ip) const {
    return shards_[static_cast<size_t>(mix_ip(ip) >> 56)];
}

const IpLimits& IpGates::limits(const Gate& gate) const {
    return gate.cdn ? policy_.cdn : policy_.ip;
}

bool IpGates::has_room(const Gate& gate) const {
    const uint32_t cap = limits(gate).concurrency;
    return cap == 0 || gate.active < cap;
}

uint32_t IpGates::spacing(const Gate& gate) const {
    return limits(gate).interval_ms + gate.penalty_ms;
}

void IpGates::admit(Gate& gate, uint64_t now) {
    ++gate.active;
    gate.next_ms = std::max(gate.next_ms, now) + spacing(gate);
}

void IpGates::enqueue(Gate& gate, GateWaiter* waiter, bool priority) {
    waiter->ip = gate.ip;
    waiter->state = GateWaiter::State::Queued;
    waiter->priority = priority;
    GateWaiter* after = priority ? gate.prio_tail : gate.tail;
    waiter->prev = after;
    waiter->next = after != nullptr ? after->next : gate.head;
    if (after != nullptr) {
        after->next = waiter;
    } else {
        gate.head = waiter;
    }
    if (waiter->next != nullptr) {
        waiter->next->prev = waiter;
    } else {
        gate.tail = waiter;
    }
    if (priority) {
        gate.prio_tail = waiter;
        ++gate.prio_waiting;
    }
}

void IpGates::unlink(Gate& gate, GateWaiter* waiter) {
    if (waiter->prev != nullptr) {
        waiter->prev->next = waiter->next;
    } else {
        gate.head = waiter->next;
    }
    if (waiter->next != nullptr) {
        waiter->next->prev = waiter->prev;
    } else {
        gate.tail = waiter->prev;
    }
    if (waiter->priority) {
        --gate.prio_waiting;
        if (gate.prio_tail == waiter) {
            gate.prio_tail = waiter->prev;  // everything before a priority waiter is one too
        }
    }
    waiter->prev = nullptr;
    waiter->next = nullptr;
}

void IpGates::note(Gate& gate, Outcome outcome, uint32_t retry_after_ms, uint64_t now) {
    const IpLimits& lim = limits(gate);
    switch (outcome) {
    case Outcome::None:
        break;
    case Outcome::Replied:
        gate.fails = 0;
        // Each normal reply halves the penalty again.
        gate.penalty_ms = gate.penalty_ms / 2 < 100 ? 0 : gate.penalty_ms / 2;
        break;
    case Outcome::Failed:
        if (gate.fails < UINT16_MAX) {
            ++gate.fails;
        }
        if (policy_.fail_limit != 0 && gate.fails >= policy_.fail_limit) {
            gate.dead = true;
        }
        break;
    case Outcome::Throttled: {
        gate.fails = 0;
        if (!lim.backoff) {
            break;  // CDN edge: one origin's rate limit says nothing about the others
        }
        const uint32_t floor = std::max<uint32_t>(lim.interval_ms, 1000);
        const uint64_t doubled = std::max<uint64_t>(2ull * gate.penalty_ms, floor);
        gate.penalty_ms = static_cast<uint32_t>(std::min<uint64_t>(doubled, policy_.max_penalty_ms));
        const uint64_t push = std::max<uint64_t>(gate.penalty_ms, std::min(retry_after_ms, policy_.max_penalty_ms));
        gate.next_ms = std::max(gate.next_ms, now + push);
        break;
    }
    }
}

uint32_t IpGates::dispatch(Gate& gate, uint64_t now, GateWaiter*& woken) {
    GateWaiter* tail = nullptr;
    const auto append = [&](GateWaiter* w) {
        if (tail != nullptr) {
            tail->next = w;
        } else {
            woken = w;
        }
        tail = w;
    };
    if (gate.dead) {
        while (GateWaiter* w = gate.head) {
            unlink(gate, w);
            w->state = GateWaiter::State::Unreachable;
            append(w);
        }
        return 0;
    }
    while (gate.head != nullptr && has_room(gate)) {
        if (gate.next_ms > now) {
            if (gate.timer_armed) {
                return 0;
            }
            gate.timer_armed = true;
            return static_cast<uint32_t>(std::min<uint64_t>(gate.next_ms - now, UINT32_MAX));
        }
        GateWaiter* w = gate.head;
        unlink(gate, w);
        w->state = GateWaiter::State::Admitted;
        admit(gate, now);
        append(w);
    }
    return 0;
}

void IpGates::deliver(GateWaiter* woken, uint32_t ip, uint32_t timer_ms, GateEvents& events) {
    if (timer_ms != 0) {
        events.arm_gate_timer(ip, timer_ms);
    }
    while (woken != nullptr) {
        GateWaiter* next = woken->next;  // on_wake may reuse the waiter at once
        woken->next = nullptr;
        events.on_wake(woken);
        woken = next;
    }
}

SeedResult IpGates::seed(uint32_t ip, GateWaiter* waiter, uint64_t now, GateEvents& events) {
    SeedResult result;
    GateWaiter* woken = nullptr;
    uint32_t timer = 0;
    {
        Shard& shard = shard_of(ip);
        ShardLock lock(shard.lock);
        Gate& gate = shard.get(ip, policy_);
        result.cdn = gate.cdn;
        const uint32_t budget = limits(gate).hosts;
        if (budget != 0 && gate.hosts >= budget) {
            result.budget = Budget::Over;
            return result;
        }
        if (gate.dead) {
            result.budget = Budget::Unreachable;
            return result;
        }
        result.budget = gate.hosts == 0 ? Budget::First : Budget::Extra;
        ++gate.hosts;
        if (gate.head == nullptr && has_room(gate) && gate.next_ms <= now) {
            admit(gate, now);
            result.admit = Admit::Now;
            return result;
        }
        enqueue(gate, waiter, false);
        result.admit = Admit::Queued;
        timer = dispatch(gate, now, woken);
    }
    deliver(woken, ip, timer, events);
    return result;
}

Admit IpGates::acquire(uint32_t ip, GateWaiter* waiter, uint32_t max_waiters, uint64_t now, GateEvents& events) {
    GateWaiter* woken = nullptr;
    uint32_t timer = 0;
    {
        Shard& shard = shard_of(ip);
        ShardLock lock(shard.lock);
        Gate& gate = shard.get(ip, policy_);
        if (gate.dead) {
            return Admit::Unreachable;
        }
        // Sites under way go ahead of queued new sites.
        if (gate.prio_waiting == 0 && has_room(gate) && gate.next_ms <= now) {
            admit(gate, now);
            return Admit::Now;
        }
        if (max_waiters != 0 && gate.prio_waiting >= max_waiters) {
            return Admit::Busy;
        }
        enqueue(gate, waiter, true);
        timer = dispatch(gate, now, woken);
    }
    deliver(woken, ip, timer, events);
    return Admit::Queued;
}

uint32_t IpGates::restart(uint32_t ip, Outcome outcome, uint32_t retry_after_ms, uint64_t now) {
    Shard& shard = shard_of(ip);
    ShardLock lock(shard.lock);
    Gate& gate = shard.get(ip, policy_);
    note(gate, outcome, retry_after_ms, now);
    const uint64_t start = std::max(gate.next_ms, now);
    gate.next_ms = start + spacing(gate);
    return static_cast<uint32_t>(std::min<uint64_t>(start - now, UINT32_MAX));
}

void IpGates::release(uint32_t ip, Outcome outcome, uint32_t retry_after_ms, uint64_t now, GateEvents& events) {
    GateWaiter* woken = nullptr;
    uint32_t timer = 0;
    {
        Shard& shard = shard_of(ip);
        ShardLock lock(shard.lock);
        Gate& gate = shard.get(ip, policy_);
        if (gate.active > 0) {
            --gate.active;
        }
        note(gate, outcome, retry_after_ms, now);
        timer = dispatch(gate, now, woken);
    }
    deliver(woken, ip, timer, events);
}

bool IpGates::cancel(GateWaiter* waiter) {
    Shard& shard = shard_of(waiter->ip);
    ShardLock lock(shard.lock);
    if (waiter->state != GateWaiter::State::Queued) {
        return false;
    }
    Gate* gate = shard.find(waiter->ip);
    unlink(*gate, waiter);
    waiter->state = GateWaiter::State::Cancelled;
    return true;
}

void IpGates::on_timer(uint32_t ip, uint64_t now, GateEvents& events) {
    GateWaiter* woken = nullptr;
    uint32_t timer = 0;
    {
        Shard& shard = shard_of(ip);
        ShardLock lock(shard.lock);
        Gate* gate = shard.find(ip);
        if (gate == nullptr) {
            return;
        }
        gate->timer_armed = false;
        timer = dispatch(*gate, now, woken);
    }
    deliver(woken, ip, timer, events);
}

bool IpGates::is_cdn(uint32_t ip) const {
    return policy_.cdn_ranges != nullptr && policy_.cdn_ranges->contains(ip);
}

size_t IpGates::size() const {
    size_t total = 0;
    for (size_t i = 0; i < kShards; ++i) {
        Shard& shard = shards_[i];
        AcquireSRWLockShared(&shard.lock);
        total += shard.gates.size();
        ReleaseSRWLockShared(&shard.lock);
    }
    return total;
}

// ---------------------------------------------------------------- Retry-After

namespace {

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

char lower(char c) {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

bool iprefix(std::string_view text, std::string_view word) {
    if (text.size() < word.size()) {
        return false;
    }
    for (size_t i = 0; i < word.size(); ++i) {
        if (lower(text[i]) != word[i]) {
            return false;
        }
    }
    return true;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

// Reads exactly `n` digits.
bool take_digits(std::string_view& s, size_t n, unsigned& out) {
    if (s.size() < n) {
        return false;
    }
    unsigned v = 0;
    for (size_t i = 0; i < n; ++i) {
        if (!is_digit(s[i])) {
            return false;
        }
        v = v * 10 + static_cast<unsigned>(s[i] - '0');
    }
    out = v;
    s.remove_prefix(n);
    return true;
}

bool take(std::string_view& s, char c) {
    if (s.empty() || s.front() != c) {
        return false;
    }
    s.remove_prefix(1);
    return true;
}

bool take_word(std::string_view& s, std::string_view word) {
    if (!iprefix(s, word)) {
        return false;
    }
    s.remove_prefix(word.size());
    return true;
}

constexpr std::string_view kMonths[12] = {"jan", "feb", "mar", "apr", "may", "jun",
                                          "jul", "aug", "sep", "oct", "nov", "dec"};
constexpr std::string_view kDays[7] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};
constexpr std::string_view kLongDays[7] = {"monday", "tuesday", "wednesday", "thursday",
                                           "friday", "saturday", "sunday"};

bool take_month(std::string_view& s, unsigned& month) {
    for (unsigned m = 0; m < 12; ++m) {
        if (take_word(s, kMonths[m])) {
            month = m + 1;
            return true;
        }
    }
    return false;
}

// "HH:MM:SS"
bool take_time(std::string_view& s, unsigned& h, unsigned& m, unsigned& sec) {
    return take_digits(s, 2, h) && take(s, ':') && take_digits(s, 2, m) && take(s, ':') && take_digits(s, 2, sec) &&
           h < 24 && m < 60 && sec <= 60;  // 60: leap second
}

// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2 ? 1 : 0;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

}  // namespace

std::optional<int64_t> parse_http_date(std::string_view value) {
    std::string_view s = trim(value);
    unsigned day = 0;
    unsigned month = 0;
    unsigned year = 0;
    unsigned h = 0;
    unsigned m = 0;
    unsigned sec = 0;
    bool long_day = false;
    bool short_day = false;
    for (size_t i = 0; i < 7 && !long_day; ++i) {
        long_day = take_word(s, kLongDays[i]);
    }
    for (size_t i = 0; i < 7 && !long_day && !short_day; ++i) {
        short_day = take_word(s, kDays[i]);
    }
    if (!long_day && !short_day) {
        return std::nullopt;
    }
    if (long_day) {
        // rfc850-date: "Sunday, 06-Nov-94 08:49:37 GMT"
        unsigned yy = 0;
        if (!take(s, ',') || !take(s, ' ') || !take_digits(s, 2, day) || !take(s, '-') || !take_month(s, month) ||
            !take(s, '-') || !take_digits(s, 2, yy) || !take(s, ' ') || !take_time(s, h, m, sec) || !take(s, ' ') ||
            !take_word(s, "gmt")) {
            return std::nullopt;
        }
        year = yy < 70 ? 2000 + yy : 1900 + yy;
    } else if (take(s, ',')) {
        // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
        if (!take(s, ' ') || !take_digits(s, 2, day) || !take(s, ' ') || !take_month(s, month) || !take(s, ' ') ||
            !take_digits(s, 4, year) || !take(s, ' ') || !take_time(s, h, m, sec) || !take(s, ' ') ||
            !take_word(s, "gmt")) {
            return std::nullopt;
        }
    } else {
        // asctime-date: "Sun Nov  6 08:49:37 1994"
        if (!take(s, ' ') || !take_month(s, month) || !take(s, ' ')) {
            return std::nullopt;
        }
        if (take(s, ' ')) {
            if (!take_digits(s, 1, day)) {
                return std::nullopt;
            }
        } else if (!take_digits(s, 2, day)) {
            return std::nullopt;
        }
        if (!take(s, ' ') || !take_time(s, h, m, sec) || !take(s, ' ') || !take_digits(s, 4, year)) {
            return std::nullopt;
        }
    }
    if (!s.empty() || day < 1 || day > 31) {
        return std::nullopt;
    }
    return days_from_civil(year, month, day) * 86400 + static_cast<int64_t>(h) * 3600 + m * 60 + sec;
}

std::optional<uint64_t> parse_retry_after(std::string_view value, int64_t now_unix) {
    const std::string_view s = trim(value);
    if (s.empty()) {
        return std::nullopt;
    }
    if (std::all_of(s.begin(), s.end(), is_digit)) {
        constexpr uint64_t kMax = UINT32_MAX;  // ~136 years: anything longer is "never" anyway
        uint64_t v = 0;
        for (char c : s) {
            v = v * 10 + static_cast<uint64_t>(c - '0');
            if (v > kMax) {
                return kMax;
            }
        }
        return v;
    }
    const std::optional<int64_t> date = parse_http_date(s);
    if (!date) {
        return std::nullopt;
    }
    return *date > now_unix ? static_cast<uint64_t>(*date - now_unix) : 0;
}

}  // namespace wc::crawl
