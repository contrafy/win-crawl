#include "crawl/dedupe.h"

#include <windows.h>

#include <intrin.h>

#include <cstring>
#include <vector>

namespace wc::crawl {

namespace {

// 64x64 -> 128 multiply folded to 64 bits (the wyhash "mum" primitive).
inline uint64_t mum(uint64_t a, uint64_t b) {
    uint64_t hi = 0;
    const uint64_t lo = _umul128(a, b, &hi);
    return lo ^ hi;
}

// MurmurHash3 finalizer: a bijection on uint64_t with full avalanche.
inline uint64_t fmix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdull;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ull;
    k ^= k >> 33;
    return k;
}

inline uint64_t load_lower8(const char* p, size_t n) {
    unsigned char buf[8] = {};
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(p[i]);
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<unsigned char>(c + ('a' - 'A'));
        }
        buf[i] = c;
    }
    uint64_t v;
    std::memcpy(&v, buf, sizeof(v));
    return v;
}

constexpr uint64_t kSecret0 = 0xa0761d6478bd642full;
constexpr uint64_t kSecret1 = 0xe7037ed1a0b428dbull;
constexpr uint64_t kSecret2 = 0x8ebc6af09c88c6e3ull;
constexpr uint64_t kSecret3 = 0x589965cc75374cc3ull;

}  // namespace

uint64_t host_hash(std::string_view text) {
    // wyhash-style: each 8-byte word is folded into the state by a 128-bit
    // multiply, the length seeds the state so zero-padded tails stay distinct.
    const size_t len = text.size();
    uint64_t state = kSecret0 ^ mum(len ^ kSecret1, kSecret2);
    const char* p = text.data();
    size_t left = len;
    while (left > 0) {
        const size_t n = left < 8 ? left : 8;
        state = mum(load_lower8(p, n) ^ kSecret1, state ^ kSecret3);
        p += n;
        left -= n;
    }
    return fmix64(mum(state ^ kSecret2, len ^ kSecret0));
}

// Each shard owns its cache line(s) so loops hammering different shards never
// bounce a shared line; the padding C4324 reports is the point.
#pragma warning(push)
#pragma warning(disable : 4324)
struct alignas(64) ShardedSet64::Shard {
    SRWLOCK lock = SRWLOCK_INIT;
    bool has_zero = false;  // 0 marks empty slots, so a zero key is tracked aside
    size_t count = 0;       // includes the zero key
    size_t mask = 0;
    std::vector<uint64_t> slots;

    void init(size_t capacity) {
        slots.assign(capacity, 0);
        mask = capacity - 1;
    }

    // Linear probing. Returns false when present.
    bool place(uint64_t key) {
        size_t i = static_cast<size_t>(key) & mask;
        for (;;) {
            uint64_t& slot = slots[i];
            if (slot == key) {
                return false;
            }
            if (slot == 0) {
                slot = key;
                return true;
            }
            i = (i + 1) & mask;
        }
    }

    void grow() {
        std::vector<uint64_t> old;
        old.swap(slots);
        init(old.size() * 2);
        for (uint64_t key : old) {
            if (key != 0) {
                place(key);
            }
        }
    }
};
#pragma warning(pop)

namespace {

size_t initial_capacity(size_t expected_per_shard) {
    // Keep the load factor under ~0.5 for the expected size.
    size_t cap = 64;
    while (cap < expected_per_shard * 2) {
        cap <<= 1;
    }
    return cap;
}

}  // namespace

ShardedSet64::ShardedSet64(size_t expected) : shards_(new Shard[kShards]) {
    const size_t cap = initial_capacity(expected / kShards + 1);
    for (size_t i = 0; i < kShards; ++i) {
        shards_[i].init(cap);
    }
}

ShardedSet64::~ShardedSet64() = default;

bool ShardedSet64::insert(uint64_t key) {
    Shard& shard = shards_[static_cast<size_t>(key >> 56)];
    AcquireSRWLockExclusive(&shard.lock);
    bool inserted;
    if (key == 0) {
        inserted = !shard.has_zero;
        shard.has_zero = true;
    } else {
        // Grow at 5/8 load so linear probe chains stay short.
        if ((shard.count + 1) * 8 > shard.slots.size() * 5) {
            shard.grow();
        }
        inserted = shard.place(key);
    }
    if (inserted) {
        ++shard.count;
    }
    ReleaseSRWLockExclusive(&shard.lock);
    return inserted;
}

size_t ShardedSet64::size() const {
    size_t total = 0;
    for (size_t i = 0; i < kShards; ++i) {
        Shard& shard = shards_[i];
        AcquireSRWLockShared(&shard.lock);
        total += shard.count;
        ReleaseSRWLockShared(&shard.lock);
    }
    return total;
}

bool HostSet::insert(std::string_view host) {
    return set_.insert(host_hash(host));
}

}  // namespace wc::crawl
