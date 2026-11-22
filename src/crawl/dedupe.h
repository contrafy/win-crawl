#pragma once
// Global, thread-safe "seen before?" set of hosts shared by all event loops.
// (The per-IP budget that used to be a second set lives in politeness.h.)
//
// The set is 256 independently locked shards (SRWLOCK) of open-addressing
// tables of 64-bit keys, so concurrent inserts from different loops almost
// never contend: with 16 loops the chance that two simultaneous inserts hit the
// same shard is ~6%, and each critical section is a handful of probes.
//
// HostSet stores a 64-bit hash of the (ASCII-lowercased) host instead of the
// string. Collision math: for n distinct hosts and a uniform 64-bit hash the
// probability that any two collide is about n^2 / 2^65. With the ~825K unique
// hosts of the 1M-URL input that is (8.25e5)^2 / 3.7e19 ~= 1.8e-8, i.e. one
// wrongly dropped host in ~50 million full runs. The payoff is 8 bytes per
// host and no string allocation on the hot path.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace wc::crawl {

// 64-bit hash of `text` with ASCII letters folded to lowercase (DNS names are
// case-insensitive). Exposed for tests.
uint64_t host_hash(std::string_view text);

class ShardedSet64 {
public:
    // `expected` sizes the shards up front so a run of that size never rehashes.
    explicit ShardedSet64(size_t expected = 0);
    ~ShardedSet64();
    ShardedSet64(const ShardedSet64&) = delete;
    ShardedSet64& operator=(const ShardedSet64&) = delete;

    // Thread-safe. `key` must be well mixed: its top bits pick the shard and
    // its low bits the slot. Returns true when `key` was not present.
    bool insert(uint64_t key);
    size_t size() const;

private:
    struct Shard;
    static constexpr size_t kShards = 256;
    std::unique_ptr<Shard[]> shards_;
};

class HostSet {
public:
    explicit HostSet(size_t expected = 0) : set_(expected) {}
    // Thread-safe. True when `host` (case-insensitive) was not seen before.
    bool insert(std::string_view host);
    size_t size() const { return set_.size(); }

private:
    ShardedSet64 set_;
};

}  // namespace wc::crawl
