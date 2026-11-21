#include "crawl/dedupe.h"

#include "doctest/doctest.h"

#include <atomic>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace wc::crawl;

TEST_CASE("dedupe: host set is case-insensitive and exact for distinct names") {
    HostSet hosts;
    CHECK(hosts.insert("www.example.com"));
    CHECK_FALSE(hosts.insert("www.example.com"));
    CHECK_FALSE(hosts.insert("WWW.Example.COM"));
    CHECK(hosts.insert("www.example.co"));
    CHECK(hosts.insert("example.com"));
    CHECK(hosts.insert(""));
    CHECK_FALSE(hosts.insert(""));
    CHECK(hosts.size() == 4);
}

TEST_CASE("dedupe: host hash separates near-identical names") {
    // Zero-padded tails and length must not alias.
    CHECK(host_hash("a") != host_hash(std::string_view("a\0", 2)));
    CHECK(host_hash("abcdefgh") != host_hash("abcdefgh0"));
    CHECK(host_hash("h1.bench.test") != host_hash("h2.bench.test"));
    CHECK(host_hash("ABC") == host_hash("abc"));
    // 200K sequential names: no collisions in the full 64 bits.
    std::unordered_set<uint64_t> seen;
    for (int i = 0; i < 200000; ++i) {
        CHECK(seen.insert(host_hash("h" + std::to_string(i) + ".bench.test")).second);
    }
}

TEST_CASE("dedupe: ip set") {
    IpSet ips;
    CHECK(ips.insert(0));
    CHECK_FALSE(ips.insert(0));
    CHECK(ips.insert(0x0100007f));
    CHECK_FALSE(ips.insert(0x0100007f));
    CHECK(ips.insert(0xffffffff));
    CHECK(ips.size() == 3);
}

TEST_CASE("dedupe: concurrent inserts count each key exactly once") {
    HostSet hosts;
    IpSet ips;
    const int threads = 8;
    const int keys = 50000;  // every thread inserts the same keys
    std::atomic<int> new_hosts{0};
    std::atomic<int> new_ips{0};
    std::vector<std::thread> workers;
    for (int t = 0; t < threads; ++t) {
        workers.emplace_back([&, t] {
            std::string name;
            for (int k = 0; k < keys; ++k) {
                // Different start offsets so threads race on the same keys.
                const int i = (k + t * 977) % keys;
                name = "host" + std::to_string(i) + ".example";
                if (hosts.insert(name)) {
                    new_hosts.fetch_add(1);
                }
                if (ips.insert(static_cast<uint32_t>(i * 2654435761u))) {
                    new_ips.fetch_add(1);
                }
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }
    CHECK(new_hosts.load() == keys);
    CHECK(new_ips.load() == keys);
    CHECK(hosts.size() == static_cast<size_t>(keys));
    CHECK(ips.size() == static_cast<size_t>(keys));
}

TEST_CASE("dedupe: presized set grows past its expectation") {
    IpSet ips(16);
    for (uint32_t i = 0; i < 100000; ++i) {
        CHECK(ips.insert(i));
    }
    for (uint32_t i = 0; i < 100000; i += 7) {
        CHECK_FALSE(ips.insert(i));
    }
    CHECK(ips.size() == 100000);
}
