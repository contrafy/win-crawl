#pragma once
// The crawl engine: N share-nothing IOCP event loops on N threads.
//
// Each loop owns a DNS resolver, a pool of task slots (one URL task and one
// Connection per slot), a link extractor and its own stats block. Loops pull
// URLs from the shared UrlInput in batches and share only the global HostSet
// and the per-IP politeness gates (politeness.h). A loop stops once the input
// is exhausted and it has no live tasks and no politeness waits; run()
// returns once every loop stopped.

#include "crawl/config.h"
#include "crawl/dedupe.h"
#include "crawl/input.h"
#include "crawl/politeness.h"
#include "crawl/record.h"
#include "crawl/stats.h"

#include <atomic>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace wc::crawl {

inline constexpr std::string_view kUserAgent = "wincrawl/2.0 (+https://github.com/contrafy/win-crawl)";
inline constexpr std::string_view kRobotsToken = "wincrawl";  // RFC 9309 product token

class Worker;

class Engine {
public:
    // `input` and `stats` must outlive the engine; `stats` needs at least
    // config.threads blocks (block i belongs to loop i).
    Engine(const Config& config, UrlInput& input, Stats& stats);
    ~Engine();
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    // Crawls until every URL was processed or request_stop() drained the
    // loops. Returns false with a message when the engine cannot start (e.g.
    // no DNS servers). Call once.
    bool run(std::string& error);

    // Thread-safe and safe from a console control handler: stop taking URLs
    // and abort everything in flight; run() returns once the loops drained.
    void request_stop();
    bool stop_requested() const { return stop_.load(std::memory_order_acquire); }

    // --record: lines written (valid after run()).
    uint64_t records_written() const { return records_written_.load(std::memory_order_relaxed); }

private:
    friend class Worker;

    void attach(Worker* worker);
    void detach(Worker* worker);

    const Config& config_;
    UrlInput& input_;
    Stats& stats_;
    HostSet hosts_;
    IpGates gates_;
    RecordWriter records_;
    std::atomic<uint64_t> records_written_{0};
    std::atomic<bool> stop_{false};
    std::mutex mutex_;  // guards workers_ against request_stop() racing loop exit
    std::vector<Worker*> workers_;
};

}  // namespace wc::crawl
