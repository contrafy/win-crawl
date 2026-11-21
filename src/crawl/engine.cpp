#include "crawl/engine.h"

#include "crawl/connection.h"
#include "dns/resolver.h"
#include "dns/servers.h"
#include "net/addr.h"
#include "net/loop.h"
#include "parse/links.h"
#include "parse/robots.h"
#include "parse/url.h"
#include "tls/tls.h"

#include <algorithm>
#include <memory>
#include <thread>

namespace wc::crawl {

namespace {

constexpr size_t kClaimBatch = 32;
constexpr uint32_t kDnsSyncMs = 250;
constexpr uint32_t kDrainPollMs = 5;
constexpr unsigned kMaxRobotsRedirects = 5;  // RFC 9309 §2.3.1.2
// Out of ephemeral ports: retry the same fetch after 50, 100, ... 1000 ms
// (about 15 s in total) before giving up on the URL as a connect failure.
constexpr unsigned kMaxPortRetries = 20;
constexpr uint32_t kPortRetryBaseMs = 50;
constexpr uint32_t kPortRetryMaxMs = 1000;

bool ascii_iprefix(std::string_view text, std::string_view prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }
    for (size_t i = 0; i < prefix.size(); ++i) {
        char c = text[i];
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c + ('a' - 'A'));
        }
        if (c != prefix[i]) {
            return false;
        }
    }
    return true;
}

bool is_html(const parse::ResponseParser& reply) {
    const std::string_view type = reply.header("Content-Type");
    return ascii_iprefix(type, "text/html") || ascii_iprefix(type, "application/xhtml+xml");
}

Counter status_counter(int status) {
    if (status >= 200 && status < 300) return Counter::Http2xx;
    if (status >= 300 && status < 400) return Counter::Http3xx;
    if (status >= 400 && status < 500) return Counter::Http4xx;
    if (status >= 500 && status < 600) return Counter::Http5xx;
    return Counter::HttpOther;
}

bool same_origin(const parse::Url& a, const parse::Url& b) {
    return a.scheme == b.scheme && a.port == b.port && a.host == b.host;
}

}  // namespace

class Task;

// Everything one event loop owns. Constructed, run and destroyed on its own
// thread; only request_stop() is reached from elsewhere, through post().
class Worker {
public:
    Worker(Engine& engine, size_t index, unsigned slots, unsigned dns_inflight,
           const std::vector<sockaddr_in>& dns_servers);
    ~Worker();

    void run();
    net::Loop& loop() { return loop_; }
    void stop();  // loop thread

    // Shared with tasks.
    Engine& engine_;
    const Config& cfg_;
    CounterBlock& stats_;
    net::Loop loop_;
    dns::Resolver resolver_;
    parse::LinkExtractor links_;
    bool stopping_ = false;

    void task_done(Task* task);
    bool new_host(std::string_view host) { return engine_.hosts_.insert(host); }
    bool new_ip(uint32_t ipv4_be) { return engine_.ips_.insert(ipv4_be); }

private:
    void start();
    void arm_dns_timer();
    void pump();
    bool next_url(std::string_view& out);
    void maybe_finish();
    void sync_dns_counters();
    void drain();

    std::vector<std::unique_ptr<Task>> tasks_;
    std::vector<Task*> free_;
    std::vector<std::string_view> batch_;
    size_t batch_pos_ = 0;
    size_t live_ = 0;
    bool input_done_ = false;
    bool pumping_ = false;
    bool finishing_ = false;
    net::TimerId dns_timer_ = 0;
};

// One URL through the pipeline. Classic and real mode share the skeleton:
//   parse -> unique host -> DNS -> unique IP -> robots -> page.
// Real mode adds GET robots with RFC 9309 semantics, redirects (each new
// origin gets DNS and its own robots check, without host/IP dedupe) and TLS.
class Task final : public FetchHandler {
public:
    explicit Task(Worker& w)
        : w_(w),
          conn_(w.loop_, *this, &w.stats_, w.cfg_.insecure ? tls::Verify::None : tls::Verify::Chain) {}

    void start(std::string_view line);
    void abort();
    bool busy() const { return conn_.busy(); }

private:
    enum class Phase : uint8_t { Idle, Dns, Robots, RobotsDns, Page, PageDns };
    enum class Policy : uint8_t { AllowAll, DisallowAll, Rules };

    bool real() const { return w_.cfg_.mode == Mode::Real; }
    void resolve(Phase phase, const std::string& host);
    void on_dns(dns::Status status, uint32_t ipv4_be);
    void on_fetch(Connection& connection, const FetchResult& result) override;
    void count_failure(FetchError error);
    bool retry_later(FetchError error);

    void start_robots();
    void fetch_robots();
    void on_robots(const FetchResult& result);
    void robots_decided(Policy policy);
    void fetch_page();
    void on_page(const FetchResult& result);
    void finish();

    void build_request(std::string_view method, const parse::Url& url);
    Endpoint endpoint(const parse::Url& url, uint32_t ipv4_be) const;

    Worker& w_;
    Connection conn_;
    Phase phase_ = Phase::Idle;
    parse::Url page_;    // current page URL (the seed, then redirect hops)
    parse::Url robots_;  // current robots.txt URL (follows robots redirects)
    parse::Url next_;    // scratch for redirect resolution
    std::string request_;
    uint32_t page_ip_ = 0;
    uint32_t robots_ip_ = 0;
    unsigned robots_hops_ = 0;
    unsigned page_hops_ = 0;
    Policy policy_ = Policy::AllowAll;
    parse::RobotsRules rules_;
    bool funnel_ = true;          // the first robots decision feeds robots_passed
    bool page_attempted_ = false;
    bool page_replied_ = false;   // at least one page reply: counts as crawled
    int last_status_ = 0;
    unsigned port_retries_ = 0;
    net::TimerId retry_timer_ = 0;
};

// ---------------------------------------------------------------- Task

void Task::start(std::string_view line) {
    CounterBlock& st = w_.stats_;
    st.add(Counter::UrlsRead);
    phase_ = Phase::Idle;
    robots_hops_ = 0;
    page_hops_ = 0;
    policy_ = Policy::AllowAll;
    funnel_ = true;
    page_attempted_ = false;
    page_replied_ = false;
    last_status_ = 0;
    port_retries_ = 0;

    if (!parse::parse_url(line, page_) || (!real() && page_.scheme != parse::Scheme::Http)) {
        finish();
        return;
    }
    st.add(Counter::UrlsParsed);
    if (!w_.new_host(page_.host)) {
        finish();
        return;
    }
    st.add(Counter::UniqueHosts);
    resolve(Phase::Dns, page_.host);
}

void Task::resolve(Phase phase, const std::string& host) {
    if (w_.stopping_) {
        finish();
        return;
    }
    phase_ = phase;
    w_.resolver_.resolve(host, [this](dns::Status status, uint32_t ipv4_be) { on_dns(status, ipv4_be); });
}

void Task::on_dns(dns::Status status, uint32_t ipv4_be) {
    // Resolver::shutdown() fails pending lookups; those are cancellations, not DNS failures.
    if (w_.stopping_) {
        finish();
        return;
    }
    const bool ok = status == dns::Status::Ok;
    switch (phase_) {
    case Phase::Dns:
        if (!ok) {
            w_.stats_.add(Counter::DnsFail);
            finish();
            return;
        }
        w_.stats_.add(Counter::DnsOk);
        if (!w_.new_ip(ipv4_be)) {
            finish();
            return;
        }
        w_.stats_.add(Counter::UniqueIps);
        page_ip_ = ipv4_be;
        w_.stats_.add(Counter::RobotsAttempted);
        start_robots();
        return;
    case Phase::RobotsDns:
        // A robots.txt redirect to an unresolvable host: unreachable.
        if (!ok) {
            robots_decided(Policy::DisallowAll);
            return;
        }
        robots_ip_ = ipv4_be;
        fetch_robots();
        return;
    case Phase::PageDns:
        if (!ok) {
            finish();  // the redirect reply already counted as the page's answer
            return;
        }
        page_ip_ = ipv4_be;
        start_robots();
        return;
    default:
        finish();
        return;
    }
}

void Task::start_robots() {
    // robots.txt of the page's origin.
    robots_ = page_;
    robots_.target.assign("/robots.txt");
    robots_ip_ = page_ip_;
    robots_hops_ = 0;
    fetch_robots();
}

void Task::fetch_robots() {
    if (w_.stopping_) {
        finish();
        return;
    }
    phase_ = Phase::Robots;
    const Config& cfg = w_.cfg_;
    build_request(real() ? "GET" : "HEAD", robots_);
    FetchOptions opt;
    opt.head = !real();
    opt.limit = static_cast<size_t>(cfg.robots_limit);
    opt.timeout_ms = cfg.timeout_ms;
    opt.connect_timeout_ms = cfg.connect_timeout_ms;
    opt.keep_alive = cfg.keepalive;
    conn_.fetch(endpoint(robots_, robots_ip_), request_, opt);
}

void Task::fetch_page() {
    if (w_.stopping_) {
        finish();
        return;
    }
    phase_ = Phase::Page;
    if (!page_attempted_) {
        page_attempted_ = true;
        w_.stats_.add(Counter::PagesAttempted);
    }
    const Config& cfg = w_.cfg_;
    build_request("GET", page_);
    FetchOptions opt;
    opt.head = false;
    opt.limit = static_cast<size_t>(cfg.page_limit);
    opt.timeout_ms = cfg.timeout_ms;
    opt.connect_timeout_ms = cfg.connect_timeout_ms;
    opt.keep_alive = cfg.keepalive;
    conn_.fetch(endpoint(page_, page_ip_), request_, opt);
}

void Task::on_fetch(Connection&, const FetchResult& result) {
    if (phase_ == Phase::Robots) {
        on_robots(result);
    } else {
        on_page(result);
    }
}

void Task::count_failure(FetchError error) {
    switch (error) {
    case FetchError::ConnectFail:
    case FetchError::NoPorts: w_.stats_.add(Counter::ConnectFail); break;
    case FetchError::Timeout: w_.stats_.add(Counter::Timeouts); break;
    case FetchError::TlsFail: w_.stats_.add(Counter::TlsFail); break;
    case FetchError::TlsCertificate:
        w_.stats_.add(Counter::TlsFail);
        w_.stats_.add(Counter::TlsCertFail);
        break;
    case FetchError::TooLarge:
    case FetchError::BadReply:
    case FetchError::Closed: w_.stats_.add(Counter::OtherFail); break;
    case FetchError::None:
    case FetchError::Aborted: break;
    }
}

bool Task::retry_later(FetchError error) {
    if (error != FetchError::NoPorts || w_.stopping_ || port_retries_ >= kMaxPortRetries) {
        return false;
    }
    // Resource pressure, not a property of the site: keep the URL and retry
    // the same step once other sockets have released their ports.
    const uint32_t delay = std::min(kPortRetryMaxMs, kPortRetryBaseMs << std::min(port_retries_, 5u));
    ++port_retries_;
    w_.stats_.add(Counter::PortExhaustion);
    retry_timer_ = w_.loop_.add_timer(delay, [this] {
        retry_timer_ = 0;
        if (phase_ == Phase::Robots) {
            fetch_robots();
        } else {
            fetch_page();
        }
    });
    return true;
}

void Task::on_robots(const FetchResult& result) {
    if (retry_later(result.error)) {
        return;
    }
    if (result.error != FetchError::None) {
        count_failure(result.error);
        if (!real()) {
            finish();
            return;
        }
        // RFC 9309 §2.3.1.4: unreachable robots.txt means disallow all.
        robots_decided(Policy::DisallowAll);
        return;
    }
    const int status = result.status;
    if (!real()) {
        // Assignment semantics: only a 4xx robots reply lets the page through.
        if (status >= 400 && status < 500) {
            w_.stats_.add(Counter::RobotsPassed);
            fetch_page();
        } else {
            finish();
        }
        return;
    }
    if (status >= 200 && status < 300) {
        rules_ = parse::RobotsRules::parse(result.body, kRobotsToken);
        robots_decided(Policy::Rules);
    } else if (status >= 300 && status < 400) {
        const std::string_view location = result.reply->header("Location");
        if (location.empty() || robots_hops_ >= kMaxRobotsRedirects || !parse::resolve_url(robots_, location, next_)) {
            robots_decided(Policy::AllowAll);  // §2.3.1.2: too many redirects = unavailable
            return;
        }
        ++robots_hops_;
        const bool same_host = next_.host == robots_.host;
        std::swap(robots_, next_);
        if (same_host) {
            fetch_robots();
        } else {
            resolve(Phase::RobotsDns, robots_.host);
        }
    } else if (status >= 400 && status < 500) {
        robots_decided(Policy::AllowAll);  // §2.3.1.3: unavailable
    } else {
        robots_decided(Policy::DisallowAll);  // §2.3.1.4: unreachable (5xx and anything odd)
    }
}

void Task::robots_decided(Policy policy) {
    policy_ = policy;
    const bool allowed = policy == Policy::AllowAll || (policy == Policy::Rules && rules_.allowed(page_.target));
    if (funnel_) {
        funnel_ = false;
        if (allowed) {
            w_.stats_.add(Counter::RobotsPassed);
        }
    }
    if (!allowed) {
        finish();
        return;
    }
    fetch_page();
}

void Task::on_page(const FetchResult& result) {
    if (retry_later(result.error)) {
        return;
    }
    if (result.error != FetchError::None) {
        count_failure(result.error);
        finish();
        return;
    }
    page_replied_ = true;
    last_status_ = result.status;
    const int status = result.status;

    if (real() && status >= 300 && status < 400 && page_hops_ < w_.cfg_.max_redirects) {
        const std::string_view location = result.reply->header("Location");
        if (!location.empty() && parse::resolve_url(page_, location, next_)) {
            ++page_hops_;
            w_.stats_.add(Counter::RedirectsFollowed);
            const bool origin = same_origin(next_, page_);
            const bool host = next_.host == page_.host;
            std::swap(page_, next_);
            if (origin) {
                // Same origin: the rules already fetched apply.
                const bool allowed = policy_ == Policy::AllowAll ||
                                     (policy_ == Policy::Rules && rules_.allowed(page_.target));
                if (allowed) {
                    fetch_page();
                } else {
                    finish();
                }
            } else if (host) {
                start_robots();  // new scheme or port on the same host: same IP, new robots
            } else {
                resolve(Phase::PageDns, page_.host);
            }
            return;
        }
    }

    if (status >= 200 && status < 300 && (!real() || is_html(*result.reply))) {
        w_.stats_.add(Counter::Links, w_.links_.extract(result.body, page_));
    }
    finish();
}

void Task::finish() {
    if (page_replied_) {
        w_.stats_.add(Counter::PagesOk);
        w_.stats_.add(status_counter(last_status_));
    }
    phase_ = Phase::Idle;
    conn_.close();  // RST: no TIME_WAIT, the next URL needs a different server anyway
    w_.task_done(this);
}

void Task::abort() {
    if (retry_timer_ != 0) {
        // Waiting out port exhaustion: nothing is in flight, end it here.
        w_.loop_.cancel_timer(retry_timer_);
        retry_timer_ = 0;
        finish();
        return;
    }
    if (phase_ == Phase::Robots || phase_ == Phase::Page) {
        conn_.abort();
    }
}

void Task::build_request(std::string_view method, const parse::Url& url) {
    request_.clear();
    if (!real() && !w_.cfg_.keepalive) {
        // --no-keepalive in classic mode reproduces the original crawler's
        // HTTP/1.0 requests (one request per connection).
        request_.append(method);
        request_.push_back(' ');
        request_.append(url.target);
        request_.append(" HTTP/1.0\r\nHost: ");
        parse::append_host_header(request_, url);
        request_.append("\r\nUser-Agent: ");
        request_.append(kUserAgent);
        request_.append("\r\nConnection: close\r\n\r\n");
        return;
    }
    parse::append_request(request_, method, url, kUserAgent, w_.cfg_.keepalive);
}

Endpoint Task::endpoint(const parse::Url& url, uint32_t ipv4_be) const {
    Endpoint ep;
    ep.ipv4_be = ipv4_be;
    ep.port = url.port;
    ep.tls = url.scheme == parse::Scheme::Https;
    ep.server_name = url.host;
    return ep;
}

// ---------------------------------------------------------------- Worker

namespace {

dns::ResolverConfig resolver_config(const Config& cfg, unsigned inflight, const std::vector<sockaddr_in>& servers) {
    dns::ResolverConfig rc;
    rc.servers = servers;
    rc.timeout_ms = cfg.dns_timeout_ms;
    rc.attempts = cfg.dns_attempts;
    rc.max_inflight = inflight;
    return rc;
}

}  // namespace

Worker::Worker(Engine& engine, size_t index, unsigned slots, unsigned dns_inflight,
               const std::vector<sockaddr_in>& dns_servers)
    : engine_(engine),
      cfg_(engine.config_),
      stats_(engine.stats_.block(index)),
      resolver_(loop_, resolver_config(engine.config_, dns_inflight, dns_servers)) {
    tasks_.reserve(slots);
    free_.reserve(slots);
    for (unsigned i = 0; i < slots; ++i) {
        tasks_.push_back(std::make_unique<Task>(*this));
    }
    // Hand out slots in index order (back of the vector is used first).
    for (size_t i = tasks_.size(); i > 0; --i) {
        free_.push_back(tasks_[i - 1].get());
    }
    batch_.reserve(kClaimBatch);
}

Worker::~Worker() = default;

void Worker::run() {
    loop_.post([this] { start(); });
    loop_.run();
}

void Worker::start() {
    arm_dns_timer();
    if (engine_.stop_requested()) {
        stop();
        return;
    }
    pump();
}

void Worker::arm_dns_timer() {
    // The resolver's counters are plain loop-thread fields; mirror them into
    // the stats block periodically for the reporter.
    dns_timer_ = loop_.add_timer(kDnsSyncMs, [this] {
        dns_timer_ = 0;
        sync_dns_counters();
        arm_dns_timer();
    });
}

void Worker::stop() {
    if (stopping_ || finishing_) {
        return;
    }
    stopping_ = true;
    for (auto& task : tasks_) {
        task->abort();  // may finish the task synchronously
    }
    // Fails queued and in-flight lookups (Timeout); their tasks then finish.
    resolver_.shutdown();
    maybe_finish();
}

bool Worker::next_url(std::string_view& out) {
    if (batch_pos_ == batch_.size()) {
        batch_.clear();
        batch_pos_ = 0;
        // Never buffer more URLs than this loop has free slots: at the tail
        // of the input, surplus would wait here while other loops sit idle.
        const size_t want = std::min(kClaimBatch, std::max<size_t>(free_.size(), 1));
        if (input_done_ || engine_.input_.claim(want, batch_) == 0) {
            input_done_ = true;
            return false;
        }
    }
    out = batch_[batch_pos_++];
    return true;
}

void Worker::pump() {
    if (pumping_) {
        return;  // a task finished synchronously inside the loop below
    }
    pumping_ = true;
    while (!stopping_ && !free_.empty()) {
        std::string_view line;
        if (!next_url(line)) {
            break;
        }
        Task* task = free_.back();
        free_.pop_back();
        ++live_;
        stats_.set(Counter::Inflight, live_);
        task->start(line);  // may finish synchronously (bad URL, duplicate host)
    }
    pumping_ = false;
    maybe_finish();
}

void Worker::task_done(Task* task) {
    free_.push_back(task);
    --live_;
    stats_.set(Counter::Inflight, live_);
    pump();
}

void Worker::maybe_finish() {
    if (finishing_ || live_ != 0 || !(input_done_ || stopping_)) {
        return;
    }
    finishing_ = true;
    resolver_.shutdown();
    if (dns_timer_ != 0) {
        loop_.cancel_timer(dns_timer_);
        dns_timer_ = 0;
    }
    sync_dns_counters();
    drain();
}

void Worker::drain() {
    // Aborted sockets and the resolver's socket complete asynchronously; the
    // loop must keep running until nothing is outstanding.
    bool busy = resolver_.busy();
    for (const auto& task : tasks_) {
        busy = busy || task->busy();
    }
    if (busy) {
        loop_.add_timer(kDrainPollMs, [this] { drain(); });
        return;
    }
    loop_.stop();
}

void Worker::sync_dns_counters() {
    const dns::Resolver::Counters& c = resolver_.counters();
    stats_.set(Counter::DnsQueriesSent, c.queries_sent);
    stats_.set(Counter::DnsRetries, c.retries);
    stats_.set(Counter::DnsTimeouts, c.timeouts);  // names that exhausted every attempt
}

// ---------------------------------------------------------------- Engine

Engine::Engine(const Config& config, UrlInput& input, Stats& stats)
    : config_(config), input_(input), stats_(stats), hosts_(input.total()), ips_(input.total()) {}

Engine::~Engine() = default;

void Engine::attach(Worker* worker) {
    std::lock_guard<std::mutex> lock(mutex_);
    workers_.push_back(worker);
    if (stop_requested()) {
        worker->loop().post([worker] { worker->stop(); });
    }
}

void Engine::detach(Worker* worker) {
    std::lock_guard<std::mutex> lock(mutex_);
    workers_.erase(std::remove(workers_.begin(), workers_.end(), worker), workers_.end());
}

void Engine::request_stop() {
    stop_.store(true, std::memory_order_release);
    std::lock_guard<std::mutex> lock(mutex_);
    for (Worker* worker : workers_) {
        worker->loop().post([worker] { worker->stop(); });
    }
}

bool Engine::run(std::string& error) {
    const unsigned n = std::max(1u, config_.threads);
    if (stats_.block_count() < n) {
        error = "internal: stats has fewer blocks than threads";
        return false;
    }
    net::startup();

    std::vector<sockaddr_in> servers;
    if (config_.dns_system) {
        servers = dns::system_dns_servers();
    } else {
        for (const DnsServer& s : config_.dns_servers) {
            servers.push_back(net::make_addr(s.ipv4_be, s.port));
        }
    }
    if (servers.empty()) {
        error = config_.dns_system ? "no system DNS servers found; pass --dns ADDR[:PORT]" : "no DNS servers configured";
        return false;
    }
    if (config_.mode == Mode::Real) {
        // Failure is not fatal: https fetches then fail as tls_fail.
        tls::startup();
    }

    std::vector<std::thread> threads;
    threads.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        // Spread the remainders so the totals match the configured limits.
        const unsigned slots = config_.concurrency / n + (i < config_.concurrency % n ? 1u : 0u);
        unsigned dns = config_.dns_inflight / n + (i < config_.dns_inflight % n ? 1u : 0u);
        dns = std::max(dns, 1u);
        threads.emplace_back([this, i, slots, dns, &servers] {
            Worker worker(*this, i, slots, dns, servers);
            attach(&worker);
            worker.run();
            detach(&worker);
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    return true;
}

}  // namespace wc::crawl
