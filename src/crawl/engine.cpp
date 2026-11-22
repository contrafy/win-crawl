#include "crawl/engine.h"

#include "crawl/connection.h"
#include "crawl/ipranges.h"
#include "crawl/record.h"
#include "dns/resolver.h"
#include "dns/servers.h"
#include "net/addr.h"
#include "net/loop.h"
#include "parse/links.h"
#include "parse/robots.h"
#include "parse/url.h"
#include "tls/tls.h"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <deque>
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
// --record: each loop hands its buffer to the writer thread once it holds
// this much (~500 records), i.e. one lock round trip per few hundred sites.
constexpr size_t kRecordFlush = 256 * 1024;
constexpr size_t kRecordBuffer = kRecordFlush + 64 * 1024;  // a record rarely exceeds 1 KiB
// A redirect to another IP queues behind at most this many other sites under
// way there; past that the hop is given up ("ip_busy"). Thousands of parked
// domains redirecting to one landing host must not pile up behind that one
// IP's spacing.
constexpr uint32_t kMaxHopWaiters = 64;

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

bool throttled(int status) {
    return status == 429 || status == 503;
}

// Retry-After of a reply, in seconds; nullopt when absent or malformed.
std::optional<uint64_t> retry_after_s(const parse::ResponseParser& reply) {
    if (!reply.has_header("Retry-After")) {
        return std::nullopt;
    }
    return parse_retry_after(reply.header("Retry-After"), static_cast<int64_t>(std::time(nullptr)));
}

}  // namespace

class Task;
class Worker;

// A wait at an IP gate. Every task embeds one for its own waits; new sites
// that queue before holding a task use one from their loop's pool, so a
// backlog of thousands of hosts on one IP costs a few dozen bytes per host,
// not a task slot.
struct Waiter : GateWaiter {
    Worker* owner = nullptr;
    Task* task = nullptr;     // a parked task; null for a queued new site
    std::string_view line;    // new site: its input line (lives in the input)
    uint64_t start_ms = 0;    // new site: when its URL was claimed (loop clock)
    uint64_t queued_ms = 0;   // new site: when it started waiting (loop clock)
    bool in_use = false;      // new site: taken from the pool
};

// Everything one event loop owns. Constructed, run and destroyed on its own
// thread; other loops reach it only through post() (request_stop(), and
// waiters woken at a gate by another loop).
class Worker final : public GateEvents {
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
    IpGates& gates_;
    bool stopping_ = false;
    const bool recording_;  // --record

    void task_done(Task* task);
    bool new_host(std::string_view host) { return engine_.hosts_.insert(host); }
    void emit(const SiteRecord& record);

    // Politeness bookkeeping. A parked task waits on politeness without a
    // socket; up to `slots` of them do not count against the loop's slots,
    // so a busy IP cannot starve the loop of work.
    Waiter* take_seed();
    void give_seed(Waiter* waiter);
    void seed_queued();
    void park(bool& counted);
    void unpark(bool& counted);

    // GateEvents, called on this loop's thread for decisions it made.
    void on_wake(GateWaiter* waiter) override;
    void arm_gate_timer(uint32_t ip, uint32_t delay_ms) override;

private:
    void start();
    void arm_dns_timer();
    void kick();
    void pump();
    bool next_url(std::string_view& out);
    Task* take_task(bool admitted_seed);
    void end_seed(Waiter* waiter);
    size_t live() const { return running_ + parked_ + queued_seeds_; }
    void update_gauges();
    void maybe_finish();
    void sync_dns_counters();
    void drain();

    const unsigned slots_;
    std::vector<std::unique_ptr<Task>> tasks_;
    std::vector<Task*> free_;
    std::vector<std::string_view> batch_;
    size_t batch_pos_ = 0;
    size_t running_ = 0;        // tasks at work
    size_t parked_ = 0;         // tasks waiting on politeness outside the slot count (<= slots_)
    size_t waiting_tasks_ = 0;  // every task waiting on politeness
    size_t queued_seeds_ = 0;   // new sites waiting at a gate without a task
    std::deque<Waiter*> ready_;  // this loop's waiters woken at a gate
    std::vector<std::unique_ptr<Waiter>> seeds_;
    std::vector<Waiter*> free_seeds_;
    unsigned gate_timers_ = 0;  // gate spacing timers armed here; other loops' sites may wait on them
    net::TimerId kick_timer_ = 0;
    bool input_done_ = false;
    bool pumping_ = false;
    bool finishing_ = false;
    net::TimerId dns_timer_ = 0;
    std::string records_;  // serialized records not yet handed to the writer
    uint64_t record_count_ = 0;
    SiteRecord scratch_;   // records of queued sites cancelled by a stop
};

// One URL through the pipeline. Classic and real mode share the skeleton:
//   parse -> unique host -> DNS -> per-IP budget and gate -> robots -> page.
// Real mode adds GET robots with RFC 9309 semantics (Crawl-delay included),
// redirects (each new origin gets DNS and its own robots check, without host
// dedupe or the IP budget), one Retry-After retry, and TLS. Every new
// connection takes a slot at its IP's gate first (politeness.h).
class Task final : public FetchHandler {
public:
    explicit Task(Worker& w)
        : w_(w),
          conn_(w.loop_, *this, &w.stats_, w.cfg_.insecure ? tls::Verify::None : tls::Verify::Chain) {
        wait_.owner = &w;
        wait_.task = this;
    }

    void start(std::string_view line);  // a new input line
    void resume(const Waiter& seed);    // a new site whose gate wait ended
    void on_gate(GateWaiter::State state);  // this task's own gate wait ended
    void abort();
    bool busy() const { return conn_.busy(); }

private:
    enum class Phase : uint8_t { Idle, Dns, Robots, RobotsDns, Page, PageDns };
    enum class Policy : uint8_t { AllowAll, DisallowAll, Rules };
    enum class Hold : uint8_t { None, Gate, Timer };  // what a politeness wait waits for
    enum class WaitFor : uint8_t { Spacing, CrawlDelay, RetryAfter };

    bool real() const { return w_.cfg_.mode == Mode::Real; }
    void reset(std::string_view line);
    void begin_record();
    void resolve(Phase phase, const std::string& host);
    void on_dns(dns::Status status, uint32_t ipv4_be);
    void admit_seed(uint32_t ip);
    void hold_slot(uint32_t ip);
    void query_https_rr();
    void on_https_rr(dns::Status status, const dns::HttpsRecord& rr);
    void note_fetch(const FetchResult& result);
    void note_tls(const tls::ClientSession& session);
    void note_outcome(const FetchResult& result);
    void on_fetch(Connection& connection, const FetchResult& result) override;
    void count_failure(FetchError error);
    bool retry_later(FetchError error);
    bool retry_after(const FetchResult& result);
    void note_crawl_delay();

    void start_robots();
    void fetch_robots();
    void on_robots(const FetchResult& result);
    void robots_decided(Policy policy);
    void fetch_page();
    void on_page(const FetchResult& result);
    void send();
    void wait(uint32_t ms, WaitFor why);
    void end_wait();
    void refused(Admit admit);
    void release_slot();
    void note_aborted();
    void finish();
    void complete();

    void build_request(std::string_view method, const parse::Url& url);
    Endpoint endpoint(const parse::Url& url, uint32_t ipv4_be) const;

    Worker& w_;
    Connection conn_;
    Phase phase_ = Phase::Idle;
    std::string_view line_;  // the input line (lives in the input)
    parse::Url page_;    // current page URL (the seed, then redirect hops)
    parse::Url robots_;  // current robots.txt URL (follows robots redirects)
    parse::Url next_;    // scratch for redirect resolution
    std::string request_;
    FetchOptions opt_;
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
    uint64_t start_ms_ = 0;

    // Politeness.
    Waiter wait_;                  // this task's own gate waits
    Hold hold_ = Hold::None;
    WaitFor wait_for_ = WaitFor::Spacing;
    bool parked_ = false;          // counted as parked by the worker
    bool holding_ = false;         // holds a connection slot at held_ip_
    bool reserved_ = false;        // the next connection start at held_ip_ is already accounted for
    uint32_t held_ip_ = 0;
    Outcome outcome_ = Outcome::None;  // how the current connection went
    uint32_t outcome_retry_ms_ = 0;    // its Retry-After, ms
    net::TimerId wait_timer_ = 0;
    uint64_t wait_start_ = 0;
    std::string delay_host_;       // the host whose robots.txt asked for a Crawl-delay
    uint32_t delay_ms_ = 0;
    uint64_t next_request_ms_ = 0; // earliest next request to delay_host_ (loop clock)
    bool delay_skip_ = false;      // Crawl-delay above the cap: skip the page
    bool retried_ = false;         // the one Retry-After retry is spent

    // --record
    SiteRecord rec_;
    bool rec_active_ = false;      // this URL's host passed dedupe: emit a record
    bool https_pending_ = false;   // an HTTPS RR query is outstanding
    bool done_pending_ = false;    // finished, waiting for the HTTPS RR answer
};

// ---------------------------------------------------------------- Task

void Task::reset(std::string_view line) {
    line_ = line;
    phase_ = Phase::Idle;
    robots_hops_ = 0;
    page_hops_ = 0;
    policy_ = Policy::AllowAll;
    funnel_ = true;
    page_attempted_ = false;
    page_replied_ = false;
    last_status_ = 0;
    port_retries_ = 0;
    rec_active_ = false;
    holding_ = false;
    reserved_ = false;
    outcome_ = Outcome::None;
    outcome_retry_ms_ = 0;
    delay_host_.clear();
    delay_ms_ = 0;
    next_request_ms_ = 0;
    delay_skip_ = false;
    retried_ = false;
}

void Task::begin_record() {
    rec_active_ = true;
    rec_.clear();
    rec_.url.assign(line_.data(), line_.size());
    rec_.host.assign(page_.host);
    rec_.seed_https = page_.scheme == parse::Scheme::Https;
}

void Task::start(std::string_view line) {
    CounterBlock& st = w_.stats_;
    st.add(Counter::UrlsRead);
    reset(line);
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
    start_ms_ = w_.loop_.now();
    if (w_.recording_) {
        begin_record();
    }
    resolve(Phase::Dns, page_.host);
}

void Task::resume(const Waiter& seed) {
    reset(seed.line);
    start_ms_ = seed.start_ms;
    parse::parse_url(line_, page_);  // parsed once already, before it queued
    if (w_.recording_) {
        begin_record();
        rec_.dns = dns::status_name(dns::Status::Ok);
        rec_.has_ip = true;
        rec_.ip = seed.ip;
        rec_.cf_ip = cloudflare_ipv4().contains(seed.ip);
        rec_.ip_dup = false;
    }
    page_ip_ = seed.ip;
    const uint64_t waited = w_.loop_.now() - seed.queued_ms;
    w_.stats_.add(Counter::PoliteWaitMs, waited);
    if (rec_active_) {
        rec_.wait_ms += waited;
    }
    if (seed.state != GateWaiter::State::Admitted) {
        // The IP's breaker tripped while this site waited.
        w_.stats_.add(Counter::IpUnreachable);
        if (rec_active_) {
            rec_.skip = "ip_unreachable";
        }
        query_https_rr();
        finish();
        return;
    }
    hold_slot(seed.ip);
    w_.stats_.add(Counter::RobotsAttempted);
    query_https_rr();
    start_robots();
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
        if (rec_active_ && phase_ == Phase::Dns) {
            rec_.dns = "cancelled";
        }
        finish();
        return;
    }
    const bool ok = status == dns::Status::Ok;
    switch (phase_) {
    case Phase::Dns:
        if (rec_active_) {
            rec_.dns = dns::status_name(status);
        }
        if (!ok) {
            w_.stats_.add(Counter::DnsFail);
            finish();
            return;
        }
        w_.stats_.add(Counter::DnsOk);
        if (rec_active_) {
            rec_.has_ip = true;
            rec_.ip = ipv4_be;
            rec_.cf_ip = cloudflare_ipv4().contains(ipv4_be);
        }
        page_ip_ = ipv4_be;
        admit_seed(ipv4_be);
        return;
    case Phase::RobotsDns:
        // A robots.txt redirect to an unresolvable host: unreachable.
        if (!ok) {
            if (rec_active_ && funnel_) {
                rec_.robots_error = "redirect_dns";
            }
            robots_decided(Policy::DisallowAll);
            return;
        }
        robots_ip_ = ipv4_be;
        fetch_robots();
        return;
    case Phase::PageDns:
        if (!ok) {
            if (rec_active_) {
                rec_.fetch = "redirect_dns";
            }
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

void Task::admit_seed(uint32_t ip) {
    CounterBlock& st = w_.stats_;
    Waiter* seed = w_.take_seed();
    seed->line = line_;
    seed->start_ms = start_ms_;
    seed->queued_ms = w_.loop_.now();
    const SeedResult r = w_.gates_.seed(ip, seed, gate_clock_ms(), w_);
    if (r.budget == Budget::Over || r.budget == Budget::Unreachable) {
        w_.give_seed(seed);
        const bool over = r.budget == Budget::Over;
        st.add(over ? Counter::IpBudgetSkips : Counter::IpUnreachable);
        if (rec_active_) {
            rec_.ip_dup = over;
            rec_.skip = over ? "ip_budget" : "ip_unreachable";
        }
        query_https_rr();  // DNS-level facts cover every resolving host
        finish();
        return;
    }
    st.add(r.budget == Budget::First ? Counter::UniqueIps : Counter::IpExtraHosts);
    if (r.cdn) {
        st.add(Counter::CdnHosts);
    }
    if (rec_active_) {
        rec_.ip_dup = false;
    }
    if (r.admit == Admit::Queued) {
        // Wait without a task: once the gate admits the site, the loop
        // resumes it in a free task, which writes its record.
        st.add(Counter::PoliteWaits);
        rec_active_ = false;
        phase_ = Phase::Idle;
        w_.seed_queued();
        w_.task_done(this);
        return;
    }
    w_.give_seed(seed);
    hold_slot(ip);
    st.add(Counter::RobotsAttempted);
    query_https_rr();
    start_robots();
}

void Task::hold_slot(uint32_t ip) {
    holding_ = true;
    held_ip_ = ip;
    reserved_ = true;  // admission already counted this connection start
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
    opt_ = FetchOptions{};
    opt_.head = !real();
    opt_.limit = static_cast<size_t>(cfg.robots_limit);
    opt_.timeout_ms = cfg.timeout_ms;
    opt_.connect_timeout_ms = cfg.connect_timeout_ms;
    opt_.keep_alive = cfg.keepalive;
    send();
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
    opt_ = FetchOptions{};
    opt_.head = false;
    opt_.limit = static_cast<size_t>(cfg.page_limit);
    opt_.timeout_ms = cfg.timeout_ms;
    opt_.connect_timeout_ms = cfg.connect_timeout_ms;
    opt_.keep_alive = cfg.keepalive;
    send();
}

// Sends request_ for the current phase once politeness allows: the host's
// Crawl-delay first, then a connection slot at the IP, or only the IP's
// spacing when this site already holds a slot there. Waits hold no socket.
void Task::send() {
    if (w_.stopping_) {
        finish();
        return;
    }
    const bool robots = phase_ == Phase::Robots;
    const parse::Url& url = robots ? robots_ : page_;
    const uint32_t ip = robots ? robots_ip_ : page_ip_;
    const Endpoint ep = endpoint(url, ip);
    const uint64_t now = w_.loop_.now();
    if (delay_ms_ != 0 && now < next_request_ms_ && url.host == delay_host_) {
        release_slot();
        w_.stats_.add(Counter::CrawlDelayWaits);
        wait(static_cast<uint32_t>(next_request_ms_ - now), WaitFor::CrawlDelay);
        return;
    }
    if (conn_.reuses(ep)) {
        conn_.fetch(ep, request_, opt_);
        return;
    }
    if (holding_ && held_ip_ == ip) {
        // A new connection where this site already holds a slot (reconnect
        // after Connection: close, http -> https, another host on the same
        // IP): concurrency is unchanged, only the spacing applies.
        if (!reserved_) {
            conn_.close();
            const uint32_t ms = w_.gates_.restart(ip, outcome_, outcome_retry_ms_, gate_clock_ms());
            outcome_ = Outcome::None;
            outcome_retry_ms_ = 0;
            reserved_ = true;
            if (ms != 0) {
                w_.stats_.add(Counter::PoliteWaits);
                wait(ms, WaitFor::Spacing);
                return;
            }
        }
        reserved_ = false;
        conn_.fetch(ep, request_, opt_);
        return;
    }
    // Another IP: give the old slot back before asking for one there, so a
    // task never waits while holding a slot.
    release_slot();
    const Admit admit = w_.gates_.acquire(ip, &wait_, kMaxHopWaiters, gate_clock_ms(), w_);
    switch (admit) {
    case Admit::Now:
        hold_slot(ip);
        reserved_ = false;
        conn_.fetch(ep, request_, opt_);
        return;
    case Admit::Queued:
        w_.stats_.add(Counter::PoliteWaits);
        hold_ = Hold::Gate;
        wait_start_ = now;
        w_.park(parked_);
        return;
    case Admit::Busy:
    case Admit::Unreachable:
        refused(admit);
        return;
    }
}

void Task::wait(uint32_t ms, WaitFor why) {
    hold_ = Hold::Timer;
    wait_for_ = why;
    wait_start_ = w_.loop_.now();
    w_.park(parked_);
    wait_timer_ = w_.loop_.add_timer(ms, [this] {
        wait_timer_ = 0;
        end_wait();
        send();
    });
}

void Task::end_wait() {
    hold_ = Hold::None;
    w_.unpark(parked_);
    const uint64_t waited = w_.loop_.now() - wait_start_;
    if (rec_active_) {
        rec_.wait_ms += waited;
    }
    switch (wait_for_) {
    case WaitFor::Spacing:
        w_.stats_.add(Counter::PoliteWaitMs, waited);
        break;
    case WaitFor::CrawlDelay:
        w_.stats_.add(Counter::CrawlDelayMs, waited);
        if (rec_active_) {
            rec_.crawl_delay_ms += waited;
        }
        break;
    case WaitFor::RetryAfter:
        break;
    }
}

void Task::on_gate(GateWaiter::State state) {
    hold_ = Hold::None;
    w_.unpark(parked_);
    const uint64_t waited = w_.loop_.now() - wait_start_;
    w_.stats_.add(Counter::PoliteWaitMs, waited);
    if (rec_active_) {
        rec_.wait_ms += waited;
    }
    if (state == GateWaiter::State::Admitted) {
        hold_slot(wait_.ip);
    }
    if (w_.stopping_) {
        note_aborted();
        finish();
        return;
    }
    if (state != GateWaiter::State::Admitted) {
        refused(Admit::Unreachable);
        return;
    }
    send();
}

// The gate turned a connection of a site under way down: a redirect to an IP
// that is unreachable or has too many sites waiting.
void Task::refused(Admit admit) {
    const char* why = admit == Admit::Busy ? "ip_busy" : "ip_unreachable";
    w_.stats_.add(Counter::IpBusy);
    if (phase_ == Phase::Robots && funnel_) {
        if (rec_active_) {
            rec_.robots_error = why;
        }
        robots_decided(Policy::DisallowAll);  // unreachable robots.txt (RFC 9309 §2.3.1.4)
        return;
    }
    if (rec_active_) {
        rec_.fetch = why;
    }
    finish();
}

void Task::release_slot() {
    conn_.close();  // RST: no TIME_WAIT
    if (!holding_) {
        return;
    }
    holding_ = false;
    reserved_ = false;
    w_.gates_.release(held_ip_, outcome_, outcome_retry_ms_, gate_clock_ms(), w_);
    outcome_ = Outcome::None;
    outcome_retry_ms_ = 0;
}

void Task::note_outcome(const FetchResult& result) {
    if (result.error == FetchError::None) {
        if (throttled(result.status)) {
            w_.stats_.add(Counter::Throttled);
            outcome_ = Outcome::Throttled;
            const std::optional<uint64_t> s = retry_after_s(*result.reply);
            outcome_retry_ms_ = s ? static_cast<uint32_t>(std::min<uint64_t>(*s * 1000, UINT32_MAX)) : 0;
        } else if (outcome_ != Outcome::Throttled) {
            outcome_ = Outcome::Replied;
        }
    } else if ((result.error == FetchError::ConnectFail || result.error == FetchError::Timeout) &&
               outcome_ == Outcome::None) {
        outcome_ = Outcome::Failed;  // nothing ever replied on this connection
    }
}

void Task::on_fetch(Connection&, const FetchResult& result) {
    note_outcome(result);
    if (rec_active_) {
        note_fetch(result);
    }
    // Crawl-delay spaces every request to the host that asked for it.
    const parse::Url& url = phase_ == Phase::Robots ? robots_ : page_;
    if (delay_ms_ != 0 && url.host == delay_host_) {
        next_request_ms_ = w_.loop_.now() + delay_ms_;
    }
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

// Real mode: a 429/503 whose Retry-After is within --max-retry-after is
// waited out (without a socket) and the request repeated, once per site.
// The release reports the throttle, which backs off the IP's spacing.
bool Task::retry_after(const FetchResult& result) {
    if (result.error != FetchError::None || !throttled(result.status)) {
        return false;
    }
    const std::optional<uint64_t> s = retry_after_s(*result.reply);
    if (!s) {
        return false;
    }
    if (rec_active_ && !rec_.retry_after) {
        rec_.retry_after = *s;
        rec_.retried = false;
    }
    if (!real() || retried_ || w_.stopping_ || *s > w_.cfg_.max_retry_after_s) {
        return false;
    }
    retried_ = true;
    if (rec_active_) {
        rec_.retried = true;
    }
    w_.stats_.add(Counter::RetryAfterRetries);
    release_slot();
    wait(static_cast<uint32_t>(*s * 1000), WaitFor::RetryAfter);
    return true;
}

void Task::note_crawl_delay() {
    const std::optional<double> delay = rules_.crawl_delay();
    if (!delay) {
        return;
    }
    if (rec_active_ && funnel_) {
        rec_.crawl_delay = *delay;
    }
    if (*delay <= 0) {
        return;
    }
    if (*delay > static_cast<double>(w_.cfg_.max_crawl_delay_s)) {
        delay_skip_ = true;  // robots_decided() skips the page
        return;
    }
    delay_host_.assign(robots_.host);
    delay_ms_ = static_cast<uint32_t>(std::ceil(*delay * 1000.0));
    next_request_ms_ = w_.loop_.now() + delay_ms_;
}

void Task::on_robots(const FetchResult& result) {
    if (retry_later(result.error) || retry_after(result)) {
        return;
    }
    if (result.error != FetchError::None) {
        count_failure(result.error);
        if (rec_active_ && funnel_) {
            rec_.robots_error = fetch_error_name(result.error);
        }
        if (!real()) {
            if (rec_active_) {
                rec_.robots_allowed = false;
            }
            finish();
            return;
        }
        // RFC 9309 §2.3.1.4: unreachable robots.txt means disallow all.
        robots_decided(Policy::DisallowAll);
        return;
    }
    const int status = result.status;
    if (rec_active_ && funnel_) {
        rec_.robots_status = status;  // overwritten along robots redirects: the last one wins
    }
    if (!real()) {
        // Assignment semantics: only a 4xx robots reply lets the page through.
        const bool allowed = status >= 400 && status < 500;
        if (rec_active_) {
            rec_.robots_allowed = allowed;
        }
        if (allowed) {
            w_.stats_.add(Counter::RobotsPassed);
            fetch_page();
        } else {
            finish();
        }
        return;
    }
    if (status >= 200 && status < 300) {
        rules_ = parse::RobotsRules::parse(result.body, kRobotsToken);
        note_crawl_delay();
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
    } else if (status == 429) {
        // Rate limited: treat like a server error, as Google does, rather
        // than as "no robots.txt" (§2.3.1.3 would allow everything).
        robots_decided(Policy::DisallowAll);
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
        if (rec_active_) {
            rec_.robots_allowed = allowed;
        }
    } else if (!allowed && rec_active_) {
        rec_.fetch = "robots_blocked";  // a redirect led to an origin whose robots.txt disallows the page
    }
    if (!allowed) {
        finish();
        return;
    }
    if (delay_skip_) {
        // Honouring a Crawl-delay above --max-crawl-delay would hold the
        // site longer than the run is willing to wait: skip the page.
        w_.stats_.add(Counter::CrawlDelaySkips);
        if (rec_active_) {
            rec_.skip = "crawl_delay";
            if (page_attempted_) {
                rec_.fetch = "crawl_delay";  // a redirect led there
            }
        }
        finish();
        return;
    }
    fetch_page();
}

void Task::on_page(const FetchResult& result) {
    if (retry_later(result.error) || retry_after(result)) {
        return;
    }
    if (result.error != FetchError::None) {
        count_failure(result.error);
        if (rec_active_) {
            rec_.fetch = fetch_error_name(result.error);
        }
        finish();
        return;
    }
    page_replied_ = true;
    last_status_ = result.status;
    const int status = result.status;
    if (rec_active_) {
        rec_.fetch = "ok";
        rec_.set_page_reply(*result.reply, page_, result.body);
    }

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
                    if (rec_active_) {
                        rec_.fetch = "robots_blocked";
                    }
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
        const size_t links = w_.links_.extract(result.body, page_);
        w_.stats_.add(Counter::Links, links);
        if (rec_active_) {
            rec_.links = links;
        }
    }
    finish();
}

void Task::finish() {
    if (page_replied_) {
        w_.stats_.add(Counter::PagesOk);
        w_.stats_.add(status_counter(last_status_));
    }
    phase_ = Phase::Idle;
    release_slot();  // also resets the connection: the next URL needs a different server anyway
    if (rec_active_) {
        rec_.redirects = page_hops_;
    }
    if (https_pending_) {
        done_pending_ = true;  // on_https_rr() completes the task
        return;
    }
    complete();
}

void Task::complete() {
    if (rec_active_) {
        rec_active_ = false;
        rec_.ms = w_.loop_.now() - start_ms_;
        w_.emit(rec_);
    }
    w_.task_done(this);
}

void Task::query_https_rr() {
    if (!rec_active_ || !w_.cfg_.https_rr) {
        return;
    }
    https_pending_ = true;
    w_.resolver_.resolve_https(page_.host,
                               [this](dns::Status status, const dns::HttpsRecord& rr) { on_https_rr(status, rr); });
}

void Task::on_https_rr(dns::Status status, const dns::HttpsRecord& rr) {
    https_pending_ = false;
    SiteRecord::HttpsRr& out = rec_.https_rr;
    // Resolver::shutdown() fails pending queries as Timeout: a cancellation.
    out.status = w_.stopping_ && status == dns::Status::Timeout ? "cancelled" : dns::status_name(status);
    out.present = status == dns::Status::Ok && rr.present;
    out.alias = out.present && rr.alias_mode;
    out.h3 = out.present && rr.alpn_h3;
    out.h2 = out.present && rr.alpn_h2;
    out.ech = out.present && rr.ech;
    if (done_pending_) {
        done_pending_ = false;
        complete();
    }
}

void Task::note_fetch(const FetchResult& result) {
    if (result.tls != nullptr && rec_.tls.handshake == nullptr) {
        note_tls(*result.tls);
    }
    // The first reply of a task is always the seed origin's robots.txt from
    // the seed IP, so CF-RAY here pairs with the seed IP's cf_ip.
    if (result.error == FetchError::None && !rec_.cf_ray) {
        rec_.cf_ray = result.reply->has_header("CF-RAY");
    }
}

void Task::note_tls(const tls::ClientSession& session) {
    SiteRecord::Tls& t = rec_.tls;
    t.protocol = session.protocol();
    if (session.failure() == tls::Failure::Certificate) {
        t.handshake = "certificate";
    } else if (t.protocol != 0) {
        t.handshake = "ok";
    } else if (session.state() == tls::ClientSession::State::Failed) {
        t.handshake = "failed";
    } else {
        t.handshake = "incomplete";  // the fetch ended (timeout, reset) mid-handshake
    }
    if (t.protocol == 0) {
        return;  // no negotiated parameters to report
    }
    const tls::ClientSession::Info info = session.info();  // valid after Failure::Certificate too
    t.cipher = info.cipher;
    t.group = info.key_exchange;
    if (t.group.empty() && info.group != 0) {
        // A group the TLS module has no name for: keep its code point.
        static constexpr char kHex[] = "0123456789abcdef";
        t.group = "0x";
        for (int shift = 12; shift >= 0; shift -= 4) {
            t.group.push_back(kHex[(info.group >> shift) & 15]);
        }
    }
    t.pq = info.pq_hybrid;
    t.resumed = info.resumed;
}

void Task::note_aborted() {
    if (!rec_active_) {
        return;
    }
    if (phase_ == Phase::Robots && funnel_) {
        rec_.robots_error = fetch_error_name(FetchError::Aborted);
    } else if (phase_ == Phase::Robots || phase_ == Phase::Page) {
        rec_.fetch = fetch_error_name(FetchError::Aborted);
    }
}

void Task::abort() {
    if (retry_timer_ != 0) {
        // Waiting out port exhaustion: nothing is in flight, end it here.
        w_.loop_.cancel_timer(retry_timer_);
        retry_timer_ = 0;
        finish();
        return;
    }
    if (hold_ == Hold::Timer) {
        w_.loop_.cancel_timer(wait_timer_);
        wait_timer_ = 0;
        end_wait();
        note_aborted();
        finish();
        return;
    }
    if (hold_ == Hold::Gate) {
        if (w_.gates_.cancel(&wait_)) {
            hold_ = Hold::None;
            w_.unpark(parked_);
            note_aborted();
            finish();
        }
        return;  // otherwise its wake is on the way and on_gate() ends the task
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
      resolver_(loop_, resolver_config(engine.config_, dns_inflight, dns_servers)),
      gates_(engine.gates_),
      recording_(engine.records_.is_open()),
      slots_(slots) {
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
    // By index: a task finishing here may run pump(), which never adds
    // tasks while stopping, but keep the bound fixed anyway.
    for (size_t i = 0, n = tasks_.size(); i < n; ++i) {
        tasks_[i]->abort();  // may finish the task synchronously
    }
    // New sites still queued at a gate end here; ones already woken arrive
    // through ready_ and end in pump().
    for (const auto& seed : seeds_) {
        if (seed->in_use && gates_.cancel(seed.get())) {
            --queued_seeds_;
            end_seed(seed.get());
        }
    }
    update_gauges();
    // Fails queued and in-flight lookups (Timeout); their tasks then finish.
    resolver_.shutdown();
    kick();
    maybe_finish();
}

bool Worker::next_url(std::string_view& out) {
    if (batch_pos_ == batch_.size()) {
        batch_.clear();
        batch_pos_ = 0;
        // Never buffer more URLs than this loop has free slots: at the tail
        // of the input, surplus would wait here while other loops sit idle.
        const size_t room = slots_ > running_ ? slots_ - running_ : 1;
        const size_t want = std::min(kClaimBatch, room);
        if (input_done_ || engine_.input_.claim(want, batch_) == 0) {
            input_done_ = true;
            return false;
        }
    }
    out = batch_[batch_pos_++];
    return true;
}

Task* Worker::take_task(bool admitted_seed) {
    if (!free_.empty()) {
        Task* task = free_.back();
        free_.pop_back();
        return task;
    }
    // Parked tasks keep their task objects, so the pool grows past the slot
    // count (to twice it for new URLs). A site woken at its gate holds a
    // connection slot there and always gets a task: making it wait for one
    // could deadlock against tasks parked behind that very slot.
    if (admitted_seed || tasks_.size() < 2 * static_cast<size_t>(slots_)) {
        tasks_.push_back(std::make_unique<Task>(*this));
        return tasks_.back().get();
    }
    return nullptr;
}

void Worker::kick() {
    if (kick_timer_ != 0 || finishing_) {
        return;
    }
    // Never inline: callers are deep inside a task's or a gate's code.
    kick_timer_ = loop_.add_timer(0, [this] {
        kick_timer_ = 0;
        pump();
    });
}

void Worker::pump() {
    if (pumping_) {
        return;  // a task finished synchronously inside the loop below
    }
    pumping_ = true;
    for (;;) {
        // Sites woken at their gate first: they hold (or were refused) a slot.
        if (!ready_.empty()) {
            Waiter* waiter = ready_.front();
            ready_.pop_front();
            if (waiter->task != nullptr) {
                waiter->task->on_gate(waiter->state);
                continue;
            }
            --queued_seeds_;
            if (stopping_) {
                end_seed(waiter);
                continue;
            }
            Task* task = take_task(true);
            ++running_;
            update_gauges();
            const Waiter seed = *waiter;
            give_seed(waiter);
            task->resume(seed);
            continue;
        }
        if (stopping_ || running_ >= slots_) {
            break;
        }
        Task* task = take_task(false);
        if (task == nullptr) {
            break;
        }
        std::string_view line;
        if (!next_url(line)) {
            free_.push_back(task);
            break;
        }
        ++running_;
        update_gauges();
        task->start(line);  // may finish synchronously (bad URL, duplicate host)
    }
    pumping_ = false;
    maybe_finish();
}

void Worker::task_done(Task* task) {
    free_.push_back(task);
    --running_;
    update_gauges();
    pump();
}

void Worker::emit(const SiteRecord& record) {
    if (records_.capacity() < kRecordBuffer) {
        records_.reserve(kRecordBuffer);  // a recycled buffer keeps its capacity; a fresh one gets it once
    }
    record.append_json(records_);
    ++record_count_;
    if (records_.size() >= kRecordFlush) {
        engine_.records_.submit(records_);
    }
}

Waiter* Worker::take_seed() {
    Waiter* waiter;
    if (!free_seeds_.empty()) {
        waiter = free_seeds_.back();
        free_seeds_.pop_back();
    } else {
        seeds_.push_back(std::make_unique<Waiter>());
        waiter = seeds_.back().get();
        waiter->owner = this;
    }
    waiter->in_use = true;
    waiter->state = GateWaiter::State::Idle;
    return waiter;
}

void Worker::give_seed(Waiter* waiter) {
    waiter->in_use = false;
    waiter->state = GateWaiter::State::Idle;
    free_seeds_.push_back(waiter);
}

void Worker::seed_queued() {
    ++queued_seeds_;
    update_gauges();
}

void Worker::park(bool& counted) {
    ++waiting_tasks_;
    if (parked_ < slots_) {
        ++parked_;
        --running_;
        counted = true;
        kick();  // a slot opened
    }
    update_gauges();
}

void Worker::unpark(bool& counted) {
    --waiting_tasks_;
    if (counted) {
        counted = false;
        --parked_;
        ++running_;
    }
    update_gauges();
}

void Worker::on_wake(GateWaiter* gate_waiter) {
    auto* waiter = static_cast<Waiter*>(gate_waiter);
    Worker* owner = waiter->owner;
    if (owner == this) {
        ready_.push_back(waiter);
        kick();
        return;
    }
    owner->loop_.post([owner, waiter] {
        owner->ready_.push_back(waiter);
        owner->kick();
    });
}

void Worker::arm_gate_timer(uint32_t ip, uint32_t delay_ms) {
    ++gate_timers_;
    loop_.add_timer(delay_ms, [this, ip] {
        --gate_timers_;
        gates_.on_timer(ip, gate_clock_ms(), *this);
        maybe_finish();
    });
}

// A new site that waited at a gate ends without a task: the run is stopping.
void Worker::end_seed(Waiter* waiter) {
    if (waiter->state == GateWaiter::State::Admitted) {
        gates_.release(waiter->ip, Outcome::None, 0, gate_clock_ms(), *this);
    }
    const bool unreachable = waiter->state == GateWaiter::State::Unreachable;
    if (unreachable) {
        stats_.add(Counter::IpUnreachable);
    }
    if (recording_) {
        SiteRecord& r = scratch_;
        r.clear();
        r.url.assign(waiter->line.data(), waiter->line.size());
        parse::Url url;
        parse::parse_url(waiter->line, url);
        r.host = url.host;
        r.seed_https = url.scheme == parse::Scheme::Https;
        r.dns = dns::status_name(dns::Status::Ok);
        r.has_ip = true;
        r.ip = waiter->ip;
        r.cf_ip = cloudflare_ipv4().contains(waiter->ip);
        r.ip_dup = false;
        if (unreachable) {
            r.skip = "ip_unreachable";
        } else {
            r.robots_error = fetch_error_name(FetchError::Aborted);
        }
        if (cfg_.https_rr) {
            r.https_rr.status = "cancelled";
        }
        r.wait_ms = loop_.now() - waiter->queued_ms;
        r.ms = loop_.now() - waiter->start_ms;
        emit(r);
    }
    give_seed(waiter);
}

void Worker::update_gauges() {
    stats_.set(Counter::Inflight, live());
    stats_.set(Counter::PoliteWaiting, waiting_tasks_ + queued_seeds_);
}

void Worker::maybe_finish() {
    if (finishing_ || live() != 0 || !(input_done_ || stopping_)) {
        return;
    }
    if (gate_timers_ != 0 && !stopping_) {
        return;  // sites of other loops may be waiting for those timers
    }
    finishing_ = true;
    if (kick_timer_ != 0) {
        loop_.cancel_timer(kick_timer_);
        kick_timer_ = 0;
    }
    if (recording_) {
        engine_.records_.submit(records_);
        engine_.records_written_.fetch_add(record_count_, std::memory_order_relaxed);
    }
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
    : config_(config),
      input_(input),
      stats_(stats),
      hosts_(input.total()),
      gates_(gate_policy(config), input.total()) {}

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
        // Failure is not fatal: https fetches then fail as tls_fail. The
        // first startup() in the process wins (main may have called it).
        tls::StartupOptions tls_options;
        tls_options.post_quantum = config_.post_quantum;
        tls::startup(tls_options);
    }
    if (!config_.record_path.empty() && !records_.open(config_.record_path, error)) {
        return false;
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
    if (records_.is_open() && !records_.close()) {
        error = "writing the record file " + config_.record_path + " failed";
        return false;
    }
    return true;
}

}  // namespace wc::crawl
