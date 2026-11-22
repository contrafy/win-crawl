#include "benchsrv/http_server.h"

#include "net/tcp.h"

#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace wc::benchsrv {

namespace {

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

// Case-insensitive token search inside a comma-separated header value.
bool has_token(std::string_view value, std::string_view token) {
    size_t pos = 0;
    while (pos <= value.size()) {
        size_t comma = value.find(',', pos);
        if (comma == std::string_view::npos) comma = value.size();
        std::string_view item = value.substr(pos, comma - pos);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1);
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.remove_suffix(1);
        if (iequals(item, token)) return true;
        pos = comma + 1;
    }
    return false;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

void bump(std::atomic<uint64_t>& counter, uint64_t by = 1) {
    counter.store(counter.load(std::memory_order_relaxed) + by, std::memory_order_relaxed);
}

constexpr size_t kRecvBuffer = 8192;  // request heads larger than this get 431

}  // namespace

RequestParse parse_request(const char* data, size_t len, HttpRequest& out) {
    const std::string_view all(data, len);
    const size_t end = all.find("\r\n\r\n");
    if (end == std::string_view::npos) return RequestParse::NeedMore;
    out = HttpRequest{};
    out.length = end + 4;
    std::string_view head = all.substr(0, end + 2);  // every line ends in CRLF

    const size_t line_end = head.find("\r\n");
    std::string_view line = head.substr(0, line_end);
    head.remove_prefix(line_end + 2);
    const size_t sp1 = line.find(' ');
    const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return RequestParse::Bad;
    const std::string_view method = line.substr(0, sp1);
    std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string_view version = line.substr(sp2 + 1);
    if (version.size() != 8 || version.substr(0, 7) != "HTTP/1.") return RequestParse::Bad;
    const bool http10 = version[7] == '0';
    if (target.empty()) return RequestParse::Bad;

    // Absolute-form (proxy style): the authority stands in for a missing Host.
    std::string_view authority;
    if (target.size() > 7 && iequals(target.substr(0, 7), "http://")) {
        target.remove_prefix(7);
        const size_t slash = target.find('/');
        authority = target.substr(0, slash);
        target = slash == std::string_view::npos ? std::string_view("/") : target.substr(slash);
    }

    bool close_token = false;
    bool keep_alive_token = false;
    while (!head.empty()) {
        const size_t eol = head.find("\r\n");
        std::string_view h = head.substr(0, eol);
        head.remove_prefix(eol + 2);
        const size_t colon = h.find(':');
        if (colon == std::string_view::npos || colon == 0) return RequestParse::Bad;
        const std::string_view name = h.substr(0, colon);
        const std::string_view value = trim(h.substr(colon + 1));
        if (iequals(name, "host")) {
            out.host = value;
        } else if (iequals(name, "connection")) {
            close_token = close_token || has_token(value, "close");
            keep_alive_token = keep_alive_token || has_token(value, "keep-alive");
        } else if (iequals(name, "content-length")) {
            if (value != "0") return RequestParse::Bad;
        } else if (iequals(name, "transfer-encoding")) {
            return RequestParse::Bad;
        }
    }
    if (out.host.empty()) out.host = authority;
    out.target = target;
    out.close = http10 ? !keep_alive_token : close_token;
    if (method == "HEAD") {
        out.head = true;
    } else if (method != "GET") {
        return RequestParse::NotImplemented;
    }
    return RequestParse::Ok;
}

// ---------------------------------------------------------------------------

// What a polite crawler must keep within bounds, as the server sees it. One
// mutex: tracking is for tests and politeness runs, not throughput runs.
//
// Concurrency is counted from server-side events that precede the client's
// own: a connection is open from its accept to the last response the server
// issued on it. Counting until the server processes the client's close would
// race: the close (a reset, on one worker thread) and the client's next
// connection (on the acceptor thread) can be processed in either order.
class HttpTracker {
public:
    explicit HttpTracker(bool track) : track_(track), t0_(std::chrono::steady_clock::now()) {}

    bool enabled() const { return track_; }

    double now_ms() const {
        return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0_).count();
    }

    // Acceptor thread. Returns the accept time.
    double accepted(uint32_t ip) {
        const double t = now_ms();
        std::lock_guard lock(mutex_);
        Ip& s = ips_[ip];
        s.track.ip = ip;
        if (s.track.accepts > 0) {
            const double gap = t - s.last_accept;
            if (s.track.min_gap_ms < 0 || gap < s.track.min_gap_ms) s.track.min_gap_ms = gap;
        }
        s.last_accept = t;
        ++s.track.accepts;
        return t;
    }

    // A connection is gone: it was open from `accept_ms` to `last_send_ms`
    // (its accept time when it never got a response).
    void closed(uint32_t ip, double accept_ms, double last_send_ms) {
        std::lock_guard lock(mutex_);
        ips_[ip].spans.emplace_back(accept_ms, std::max(accept_ms, last_send_ms));
    }

    void request(uint64_t host, bool robots, uint16_t status) {
        const double t = now_ms();
        std::lock_guard lock(mutex_);
        hosts_[host].push_back(RequestEvent{t, status, robots});
    }

    // True exactly once per host: its first page request (Behavior::throttle).
    bool first_page(uint64_t host) {
        std::lock_guard lock(mutex_);
        return throttled_.insert(host).second;
    }

    std::vector<IpTrack> ips() const {
        std::lock_guard lock(mutex_);
        std::vector<IpTrack> out;
        out.reserve(ips_.size());
        std::vector<std::pair<double, int>> events;
        for (const auto& [ip, s] : ips_) {
            IpTrack t = s.track;
            // Sweep: ends sort before starts at the same instant (no overlap).
            events.clear();
            for (const auto& [from, to] : s.spans) {
                events.emplace_back(from, +1);
                events.emplace_back(to, -1);
            }
            std::sort(events.begin(), events.end());
            int open = 0;
            for (const auto& e : events) {
                open += e.second;
                t.max_open = std::max(t.max_open, static_cast<uint32_t>(std::max(open, 0)));
            }
            out.push_back(t);
        }
        return out;
    }

    std::vector<RequestEvent> requests(uint64_t host) const {
        std::lock_guard lock(mutex_);
        const auto it = hosts_.find(host);
        return it == hosts_.end() ? std::vector<RequestEvent>{} : it->second;
    }

    size_t host_count() const {
        std::lock_guard lock(mutex_);
        return hosts_.size();
    }

private:
    struct Ip {
        IpTrack track;
        double last_accept = 0;
        std::vector<std::pair<double, double>> spans;  // closed connections: accept .. last response
    };

    const bool track_;
    const std::chrono::steady_clock::time_point t0_;
    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, Ip> ips_;
    std::unordered_map<uint64_t, std::vector<RequestEvent>> hosts_;
    std::unordered_set<uint64_t> throttled_;
};

// ---------------------------------------------------------------------------

enum class ConnState : uint8_t { Free, Reading, Delaying, Sending, Closing };

struct Conn final : net::TcpHandler {
    Conn(HttpWorker& w, net::Loop& loop) : worker(w), socket(loop, *this), buf(new char[kRecvBuffer]) {}

    void on_connect(net::TcpSocket&, DWORD) override {}
    void on_send(net::TcpSocket&, DWORD error) override;
    void on_recv(net::TcpSocket&, size_t bytes, DWORD error) override;

    HttpWorker& worker;
    net::TcpSocket socket;
    std::unique_ptr<char[]> buf;
    size_t len = 0;      // buffered request bytes
    size_t req_len = 0;  // head length of the request being answered
    ConnState state = ConnState::Free;
    bool close_after = false;
    const char* out = nullptr;
    size_t out_len = 0;
    uint16_t status = 0;
    net::TimerId timer = 0;
    uint64_t last_active = 0;
    uint32_t local_ip = 0;
    double accept_ms = 0;      // tracking: when the acceptor took the connection
    double last_send_ms = -1;  // tracking: when the last response was issued
    Conn* prev = nullptr;
    Conn* next = nullptr;
};

class HttpWorker {
public:
    HttpWorker(const Behavior& behavior, const HttpServerConfig& config, HttpTracker& tracker)
        : behavior_(behavior), config_(config), tracker_(tracker) {}

    net::Loop& loop() { return loop_; }
    void set_responses(const ResponseSet* responses) { responses_ = responses; }

    void start_sweep() {
        const uint32_t period = std::max<uint32_t>(50, std::min<uint32_t>(1000, config_.idle_timeout_ms / 4));
        sweep_timer_ = loop_.add_timer(period, [this] { sweep(); });
    }

    // Loop thread. Takes ownership of an accepted socket.
    void adopt(SOCKET s, uint32_t local_ip, double accept_ms) {
        if (stopping_) {
            const linger lg{1, 0};
            setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
            closesocket(s);
            if (tracker_.enabled()) tracker_.closed(local_ip, accept_ms, accept_ms);
            return;
        }
        Conn* c;
        if (!free_.empty()) {
            c = free_.back();
            free_.pop_back();
        } else {
            all_.push_back(std::make_unique<Conn>(*this, loop_));
            c = all_.back().get();
        }
        const BOOL nodelay = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
        if (c->socket.adopt(s) != 0) {  // adopt() closed the socket
            free_.push_back(c);
            if (tracker_.enabled()) tracker_.closed(local_ip, accept_ms, accept_ms);
            return;
        }
        c->state = ConnState::Reading;
        c->len = 0;
        c->req_len = 0;
        c->timer = 0;
        c->local_ip = local_ip;
        c->accept_ms = accept_ms;
        c->last_send_ms = -1;
        c->last_active = loop_.now();
        c->prev = nullptr;
        c->next = live_;
        if (live_) live_->prev = c;
        live_ = c;
        bump(stats_.accepted);
        c->socket.recv(c->buf.get(), kRecvBuffer);
    }

    void on_recv(Conn& c, size_t bytes, DWORD error) {
        if (c.state == ConnState::Closing) {
            release_if_idle(c);
            return;
        }
        if (error != 0 || bytes == 0) {
            // Peer is done (FIN or RST). Resetting from CLOSE_WAIT moves the
            // peer from FIN_WAIT_2 straight to CLOSED: no TIME_WAIT anywhere.
            abort(c);
            return;
        }
        c.last_active = loop_.now();
        c.len += bytes;
        serve(c);
    }

    void on_send(Conn& c, DWORD error) {
        if (c.state == ConnState::Closing) {
            release_if_idle(c);
            return;
        }
        if (error != 0) {
            abort(c);
            return;
        }
        count_response(c);
        c.last_active = loop_.now();
        if (c.close_after) {
            // Close-delimited readers (HTTP/1.0, the legacy crawler) need our
            // FIN, so this is a normal close and the server side keeps the
            // TIME_WAIT. That costs no client ephemeral ports, and clients that
            // read by length and reset first (wc::net's default) avoid it. On
            // Windows an abortive close after shutdown(SD_SEND) does not send
            // an RST, so there is no cheaper way out for EOF readers.
            c.socket.close(false);
            c.state = ConnState::Closing;
            release_if_idle(c);
            return;
        }
        std::memmove(c.buf.get(), c.buf.get() + c.req_len, c.len - c.req_len);
        c.len -= c.req_len;
        c.req_len = 0;
        serve(c);
    }

    void begin_shutdown() {
        stopping_ = true;
        if (sweep_timer_ != 0) loop_.cancel_timer(sweep_timer_);
        sweep_timer_ = 0;
        for (Conn* c = live_; c != nullptr;) {
            Conn* next = c->next;
            if (c->state != ConnState::Closing) abort(*c);
            c = next;
        }
        finish_when_drained();
    }

    void add_counters(HttpCounters& out) const {
        out.requests += stats_.requests.load(std::memory_order_relaxed);
        out.robots += stats_.robots.load(std::memory_order_relaxed);
        out.status_2xx += stats_.s2xx.load(std::memory_order_relaxed);
        out.status_3xx += stats_.s3xx.load(std::memory_order_relaxed);
        out.status_4xx += stats_.s4xx.load(std::memory_order_relaxed);
        out.status_5xx += stats_.s5xx.load(std::memory_order_relaxed);
        out.bytes_sent += stats_.bytes.load(std::memory_order_relaxed);
        out.accepted += stats_.accepted.load(std::memory_order_relaxed);
        out.active += stats_.accepted.load(std::memory_order_relaxed) - stats_.released.load(std::memory_order_relaxed);
    }

private:
    // Answers every complete request in the buffer, one at a time; otherwise reads more.
    void serve(Conn& c) {
        HttpRequest req;
        const RequestParse result = parse_request(c.buf.get(), c.len, req);
        const Response* resp = nullptr;
        bool close = true;
        uint32_t delay = 0;
        switch (result) {
            case RequestParse::NeedMore:
                if (c.len == kRecvBuffer) {
                    resp = &responses_->too_large();
                    c.req_len = c.len;
                    break;
                }
                c.state = ConnState::Reading;
                c.socket.recv(c.buf.get() + c.len, kRecvBuffer - c.len);
                return;
            case RequestParse::Bad:
                resp = &responses_->bad_request();
                c.req_len = c.len;
                break;
            case RequestParse::NotImplemented:
                resp = &responses_->not_implemented();
                c.req_len = req.length;
                break;
            case RequestParse::Ok: {
                c.req_len = req.length;
                close = req.close;
                const int conn = close ? 1 : 0;
                uint64_t n = 0;
                if (auto hn = host_header_number(req.host, behavior_.zone)) {
                    n = *hn;
                } else if (auto ipn = ip_host_number(c.local_ip)) {
                    n = *ipn;
                }
                const std::string_view path = req.target;
                const bool robots = path == "/robots.txt" || path.substr(0, 12) == "/robots.txt?";
                if (robots) {
                    bump(stats_.robots);
                    const bool missing = robots_missing(behavior_, n);
                    resp = !missing && host_crawl_delay(behavior_, n) ? &responses_->robots_delayed(conn)
                                                                     : &responses_->robots(missing, conn);
                } else if (behavior_.throttle > 0 && host_throttled(behavior_, n) && tracker_.first_page(n)) {
                    resp = &responses_->throttled(conn);
                } else {
                    const PagePlan plan = page_plan(behavior_, n, path);
                    switch (plan.kind) {
                        case PageKind::Ok: resp = &responses_->page(plan.template_index, plan.chunked, conn); break;
                        case PageKind::Redirect: resp = &responses_->redirect(conn); break;
                        case PageKind::NotFound: resp = &responses_->not_found(conn); break;
                        case PageKind::ServerError: resp = &responses_->server_error(conn); break;
                    }
                }
                if (tracker_.enabled()) tracker_.request(n, robots, resp->status);
                delay = http_delay_ms(behavior_, n, path);
                break;
            }
        }
        c.close_after = close;
        c.out = resp->data.data();
        c.out_len = req.head && result == RequestParse::Ok ? resp->head_len : resp->data.size();
        c.status = resp->status;
        if (delay != 0) {
            c.state = ConnState::Delaying;
            Conn* cp = &c;
            c.timer = loop_.add_timer(delay, [this, cp] {
                cp->timer = 0;
                send_response(*cp);
            });
            return;
        }
        send_response(c);
    }

    void send_response(Conn& c) {
        c.state = ConnState::Sending;
        if (tracker_.enabled()) c.last_send_ms = tracker_.now_ms();  // before the client can see it
        c.socket.send(c.out, c.out_len);
    }

    void count_response(const Conn& c) {
        bump(stats_.requests);
        bump(stats_.bytes, c.out_len);
        switch (c.status / 100) {
            case 2: bump(stats_.s2xx); break;
            case 3: bump(stats_.s3xx); break;
            case 4: bump(stats_.s4xx); break;
            case 5: bump(stats_.s5xx); break;
            default: break;
        }
    }

    void abort(Conn& c) {
        if (c.timer != 0) {
            loop_.cancel_timer(c.timer);
            c.timer = 0;
        }
        c.socket.close(true);
        c.state = ConnState::Closing;
        release_if_idle(c);
    }

    void release_if_idle(Conn& c) {
        if (c.socket.busy()) return;
        if (c.prev) c.prev->next = c.next;
        else live_ = c.next;
        if (c.next) c.next->prev = c.prev;
        c.prev = c.next = nullptr;
        c.state = ConnState::Free;
        free_.push_back(&c);
        bump(stats_.released);
        if (tracker_.enabled()) tracker_.closed(c.local_ip, c.accept_ms, c.last_send_ms);
    }

    void sweep() {
        sweep_timer_ = 0;
        const uint64_t now = loop_.now();
        for (Conn* c = live_; c != nullptr;) {
            Conn* next = c->next;
            if (c->state == ConnState::Reading && now - c->last_active >= config_.idle_timeout_ms) {
                abort(*c);
            }
            c = next;
        }
        if (!stopping_) start_sweep();
    }

    void finish_when_drained() {
        if (live_ == nullptr) {
            loop_.stop();
            return;
        }
        loop_.add_timer(1, [this] { finish_when_drained(); });
    }

    const Behavior& behavior_;
    const HttpServerConfig& config_;
    HttpTracker& tracker_;
    const ResponseSet* responses_ = nullptr;
    net::Loop loop_;
    std::vector<std::unique_ptr<Conn>> all_;
    std::vector<Conn*> free_;
    Conn* live_ = nullptr;
    net::TimerId sweep_timer_ = 0;
    bool stopping_ = false;

    // Single writer (this loop); stats readers load relaxed. Open connections
    // are accepted - released so neither side needs a read-modify-write.
    struct Stats {
        std::atomic<uint64_t> requests{0}, robots{0}, s2xx{0}, s3xx{0}, s4xx{0}, s5xx{0}, bytes{0};
        std::atomic<uint64_t> accepted{0}, released{0};
    } stats_;
};

void Conn::on_send(net::TcpSocket&, DWORD error) { worker.on_send(*this, error); }
void Conn::on_recv(net::TcpSocket&, size_t bytes, DWORD error) { worker.on_recv(*this, bytes, error); }

// ---------------------------------------------------------------------------

class HttpServer::Acceptor {
public:
    Acceptor(std::vector<std::unique_ptr<HttpWorker>>& workers, HttpTracker& tracker)
        : workers_(workers), tracker_(tracker) {}

    net::Loop& loop() { return loop_; }

    // Before the loop runs. Returns 0 or a WinSock error.
    DWORD listen(const sockaddr_in& local, size_t accept_depth, sockaddr_in& bound) {
        auto listener = std::make_unique<net::TcpListener>(loop_, [this](SOCKET s) { on_accept(s); });
        // Plain SOMAXCONN gives ~200 on Windows; crawler connect bursts need far more.
        const DWORD err = listener->listen(local, SOMAXCONN_HINT(16384), accept_depth);
        if (err != 0) return err;
        bound = listener->local_address();
        listeners_.push_back(std::move(listener));
        return 0;
    }

    void shutdown_on_loop() {
        for (auto& l : listeners_) l->close();
        finish_when_drained();
    }

private:
    void on_accept(SOCKET s) {
        // The local address tells IP-literal clients' host number apart even
        // without a Host header.
        sockaddr_in local{};
        int len = sizeof(local);
        uint32_t local_ip = 0;
        if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &len) == 0) local_ip = local.sin_addr.s_addr;
        const double accept_ms = tracker_.enabled() ? tracker_.accepted(local_ip) : 0;
        HttpWorker* w = workers_[next_++ % workers_.size()].get();
        w->loop().post([w, s, local_ip, accept_ms] { w->adopt(s, local_ip, accept_ms); });
    }

    void finish_when_drained() {
        bool busy = false;
        for (const auto& l : listeners_) busy = busy || l->busy();
        if (!busy) {
            loop_.stop();
            return;
        }
        loop_.add_timer(1, [this] { finish_when_drained(); });
    }

    std::vector<std::unique_ptr<HttpWorker>>& workers_;
    HttpTracker& tracker_;
    net::Loop loop_;
    std::vector<std::unique_ptr<net::TcpListener>> listeners_;
    size_t next_ = 0;
};

HttpServer::HttpServer(const Behavior& behavior, const HttpServerConfig& config)
    : behavior_(behavior), config_(config), tracker_(std::make_unique<HttpTracker>(config.track)) {
    const uint32_t n = config_.threads == 0 ? 1 : config_.threads;
    for (uint32_t i = 0; i < n; ++i) workers_.push_back(std::make_unique<HttpWorker>(behavior_, config_, *tracker_));
    acceptor_ = std::make_unique<Acceptor>(workers_, *tracker_);
}

HttpServer::~HttpServer() { stop(); }

DWORD HttpServer::start(const sockaddr_in& local) { return start(std::vector<sockaddr_in>{local}); }

DWORD HttpServer::start(const std::vector<sockaddr_in>& locals) {
    if (locals.empty()) return WSAEINVAL;
    DWORD late_error = 0;
    for (size_t i = 0; i < locals.size(); ++i) {
        sockaddr_in local = locals[i];
        if (i > 0 && local.sin_port == 0) local.sin_port = local_.sin_port;  // share the first port
        sockaddr_in bound{};
        if (const DWORD err = acceptor_->listen(local, config_.accept_depth, bound)) {
            if (i == 0) return err;
            // Earlier listeners have accepts outstanding: run the loops so
            // stop() can drain them, then report the failure.
            late_error = err;
            break;
        }
        if (i == 0) local_ = bound;
    }
    responses_ = std::make_unique<ResponseSet>(behavior_, ntohs(local_.sin_port));
    for (auto& w : workers_) {
        w->set_responses(responses_.get());
        w->start_sweep();  // before run(): nothing else touches the loop yet
        HttpWorker* wp = w.get();
        worker_threads_.emplace_back([wp] { wp->loop().run(); });
    }
    acceptor_thread_ = std::thread([this] { acceptor_->loop().run(); });
    if (late_error != 0) {
        stop();
        return late_error;
    }
    return 0;
}

void HttpServer::stop() {
    if (!acceptor_thread_.joinable()) return;
    // Acceptor first, so no adopt() is posted to a worker after its shutdown.
    acceptor_->loop().post([this] { acceptor_->shutdown_on_loop(); });
    acceptor_thread_.join();
    for (auto& w : workers_) {
        HttpWorker* wp = w.get();
        wp->loop().post([wp] { wp->begin_shutdown(); });
    }
    for (auto& t : worker_threads_) t.join();
    worker_threads_.clear();
}

HttpCounters HttpServer::counters() const {
    HttpCounters c;
    for (const auto& w : workers_) w->add_counters(c);
    return c;
}

std::vector<IpTrack> HttpServer::ip_tracks() const { return tracker_->ips(); }

std::vector<RequestEvent> HttpServer::host_requests(uint64_t host) const { return tracker_->requests(host); }

size_t HttpServer::tracked_hosts() const { return tracker_->host_count(); }

}  // namespace wc::benchsrv
