#include "benchsrv/http_server.h"

#include "net/tcp.h"

#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <cstring>

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
    Conn* prev = nullptr;
    Conn* next = nullptr;
};

class HttpWorker {
public:
    HttpWorker(const Behavior& behavior, const HttpServerConfig& config) : behavior_(behavior), config_(config) {}

    net::Loop& loop() { return loop_; }
    void set_responses(const ResponseSet* responses) { responses_ = responses; }

    void start_sweep() {
        const uint32_t period = std::max<uint32_t>(50, std::min<uint32_t>(1000, config_.idle_timeout_ms / 4));
        sweep_timer_ = loop_.add_timer(period, [this] { sweep(); });
    }

    // Loop thread. Takes ownership of an accepted socket.
    void adopt(SOCKET s, uint32_t local_ip) {
        if (stopping_) {
            const linger lg{1, 0};
            setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
            closesocket(s);
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
            return;
        }
        c->state = ConnState::Reading;
        c->len = 0;
        c->req_len = 0;
        c->timer = 0;
        c->local_ip = local_ip;
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
                if (path == "/robots.txt" || path.substr(0, 12) == "/robots.txt?") {
                    bump(stats_.robots);
                    resp = &responses_->robots(robots_missing(behavior_, n), conn);
                } else {
                    const PagePlan plan = page_plan(behavior_, n, path);
                    switch (plan.kind) {
                        case PageKind::Ok: resp = &responses_->page(plan.template_index, plan.chunked, conn); break;
                        case PageKind::Redirect: resp = &responses_->redirect(conn); break;
                        case PageKind::NotFound: resp = &responses_->not_found(conn); break;
                        case PageKind::ServerError: resp = &responses_->server_error(conn); break;
                    }
                }
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
    explicit Acceptor(std::vector<std::unique_ptr<HttpWorker>>& workers)
        : workers_(workers), listener_(loop_, [this](SOCKET s) { on_accept(s); }) {}

    net::Loop& loop() { return loop_; }
    net::TcpListener& listener() { return listener_; }

    void shutdown_on_loop() {
        listener_.close();
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
        HttpWorker* w = workers_[next_++ % workers_.size()].get();
        w->loop().post([w, s, local_ip] { w->adopt(s, local_ip); });
    }

    void finish_when_drained() {
        if (!listener_.busy()) {
            loop_.stop();
            return;
        }
        loop_.add_timer(1, [this] { finish_when_drained(); });
    }

    std::vector<std::unique_ptr<HttpWorker>>& workers_;
    net::Loop loop_;
    net::TcpListener listener_;
    size_t next_ = 0;
};

HttpServer::HttpServer(const Behavior& behavior, const HttpServerConfig& config)
    : behavior_(behavior), config_(config) {
    const uint32_t n = config_.threads == 0 ? 1 : config_.threads;
    for (uint32_t i = 0; i < n; ++i) workers_.push_back(std::make_unique<HttpWorker>(behavior_, config_));
    acceptor_ = std::make_unique<Acceptor>(workers_);
}

HttpServer::~HttpServer() { stop(); }

DWORD HttpServer::start(const sockaddr_in& local) {
    // Plain SOMAXCONN gives ~200 on Windows; crawler connect bursts need far more.
    const DWORD err = acceptor_->listener().listen(local, SOMAXCONN_HINT(16384), config_.accept_depth);
    if (err != 0) return err;
    local_ = acceptor_->listener().local_address();
    responses_ = std::make_unique<ResponseSet>(behavior_, ntohs(local_.sin_port));
    for (auto& w : workers_) {
        w->set_responses(responses_.get());
        w->start_sweep();  // before run(): nothing else touches the loop yet
        HttpWorker* wp = w.get();
        worker_threads_.emplace_back([wp] { wp->loop().run(); });
    }
    acceptor_thread_ = std::thread([this] { acceptor_->loop().run(); });
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

}  // namespace wc::benchsrv
