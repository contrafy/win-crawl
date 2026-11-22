#include "crawl/connection.h"

#include "net/addr.h"

#include <algorithm>
#include <cassert>

namespace wc::crawl {

namespace {

constexpr size_t kInitialRx = 16 * 1024;
constexpr size_t kMinRecv = 8 * 1024;
// Buffers above this are released after the reply that grew them, so a few
// large pages do not pin megabytes in every task slot.
constexpr size_t kShrinkTo = 64 * 1024;
// One TLS record is at most 16 KiB + overhead; two fit.
constexpr size_t kTlsRecv = 34 * 1024;

// SO_REUSE_UNICASTPORT is not honoured everywhere, so every outbound socket
// pins an ephemeral port; these errors mean the machine ran out for now.
bool is_port_pressure(DWORD error) {
    return error == WSAENOBUFS || error == WSAEADDRINUSE;
}

}  // namespace

const char* fetch_error_name(FetchError error) {
    switch (error) {
    case FetchError::None: return "none";
    case FetchError::ConnectFail: return "connect_fail";
    case FetchError::Timeout: return "timeout";
    case FetchError::TlsFail: return "tls_fail";
    case FetchError::TlsCertificate: return "tls_certificate";
    case FetchError::TooLarge: return "too_large";
    case FetchError::BadReply: return "bad_reply";
    case FetchError::Closed: return "closed";
    case FetchError::NoPorts: return "no_ports";
    case FetchError::Aborted: return "aborted";
    }
    return "?";
}

Connection::Connection(net::Loop& loop, FetchHandler& handler, CounterBlock* stats, tls::Verify verify)
    : loop_(loop), handler_(handler), stats_(stats), verify_(verify), socket_(loop, *this) {}

Connection::~Connection() {
    assert(!busy() && "destroying a Connection with a fetch in progress");
    cancel_timers();
    if (socket_.is_open()) {
        socket_.close(true);
    }
}

void Connection::fetch(const Endpoint& endpoint, std::string_view request, const FetchOptions& options) {
    assert(!busy());
    active_ = true;
    in_fetch_ = true;
    done_ = false;
    eof_ = false;
    retried_ = false;
    handshaking_ = false;
    drain_ = Drain::None;
    error_ = FetchError::None;
    options_ = options;
    request_.assign(request.data(), request.size());
    reset_buffers();
    fetch_timer_ = loop_.add_timer(options.timeout_ms, [this] {
        fetch_timer_ = 0;
        fail(FetchError::Timeout);
    });

    const bool same = keep_open_ && ip_ == endpoint.ipv4_be && port_ == endpoint.port && is_tls_ == endpoint.tls &&
                      server_name_ == endpoint.server_name;
    keep_open_ = false;
    if (same) {
        reused_ = true;
        send_request();
        if (!draining()) {
            start_recv();
        }
    } else {
        if (socket_.is_open()) {
            socket_.close(true);  // idle: nothing outstanding, so not busy afterwards
        }
        ip_ = endpoint.ipv4_be;
        port_ = endpoint.port;
        is_tls_ = endpoint.tls;
        server_name_.assign(endpoint.server_name.data(), endpoint.server_name.size());
        reused_ = false;
        start_connect();
    }
    in_fetch_ = false;
}

void Connection::abort() {
    if (active_) {
        fail(FetchError::Aborted);
    } else {
        close();
    }
}

void Connection::close() {
    assert(!active_);
    keep_open_ = false;
    if (socket_.is_open()) {
        socket_.close(true);
    }
    tls_.reset();
    // An idle slot should not pin a multi-megabyte page until its next fetch.
    if (rx_.capacity() > kShrinkTo) {
        std::vector<char>().swap(rx_);
        rx_len_ = 0;
    }
}

void Connection::reset_buffers() {
    if (rx_.capacity() > kShrinkTo) {
        std::vector<char>().swap(rx_);
    }
    rx_len_ = 0;
    tx_.clear();
    wire_.clear();
    parser_.reset(options_.head, options_.limit);
}

void Connection::cancel_timers() {
    if (fetch_timer_ != 0) {
        loop_.cancel_timer(fetch_timer_);
        fetch_timer_ = 0;
    }
    if (connect_timer_ != 0) {
        loop_.cancel_timer(connect_timer_);
        connect_timer_ = 0;
    }
}

void Connection::start_connect() {
    tls_.reset();
    const DWORD err = socket_.open();
    if (err != 0) {
        fail(is_port_pressure(err) ? FetchError::NoPorts : FetchError::ConnectFail);
        return;
    }
    ++connects_;
    connect_timer_ = loop_.add_timer(options_.connect_timeout_ms, [this] {
        connect_timer_ = 0;
        fail(FetchError::ConnectFail);
    });
    socket_.connect(net::make_addr(ip_, port_));
}

void Connection::on_connect(net::TcpSocket&, DWORD error) {
    if (connect_timer_ != 0) {
        loop_.cancel_timer(connect_timer_);
        connect_timer_ = 0;
    }
    if (draining()) {
        settle();
        return;
    }
    if (error != 0) {
        fail(is_port_pressure(error) ? FetchError::NoPorts : FetchError::ConnectFail);
        return;
    }
    if (is_tls_) {
        tls_.emplace(server_name_, verify_);
        handshaking_ = true;
        if (tls_->start(wire_) == tls::ClientSession::State::Failed) {
            fail(FetchError::TlsFail);
            return;
        }
        flush_wire();
        start_recv();
        return;
    }
    send_request();
    start_recv();
}

void Connection::send_request() {
    if (is_tls_) {
        if (!tls_ || !tls_->encrypt(request_.data(), request_.size(), wire_)) {
            fail(FetchError::TlsFail);
            return;
        }
        flush_wire();
        return;
    }
    sending_ = true;
    socket_.send(request_.data(), request_.size());
}

void Connection::flush_wire() {
    if (sending_ || wire_.empty()) {
        return;
    }
    // tx_ must stay untouched until on_send; later output collects in wire_.
    tx_.swap(wire_);
    wire_.clear();
    sending_ = true;
    socket_.send(tx_.data(), tx_.size());
}

void Connection::on_send(net::TcpSocket&, DWORD error) {
    sending_ = false;
    if (draining()) {
        settle();
        return;
    }
    if (error != 0) {
        if (stale_keepalive()) {
            retry_fresh();
        } else {
            fail(handshaking_ ? FetchError::TlsFail : FetchError::Closed);
        }
        return;
    }
    if (is_tls_) {
        flush_wire();
    }
}

void Connection::start_recv() {
    if (recving_) {
        return;
    }
    if (is_tls_) {
        if (raw_.size() < kTlsRecv) {
            raw_.resize(kTlsRecv);
        }
        recving_ = true;
        socket_.recv(raw_.data(), raw_.size());
        return;
    }
    // Plain HTTP reads straight into the reply buffer; rx_.size() is its
    // usable capacity. Reading one byte past the limit lets the parser see
    // the overflow instead of the connection stalling at the cap.
    const size_t cap = options_.limit + 1;
    if (rx_.size() - rx_len_ < kMinRecv && rx_.size() < cap) {
        size_t grown = std::max({rx_.size() * 2, rx_len_ + 2 * kMinRecv, kInitialRx});
        rx_.resize(std::min(grown, cap));
    }
    const size_t room = rx_len_ < cap ? cap - rx_len_ : 1;
    const size_t want = std::min(rx_.size() - rx_len_, room);
    if (want == 0) {
        fail(FetchError::TooLarge);
        return;
    }
    recving_ = true;
    socket_.recv(rx_.data() + rx_len_, want);
}

void Connection::on_recv(net::TcpSocket&, size_t bytes, DWORD error) {
    recving_ = false;
    if (draining()) {
        settle();
        return;
    }
    if (error != 0) {
        if (stale_keepalive()) {
            retry_fresh();
        } else {
            fail(handshaking_ ? FetchError::TlsFail : FetchError::Closed);
        }
        return;
    }
    if (bytes == 0) {  // FIN
        if (handshaking_) {
            fail(FetchError::TlsFail);
        } else if (stale_keepalive()) {
            retry_fresh();
        } else {
            eof_ = true;
            on_reply_bytes(true);
        }
        return;
    }
    if (stats_ != nullptr) {
        stats_->add(Counter::BytesReceived, bytes);
    }
    if (!is_tls_) {
        rx_len_ += bytes;
        on_reply_bytes(false);
        return;
    }

    rx_.resize(rx_len_);
    const tls::ClientSession::State state = tls_->feed(raw_.data(), bytes, wire_, rx_);
    rx_len_ = rx_.size();
    if (state == tls::ClientSession::State::Failed) {
        fail(tls_->failure() == tls::Failure::Certificate ? FetchError::TlsCertificate : FetchError::TlsFail);
        return;
    }
    flush_wire();
    if (handshaking_) {
        if (state == tls::ClientSession::State::Handshaking) {
            start_recv();
            return;
        }
        if (state != tls::ClientSession::State::Established) {
            fail(FetchError::TlsFail);
            return;
        }
        handshaking_ = false;
        send_request();
        if (draining()) {
            return;
        }
        if (rx_len_ == 0) {
            start_recv();
            return;
        }
    }
    if (state == tls::ClientSession::State::Closed) {  // close_notify
        if (stale_keepalive()) {
            retry_fresh();
        } else {
            eof_ = true;
            on_reply_bytes(true);
        }
        return;
    }
    on_reply_bytes(false);
}

void Connection::on_reply_bytes(bool eof) {
    parse::ParseStatus st = parser_.parse(rx_.data(), rx_len_);
    if (eof && st == parse::ParseStatus::NeedMore) {
        st = parser_.finish(rx_.data(), rx_len_);
    }
    switch (st) {
    case parse::ParseStatus::NeedMore:
        if (eof) {
            fail(FetchError::Closed);
        } else {
            start_recv();
        }
        return;
    case parse::ParseStatus::Error:
        switch (parser_.error()) {
        case parse::HttpError::TooLarge: fail(FetchError::TooLarge); break;
        case parse::HttpError::Truncated: fail(FetchError::Closed); break;
        default: fail(FetchError::BadReply); break;
        }
        return;
    case parse::ParseStatus::Done:
        complete();
        return;
    }
}

void Connection::complete() {
    done_ = true;
    cancel_timers();
    // Reuse only a cleanly framed reply with nothing unexpected behind it, including
    // TLS output (e.g. a KeyUpdate reply) still waiting to be sent.
    keep_open_ = options_.keep_alive && parser_.keep_alive() && !eof_ && parser_.consumed() == rx_len_ &&
                 wire_.empty() &&
                 (!is_tls_ || (tls_ && tls_->state() == tls::ClientSession::State::Established &&
                               tls_->pending_input() == 0));
    if (!keep_open_) {
        socket_.close(true);
    }
    settle();
}

void Connection::fail(FetchError error) {
    if (!active_ || error_ != FetchError::None || done_) {
        return;  // the first outcome wins
    }
    error_ = error;
    drain_ = Drain::Deliver;
    cancel_timers();
    keep_open_ = false;
    if (socket_.is_open()) {
        socket_.close(true);
    }
    settle();
}

void Connection::retry_fresh() {
    retried_ = true;
    reused_ = false;
    socket_.close(true);
    rx_len_ = 0;
    tx_.clear();
    wire_.clear();
    parser_.reset(options_.head, options_.limit);
    drain_ = Drain::Reconnect;
    settle();
}

void Connection::settle() {
    if (socket_.busy()) {
        return;  // the remaining completions call settle() again
    }
    if (error_ == FetchError::None && !done_ && drain_ == Drain::Reconnect) {
        drain_ = Drain::None;
        start_connect();
        return;
    }
    if (in_fetch_) {
        // Never complete inside fetch(): the caller is still on its stack.
        if (defer_timer_ == 0) {
            defer_timer_ = loop_.add_timer(0, [this] {
                defer_timer_ = 0;
                settle();
            });
        }
        return;
    }
    if (defer_timer_ != 0) {
        loop_.cancel_timer(defer_timer_);
        defer_timer_ = 0;
    }
    deliver();
}

void Connection::deliver() {
    active_ = false;
    drain_ = Drain::None;
    FetchResult result;
    result.error = error_;
    result.reused = reused_;
    result.tls = is_tls_ && tls_ ? &*tls_ : nullptr;
    if (error_ == FetchError::None) {
        result.status = parser_.status();
        result.reply = &parser_;
        result.body = parser_.body();
    }
    handler_.on_fetch(*this, result);  // last: the handler may start the next fetch
}

}  // namespace wc::crawl
