#pragma once
// One HTTP client connection on one loop: TcpSocket + optional TLS session +
// incremental response parser, with keep-alive reuse between fetches.
//
// A fetch names its endpoint; when the previous fetch left a reusable
// connection to the same endpoint the request goes out on it, otherwise the
// old socket is reset and a new one connected. A kept-alive connection that
// the server closed before answering is retried once on a fresh connection.
//
// Completion is reported exactly once per fetch through FetchHandler, on the
// loop thread, never inside fetch(), and only once the socket has no
// operations outstanding, so the handler may immediately start the next
// fetch. The Connection does not touch itself after calling the handler.

#include "crawl/stats.h"
#include "net/loop.h"
#include "net/tcp.h"
#include "parse/http.h"
#include "tls/tls.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wc::crawl {

enum class FetchError : uint8_t {
    None,
    ConnectFail,  // connect refused/unreachable or connect timeout
    Timeout,      // the whole fetch exceeded its time budget
    TlsFail,      // handshake or record failure
    TlsCertificate,  // the peer certificate failed verification (Verify::Chain)
    TooLarge,     // reply exceeded the size limit
    BadReply,     // not a parsable HTTP reply
    Closed,       // peer closed or reset before the reply was complete
    NoPorts,      // no ephemeral port/buffers for a new socket: transient, retry later
    Aborted,      // Connection::abort()
};

const char* fetch_error_name(FetchError error);

struct Endpoint {
    uint32_t ipv4_be = 0;
    uint16_t port = 80;  // host byte order
    bool tls = false;
    std::string_view server_name;  // TLS SNI + certificate name; keys reuse
};

struct FetchOptions {
    bool head = false;          // the request is HEAD (reply has no body)
    size_t limit = 0;           // cap on the raw reply bytes
    uint32_t timeout_ms = 10000;  // whole fetch, connect included
    uint32_t connect_timeout_ms = 5000;
    bool keep_alive = true;     // false: close after this reply regardless
};

struct FetchResult {
    FetchError error = FetchError::None;
    int status = 0;  // valid when error == None
    // Valid when error == None, only for the duration of the callback.
    const parse::ResponseParser* reply = nullptr;
    std::string_view body;
    bool reused = false;  // request went out on a kept-alive connection
};

class Connection;

class FetchHandler {
public:
    virtual void on_fetch(Connection& connection, const FetchResult& result) = 0;

protected:
    ~FetchHandler() = default;
};

class Connection final : private net::TcpHandler {
public:
    // `stats` (may be null) receives BytesReceived for every byte read.
    Connection(net::Loop& loop, FetchHandler& handler, CounterBlock* stats, tls::Verify verify);
    ~Connection();  // requires !busy()
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // Requires !busy(). `request` is copied.
    void fetch(const Endpoint& endpoint, std::string_view request, const FetchOptions& options);

    // Fails the fetch in progress with Aborted (delivered asynchronously), or
    // just resets an idle kept-alive socket.
    void abort();
    // Resets an idle kept-alive socket (RST, no TIME_WAIT). Requires no fetch
    // in progress.
    void close();

    // A fetch is in progress or the socket still has operations draining.
    bool busy() const { return active_ || socket_.busy(); }
    // An idle connection is being kept alive.
    bool reusable() const { return keep_open_; }
    // TCP connects started over this object's lifetime (tests, diagnostics).
    uint64_t connects() const { return connects_; }

private:
    enum class Drain : uint8_t { None, Deliver, Reconnect };

    void on_connect(net::TcpSocket& socket, DWORD error) override;
    void on_send(net::TcpSocket& socket, DWORD error) override;
    void on_recv(net::TcpSocket& socket, size_t bytes, DWORD error) override;

    void start_connect();
    void send_request();
    void flush_wire();
    void start_recv();
    void on_reply_bytes(bool eof);
    void complete();
    void fail(FetchError error);
    void retry_fresh();
    void settle();
    void deliver();
    void cancel_timers();
    void reset_buffers();
    bool draining() const { return error_ != FetchError::None || done_ || drain_ != Drain::None; }
    // A kept-alive connection the server closed before any reply byte: retry once.
    bool stale_keepalive() const { return reused_ && !retried_ && rx_len_ == 0; }

    net::Loop& loop_;
    FetchHandler& handler_;
    CounterBlock* stats_;
    tls::Verify verify_;
    net::TcpSocket socket_;
    std::optional<tls::ClientSession> tls_;

    // Endpoint of the current socket.
    uint32_t ip_ = 0;
    uint16_t port_ = 0;
    bool is_tls_ = false;
    std::string server_name_;
    bool keep_open_ = false;  // idle and reusable

    // Fetch in progress.
    bool active_ = false;
    bool in_fetch_ = false;  // inside fetch(): completion must be deferred
    bool handshaking_ = false;
    bool sending_ = false;
    bool recving_ = false;
    bool done_ = false;      // reply complete; waiting for the socket to drain
    bool reused_ = false;
    bool retried_ = false;
    bool eof_ = false;
    Drain drain_ = Drain::None;
    FetchError error_ = FetchError::None;
    FetchOptions options_;
    std::string request_;
    net::TimerId fetch_timer_ = 0;
    net::TimerId connect_timer_ = 0;
    net::TimerId defer_timer_ = 0;
    uint64_t connects_ = 0;

    parse::ResponseParser parser_;
    std::vector<char> rx_;    // reply bytes (plaintext); [0, rx_len_) valid
    size_t rx_len_ = 0;
    std::vector<char> raw_;   // TLS: ciphertext receive buffer
    std::vector<char> tx_;    // TLS: bytes of the send in flight
    std::vector<char> wire_;  // TLS: bytes produced while a send was in flight
};

}  // namespace wc::crawl
