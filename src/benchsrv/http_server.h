#pragma once
// Fake HTTP/1.1 origin for benchmarks and tests.
//
// One listener loop accepts and hands sockets round-robin to `threads` worker
// loops. Responses are chosen deterministically from the Behavior model keyed
// by the Host header's host number (or the IP-literal / local address), and are
// all pre-generated at start, so serving a request is parsing plus a single
// send of a shared, immutable buffer.
//
// Connection handling: HTTP/1.1 keep-alive by default, HTTP/1.0 keep-alive only
// when asked, pipelined requests served in order. After a response to a client
// that asked for close, the server half-closes (FIN) and waits for the client's
// FIN or RST before an abortive close, so neither side keeps a TIME_WAIT entry
// (graceful_close = true instead closes normally and leaves TIME_WAIT on the
// server). Peers that close or reset, idle connections and shutdown all use
// abortive close.

#include "benchsrv/behavior.h"
#include "net/loop.h"

#include <winsock2.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace wc::benchsrv {

struct HttpServerConfig {
    uint32_t threads = 4;              // worker loops
    uint32_t idle_timeout_ms = 30000;  // idle keep-alive / half-closed connections get reset
    bool graceful_close = false;
    size_t accept_depth = 256;  // outstanding AcceptEx calls
};

struct HttpCounters {
    uint64_t requests = 0;
    uint64_t robots = 0;  // requests for /robots.txt
    uint64_t status_2xx = 0;
    uint64_t status_3xx = 0;
    uint64_t status_4xx = 0;
    uint64_t status_5xx = 0;
    uint64_t bytes_sent = 0;
    uint64_t accepted = 0;
    uint64_t active = 0;  // open connections
};

// One fully formatted response; HEAD sends only the first `head_len` bytes.
struct Response {
    std::string data;
    size_t head_len = 0;
    uint16_t status = 0;
};

// Every response the server can send, built once from a Behavior.
class ResponseSet {
public:
    // `link_port` goes into absolute links inside page bodies.
    ResponseSet(const Behavior& behavior, uint16_t link_port);

    // conn: 0 = keep-alive, 1 = close.
    const Response& robots(bool missing, int conn) const { return robots_[missing ? 1 : 0][conn]; }
    const Response& page(uint32_t tmpl, bool chunked, int conn) const { return pages_[tmpl][chunked ? 1 : 0][conn]; }
    const Response& redirect(int conn) const { return redirect_[conn]; }
    const Response& not_found(int conn) const { return not_found_[conn]; }
    const Response& server_error(int conn) const { return server_error_[conn]; }
    const Response& bad_request() const { return bad_request_; }
    const Response& too_large() const { return too_large_; }
    const Response& not_implemented() const { return not_implemented_; }

    // Unencoded body of a page template (for tests and link-count checks).
    const std::string& page_body(uint32_t tmpl) const { return bodies_[tmpl]; }

private:
    std::string bodies_[kPageTemplates];
    Response robots_[2][2];
    Response pages_[kPageTemplates][2][2];
    Response redirect_[2], not_found_[2], server_error_[2];
    Response bad_request_, too_large_, not_implemented_;
};

// Request head as the server sees it; views point into the caller's buffer.
struct HttpRequest {
    bool head = false;        // HEAD (otherwise GET)
    bool close = false;       // client wants the connection closed after the response
    std::string_view target;  // origin-form path
    std::string_view host;    // Host header (or absolute-form authority)
    size_t length = 0;        // bytes of the request head, CRLFCRLF included
};

enum class RequestParse : uint8_t { NeedMore, Ok, Bad, NotImplemented };

// Parses one request head from the start of data[0, len). Request bodies are
// not supported (Bad). Exposed for tests.
RequestParse parse_request(const char* data, size_t len, HttpRequest& out);

class HttpWorker;

class HttpServer {
public:
    HttpServer(const Behavior& behavior, const HttpServerConfig& config);
    ~HttpServer();
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    // Binds and listens on `local`, starts all loop threads. Returns 0 or a WinSock error.
    DWORD start(const sockaddr_in& local);
    // Resets every connection, closes the listener and joins all threads. Idempotent.
    void stop();

    // Bound address (the real port when started with port 0).
    sockaddr_in local_address() const { return local_; }
    HttpCounters counters() const;  // any thread
    const ResponseSet& responses() const { return *responses_; }

private:
    class Acceptor;

    const Behavior behavior_;
    const HttpServerConfig config_;
    std::unique_ptr<ResponseSet> responses_;
    std::vector<std::unique_ptr<HttpWorker>> workers_;
    std::unique_ptr<Acceptor> acceptor_;
    std::thread acceptor_thread_;
    std::vector<std::thread> worker_threads_;
    sockaddr_in local_{};
};

}  // namespace wc::benchsrv
