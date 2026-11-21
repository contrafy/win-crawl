#pragma once
// Asynchronous TCP stream and listener on a Loop.
//
// Contract shared by every socket type in wc::net:
//  - Every operation that was started completes exactly once through the
//    handler, on the loop thread, including after close() (with
//    ERROR_OPERATION_ABORTED). Nothing ever completes inline inside the
//    starting call.
//  - The socket never touches itself after invoking a handler callback, so a
//    handler may destroy the socket from inside a callback once !busy().
//  - Destroying a socket that is busy() is a programming error.

#include "net/loop.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <vector>

namespace wc::net {

class TcpSocket;

class TcpHandler {
public:
    virtual void on_connect(TcpSocket& socket, DWORD error) = 0;
    // The whole buffer passed to send() was written, or the send failed.
    virtual void on_send(TcpSocket& socket, DWORD error) = 0;
    // bytes == 0 && error == 0 means the peer closed its side (FIN).
    virtual void on_recv(TcpSocket& socket, size_t bytes, DWORD error) = 0;

protected:
    ~TcpHandler() = default;
};

// At most one connect-or-send and one recv may be outstanding at a time.
class TcpSocket {
public:
    TcpSocket(Loop& loop, TcpHandler& handler);
    ~TcpSocket();
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    // Creates a fresh outbound socket (closing any previous one; requires
    // !busy()), binds 0.0.0.0:0, sets TCP_NODELAY and SO_REUSE_UNICASTPORT,
    // and associates it with the loop. Returns 0 or a WinSock error.
    DWORD open();

    // Takes ownership of an accepted socket (already SO_UPDATE_ACCEPT_CONTEXT'd
    // by TcpListener) and associates it with this socket's loop. Ownership is
    // unconditional: on failure the socket is closed here. Requires !busy().
    DWORD adopt(SOCKET accepted);

    void connect(const sockaddr_in& remote);  // ConnectEx -> on_connect
    // Completes once all `len` bytes are written; `data` must stay valid until on_send.
    void send(const char* data, size_t len);
    // One WSARecv of up to `cap` (> 0) bytes into `buf` -> on_recv.
    void recv(char* buf, size_t cap);

    // abort = true: SO_LINGER {1, 0} so the close sends RST and leaves no
    // TIME_WAIT. Pending operations complete with ERROR_OPERATION_ABORTED.
    void close(bool abort = true);

    bool is_open() const;
    bool busy() const;  // any operation outstanding
    Loop& loop() const;
    // For socket options the wrapper does not cover; INVALID_SOCKET when closed.
    SOCKET native_handle() const;

private:
    struct Op {
        IoRequest io;
        TcpSocket* owner = nullptr;
        DWORD deferred_error = 0;  // synchronous failure reported via the port
        bool pending = false;
    };
    static void on_connect_done(IoRequest* req, DWORD bytes, DWORD error);
    static void on_send_done(IoRequest* req, DWORD bytes, DWORD error);
    static void on_recv_done(IoRequest* req, DWORD bytes, DWORD error);
    static Op& op_of(IoRequest* req);
    void init_op(Op& op, void (*complete)(IoRequest*, DWORD, DWORD));
    void start(Op& op);
    void defer(Op& op, DWORD error);
    DWORD settle(Op& op, DWORD loop_error);
    bool send_chunk();

    Loop& loop_;
    TcpHandler& handler_;
    SOCKET sock_ = INVALID_SOCKET;
    bool closed_ = false;  // close() ran: in-flight operations report aborted
    Op connect_op_;
    Op send_op_;
    Op recv_op_;
    DWORD recv_flags_ = 0;
    const char* send_data_ = nullptr;
    size_t send_len_ = 0;
    size_t send_done_ = 0;
};

class TcpListener {
public:
    // `on_accept` runs on the loop thread with a connected socket that is not
    // associated with any completion port; the callee owns it (typically posts
    // it to another loop, which calls TcpSocket::adopt()).
    TcpListener(Loop& loop, std::function<void(SOCKET)> on_accept);
    ~TcpListener();
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    // Binds, listens and keeps `accept_depth` AcceptEx calls outstanding.
    // Returns 0 or a WinSock error.
    DWORD listen(const sockaddr_in& local, int backlog = SOMAXCONN, size_t accept_depth = 64);
    void close();
    bool busy() const;
    // Bound address after a successful listen() (resolves port 0).
    sockaddr_in local_address() const;

private:
    struct AcceptOp;
    static void on_accept_done(IoRequest* req, DWORD bytes, DWORD error);
    DWORD arm(AcceptOp& op);

    Loop& loop_;
    std::function<void(SOCKET)> on_accept_;
    SOCKET sock_ = INVALID_SOCKET;
    sockaddr_in local_{};
    size_t pending_ = 0;
    std::vector<std::unique_ptr<AcceptOp>> ops_;
};

}  // namespace wc::net
