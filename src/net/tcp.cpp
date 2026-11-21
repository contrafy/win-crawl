#include "net/tcp.h"

#include "net/addr.h"
#include "net/detail.h"

#include <mswsock.h>

#include <algorithm>
#include <cassert>

namespace wc::net {

namespace {

// Large sends are issued in slices: each overlapped WSASend pins its whole
// buffer in kernel memory, and slicing keeps that bounded per connection.
constexpr size_t kMaxSendChunk = size_t{1} << 20;

// AcceptEx needs room for each address plus 16 bytes of provider overhead.
constexpr DWORD kAcceptAddrLen = sizeof(sockaddr_in) + 16;

SOCKET new_tcp_socket() {
    return WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
}

DWORD last_wsa_error() {
    return static_cast<DWORD>(WSAGetLastError());
}

}  // namespace

// --- TcpSocket ----------------------------------------------------------------

TcpSocket::TcpSocket(Loop& loop, TcpHandler& handler) : loop_(loop), handler_(handler) {
    startup();
    init_op(connect_op_, &TcpSocket::on_connect_done);
    init_op(send_op_, &TcpSocket::on_send_done);
    init_op(recv_op_, &TcpSocket::on_recv_done);
}

TcpSocket::~TcpSocket() {
    assert(!busy() && "destroying a TcpSocket with operations outstanding");
    close(true);
}

void TcpSocket::init_op(Op& op, void (*complete)(IoRequest*, DWORD, DWORD)) {
    op.io.complete = complete;
    op.owner = this;
}

TcpSocket::Op& TcpSocket::op_of(IoRequest* req) {
    return *CONTAINING_RECORD(req, Op, io);
}

DWORD TcpSocket::open() {
    if (busy()) {
        return WSAEINVAL;
    }
    close(true);
    SOCKET s = new_tcp_socket();
    if (s == INVALID_SOCKET) {
        return last_wsa_error();
    }
    // An explicit bind to port 0 normally reserves a machine-wide unique
    // ephemeral port, capping concurrent outbound connections at the size of
    // the ephemeral range. SO_REUSE_UNICASTPORT lets the stack share a port
    // across different destinations (implicit-bind connect() gets this by
    // default). Older systems reject it, which only costs that scalability.
    const DWORD reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSE_UNICASTPORT, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    const sockaddr_in any = make_addr(INADDR_ANY, 0);
    const BOOL nodelay = TRUE;
    DWORD err = 0;
    if (bind(s, reinterpret_cast<const sockaddr*>(&any), sizeof(any)) != 0 ||
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) != 0) {
        err = last_wsa_error();
    } else {
        err = loop_.associate(reinterpret_cast<HANDLE>(s));
    }
    if (err != 0) {
        closesocket(s);
        return err;
    }
    sock_ = s;
    closed_ = false;
    return 0;
}

DWORD TcpSocket::adopt(SOCKET accepted) {
    if (busy()) {
        closesocket(accepted);
        return WSAEINVAL;
    }
    close(true);
    const BOOL nodelay = TRUE;
    DWORD err = 0;
    if (setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) != 0) {
        err = last_wsa_error();
    } else {
        err = loop_.associate(reinterpret_cast<HANDLE>(accepted));
    }
    if (err != 0) {
        closesocket(accepted);
        return err;
    }
    sock_ = accepted;
    closed_ = false;
    return 0;
}

void TcpSocket::start(Op& op) {
    assert(!op.pending && "operation already outstanding");
    op.io.ov = OVERLAPPED{};
    op.deferred_error = 0;
    op.pending = true;
}

void TcpSocket::defer(Op& op, DWORD error) {
    op.deferred_error = error;
    if (!detail::post_completion(loop_, &op.io)) {
        IoRequest* req = &op.io;
        loop_.post([req] { req->complete(req, 0, 0); });
    }
}

DWORD TcpSocket::settle(Op& op, DWORD loop_error) {
    DWORD err;
    if (closed_) {
        err = ERROR_OPERATION_ABORTED;
    } else if (op.deferred_error != 0) {
        err = op.deferred_error;
    } else {
        err = detail::wsa_error(sock_, &op.io.ov, loop_error);
    }
    op.deferred_error = 0;
    return err;
}

void TcpSocket::connect(const sockaddr_in& remote) {
    assert(!send_op_.pending);
    start(connect_op_);
    const auto connect_ex = detail::extensions().connect_ex;
    if (sock_ == INVALID_SOCKET) {
        defer(connect_op_, WSAENOTSOCK);
    } else if (connect_ex == nullptr) {
        defer(connect_op_, WSAEOPNOTSUPP);
    } else if (!connect_ex(sock_, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote), nullptr, 0, nullptr,
                           &connect_op_.io.ov) &&
               WSAGetLastError() != ERROR_IO_PENDING) {
        defer(connect_op_, last_wsa_error());
    }
}

void TcpSocket::on_connect_done(IoRequest* req, DWORD, DWORD error) {
    Op& op = op_of(req);
    TcpSocket& self = *op.owner;
    DWORD err = self.settle(op, error);
    // Without this the socket lacks its connected state for shutdown(),
    // getpeername() and friends.
    if (err == 0 && setsockopt(self.sock_, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0) != 0) {
        err = last_wsa_error();
    }
    op.pending = false;
    self.handler_.on_connect(self, err);
}

bool TcpSocket::send_chunk() {
    const size_t len = std::min(send_len_ - send_done_, kMaxSendChunk);
    WSABUF buf{static_cast<ULONG>(len), const_cast<char*>(send_data_ + send_done_)};
    send_op_.io.ov = OVERLAPPED{};
    if (WSASend(sock_, &buf, 1, nullptr, 0, &send_op_.io.ov, nullptr) == 0) {
        return true;  // completion is still queued to the port
    }
    return WSAGetLastError() == WSA_IO_PENDING;
}

void TcpSocket::send(const char* data, size_t len) {
    assert(!connect_op_.pending);
    start(send_op_);
    send_data_ = data;
    send_len_ = len;
    send_done_ = 0;
    if (sock_ == INVALID_SOCKET) {
        defer(send_op_, WSAENOTSOCK);
    } else if (len == 0) {
        defer(send_op_, 0);
    } else if (!send_chunk()) {
        defer(send_op_, last_wsa_error());
    }
}

void TcpSocket::on_send_done(IoRequest* req, DWORD bytes, DWORD error) {
    Op& op = op_of(req);
    TcpSocket& self = *op.owner;
    DWORD err = self.settle(op, error);
    if (err == 0 && self.send_done_ < self.send_len_) {
        if (bytes == 0) {
            err = WSAECONNABORTED;  // no progress without an error: never spin
        } else {
            self.send_done_ += bytes;
            if (self.send_done_ < self.send_len_) {
                if (self.send_chunk()) {
                    return;
                }
                err = last_wsa_error();
            }
        }
    }
    op.pending = false;
    self.handler_.on_send(self, err);
}

void TcpSocket::recv(char* buf, size_t cap) {
    assert(cap > 0 && "a zero-byte recv would be indistinguishable from FIN");
    start(recv_op_);
    if (sock_ == INVALID_SOCKET) {
        defer(recv_op_, WSAENOTSOCK);
        return;
    }
    WSABUF wsabuf{static_cast<ULONG>(std::min<size_t>(cap, ULONG_MAX)), buf};
    recv_flags_ = 0;
    if (WSARecv(sock_, &wsabuf, 1, nullptr, &recv_flags_, &recv_op_.io.ov, nullptr) != 0 &&
        WSAGetLastError() != WSA_IO_PENDING) {
        defer(recv_op_, last_wsa_error());
    }
}

void TcpSocket::on_recv_done(IoRequest* req, DWORD bytes, DWORD error) {
    Op& op = op_of(req);
    TcpSocket& self = *op.owner;
    const DWORD err = self.settle(op, error);
    op.pending = false;
    self.handler_.on_recv(self, err == 0 ? bytes : 0, err);
}

void TcpSocket::close(bool abort) {
    if (sock_ == INVALID_SOCKET) {
        return;
    }
    if (abort) {
        const LINGER linger{1, 0};
        setsockopt(sock_, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&linger), sizeof(linger));
    }
    // Cancels every outstanding overlapped operation on the socket; each still
    // completes through the port, and closed_ makes it report aborted.
    closesocket(sock_);
    sock_ = INVALID_SOCKET;
    closed_ = true;
}

bool TcpSocket::is_open() const {
    return sock_ != INVALID_SOCKET;
}

bool TcpSocket::busy() const {
    return connect_op_.pending || send_op_.pending || recv_op_.pending;
}

Loop& TcpSocket::loop() const {
    return loop_;
}

SOCKET TcpSocket::native_handle() const {
    return sock_;
}

// --- TcpListener --------------------------------------------------------------

struct TcpListener::AcceptOp {
    IoRequest io;
    TcpListener* owner = nullptr;
    SOCKET accepted = INVALID_SOCKET;
    char addrs[2 * kAcceptAddrLen];
};

TcpListener::TcpListener(Loop& loop, std::function<void(SOCKET)> on_accept)
    : loop_(loop), on_accept_(std::move(on_accept)) {
    startup();
}

TcpListener::~TcpListener() {
    assert(!busy() && "destroying a TcpListener with accepts outstanding");
    close();
}

DWORD TcpListener::listen(const sockaddr_in& local, int backlog, size_t accept_depth) {
    if (sock_ != INVALID_SOCKET || busy() || accept_depth == 0) {
        return WSAEINVAL;
    }
    if (detail::extensions().accept_ex == nullptr) {
        return WSAEOPNOTSUPP;
    }
    SOCKET s = new_tcp_socket();
    if (s == INVALID_SOCKET) {
        return last_wsa_error();
    }
    int len = sizeof(local_);
    DWORD err = 0;
    if (bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0 || ::listen(s, backlog) != 0 ||
        getsockname(s, reinterpret_cast<sockaddr*>(&local_), &len) != 0) {
        err = last_wsa_error();
    } else {
        err = loop_.associate(reinterpret_cast<HANDLE>(s));
    }
    if (err != 0) {
        closesocket(s);
        return err;
    }
    sock_ = s;

    while (ops_.size() < accept_depth) {
        auto op = std::make_unique<AcceptOp>();
        op->io.complete = &TcpListener::on_accept_done;
        op->owner = this;
        ops_.push_back(std::move(op));
    }
    for (size_t i = 0; i < accept_depth; ++i) {
        if (const DWORD arm_err = arm(*ops_[i]); arm_err != 0) {
            close();
            return arm_err;
        }
        ++pending_;
    }
    return 0;
}

DWORD TcpListener::arm(AcceptOp& op) {
    // A client that resets while queued can fail AcceptEx synchronously; that
    // only concerns that one client, so try again with a fresh socket.
    for (int attempt = 0; attempt < 16; ++attempt) {
        SOCKET s = new_tcp_socket();
        if (s == INVALID_SOCKET) {
            return last_wsa_error();
        }
        op.io.ov = OVERLAPPED{};
        op.accepted = s;
        DWORD bytes = 0;
        if (detail::extensions().accept_ex(sock_, s, op.addrs, 0, kAcceptAddrLen, kAcceptAddrLen, &bytes,
                                           &op.io.ov) ||
            WSAGetLastError() == ERROR_IO_PENDING) {
            return 0;  // completes through the port either way
        }
        const DWORD err = last_wsa_error();
        closesocket(s);
        op.accepted = INVALID_SOCKET;
        if (err != WSAECONNRESET) {
            return err;
        }
    }
    return WSAECONNRESET;
}

void TcpListener::on_accept_done(IoRequest* req, DWORD, DWORD error) {
    auto* op = CONTAINING_RECORD(req, AcceptOp, io);
    TcpListener& self = *op->owner;
    SOCKET accepted = op->accepted;
    op->accepted = INVALID_SOCKET;
    if (self.sock_ == INVALID_SOCKET) {
        closesocket(accepted);
        --self.pending_;
        return;
    }
    // Inherit the listener's properties so getpeername()/shutdown() work.
    if (error != 0 || setsockopt(accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                                 reinterpret_cast<const char*>(&self.sock_), sizeof(self.sock_)) != 0) {
        closesocket(accepted);  // typically WSAECONNRESET: the client gave up
        accepted = INVALID_SOCKET;
    }
    // Re-arm before handing the socket out so the callback is the last touch.
    if (self.arm(*op) != 0) {
        --self.pending_;
    }
    if (accepted != INVALID_SOCKET) {
        self.on_accept_(accepted);
    }
}

void TcpListener::close() {
    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
}

bool TcpListener::busy() const {
    return pending_ != 0;
}

sockaddr_in TcpListener::local_address() const {
    return local_;
}

}  // namespace wc::net
