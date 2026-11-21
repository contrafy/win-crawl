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
    // by TcpListener) and associates it with this socket's loop.
    DWORD adopt(SOCKET accepted);

    void connect(const sockaddr_in& remote);  // ConnectEx -> on_connect
    // Completes once all `len` bytes are written; `data` must stay valid until on_send.
    void send(const char* data, size_t len);
    // One WSARecv of up to `cap` bytes into `buf` -> on_recv.
    void recv(char* buf, size_t cap);

    // abort = true: SO_LINGER {1, 0} so the close sends RST and leaves no
    // TIME_WAIT. Pending operations complete with ERROR_OPERATION_ABORTED.
    void close(bool abort = true);

    bool is_open() const;
    bool busy() const;  // any operation outstanding
    Loop& loop() const;
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
};

}  // namespace wc::net
