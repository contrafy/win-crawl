#pragma once
// Asynchronous UDP socket on a Loop. Same completion contract as tcp.h.

#include "net/loop.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstddef>

namespace wc::net {

class UdpSocket;

class UdpHandler {
public:
    // `data` is valid only for the duration of the call.
    virtual void on_datagram(UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) = 0;

protected:
    ~UdpHandler() = default;
};

class UdpSocket {
public:
    UdpSocket(Loop& loop, UdpHandler& handler);
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    // Binds `local` (port 0 = ephemeral), disables SIO_UDP_CONNRESET (ICMP
    // port-unreachable must not fail later receives), sets SO_RCVBUF, and keeps
    // `recv_depth` WSARecvFrom calls outstanding. Returns 0 or a WinSock error.
    DWORD open(const sockaddr_in& local, size_t recv_depth = 16, int rcvbuf_bytes = 4 << 20);

    // Copies `data` into a pooled send buffer; fire-and-forget. Returns false
    // only when the send could not be started.
    bool send_to(const sockaddr_in& remote, const char* data, size_t len);

    // Outstanding operations complete aborted; no on_datagram after close().
    void close();
    bool busy() const;
    // Bound address (useful after binding port 0).
    sockaddr_in local_address() const;
};

}  // namespace wc::net
