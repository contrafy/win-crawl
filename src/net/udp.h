#pragma once
// Asynchronous UDP socket on a Loop. Same completion contract as tcp.h.

#include "net/loop.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstddef>
#include <memory>
#include <vector>

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
    // Each receive owns a kRecvBufferSize buffer; larger datagrams are dropped.
    DWORD open(const sockaddr_in& local, size_t recv_depth = 16, int rcvbuf_bytes = 4 << 20);

    // Copies `data` into a pooled send buffer; fire-and-forget. Returns false
    // only when the send could not be started.
    bool send_to(const sockaddr_in& remote, const char* data, size_t len);

    // Outstanding operations complete aborted; no on_datagram after close().
    // There is no completion callback for the aborted operations: an owner that
    // wants to destroy the socket waits (timer/post) until !busy(). on_datagram
    // runs with busy() true, so the socket cannot be destroyed from inside it.
    void close();
    bool busy() const;
    // Bound address (useful after binding port 0).
    sockaddr_in local_address() const;

    // DNS replies are tiny; a resolver advertising an EDNS payload size up to
    // this value never sees a truncated datagram.
    static constexpr size_t kRecvBufferSize = 4096;

private:
    struct RecvOp;
    struct SendOp;
    static void on_recv_done(IoRequest* req, DWORD bytes, DWORD error);
    static void on_send_done(IoRequest* req, DWORD bytes, DWORD error);
    bool post_recv(RecvOp& op);

    Loop& loop_;
    UdpHandler& handler_;
    SOCKET sock_ = INVALID_SOCKET;
    sockaddr_in local_{};
    size_t recvs_pending_ = 0;
    size_t sends_pending_ = 0;
    std::vector<std::unique_ptr<RecvOp>> recv_ops_;
    std::vector<std::unique_ptr<SendOp>> send_ops_;  // owns every send request
    std::vector<SendOp*> free_sends_;
};

}  // namespace wc::net
