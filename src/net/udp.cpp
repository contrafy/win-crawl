#include "net/udp.h"

#include "net/detail.h"

#include <mswsock.h>

#include <cassert>
#include <cstring>

namespace wc::net {

struct UdpSocket::RecvOp {
    IoRequest io;
    UdpSocket* owner = nullptr;
    sockaddr_in from{};
    INT from_len = 0;
    DWORD flags = 0;
    char buf[kRecvBufferSize];
};

struct UdpSocket::SendOp {
    IoRequest io;
    UdpSocket* owner = nullptr;
    sockaddr_in to{};
    std::vector<char> buf;  // capacity is reused across sends
};

UdpSocket::UdpSocket(Loop& loop, UdpHandler& handler) : loop_(loop), handler_(handler) {
    startup();
}

UdpSocket::~UdpSocket() {
    assert(!busy() && "destroying a UdpSocket with operations outstanding");
    close();
}

DWORD UdpSocket::open(const sockaddr_in& local, size_t recv_depth, int rcvbuf_bytes) {
    if (sock_ != INVALID_SOCKET || busy() || recv_depth == 0) {
        return WSAEINVAL;
    }
    SOCKET s = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) {
        return static_cast<DWORD>(WSAGetLastError());
    }
    auto fail = [s] {
        const auto err = static_cast<DWORD>(WSAGetLastError());
        closesocket(s);
        return err;
    };
    BOOL report_reset = FALSE;
    DWORD bytes = 0;
    if (WSAIoctl(s, SIO_UDP_CONNRESET, &report_reset, sizeof(report_reset), nullptr, 0, &bytes, nullptr, nullptr) != 0) {
        return fail();
    }
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf_bytes), sizeof(rcvbuf_bytes)) != 0) {
        return fail();
    }
    if (bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
        return fail();
    }
    int len = sizeof(local_);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&local_), &len) != 0) {
        return fail();
    }
    if (const DWORD err = loop_.associate(reinterpret_cast<HANDLE>(s)); err != 0) {
        closesocket(s);
        return err;
    }
    sock_ = s;

    if (recv_ops_.size() < recv_depth) {
        recv_ops_.reserve(recv_depth);
        while (recv_ops_.size() < recv_depth) {
            auto op = std::make_unique<RecvOp>();
            op->io.complete = &UdpSocket::on_recv_done;
            op->owner = this;
            recv_ops_.push_back(std::move(op));
        }
    }
    for (size_t i = 0; i < recv_depth; ++i) {
        if (!post_recv(*recv_ops_[i])) {
            const auto err = static_cast<DWORD>(WSAGetLastError());
            close();
            return err;
        }
        ++recvs_pending_;
    }
    return 0;
}

bool UdpSocket::post_recv(RecvOp& op) {
    op.io.ov = OVERLAPPED{};
    op.from_len = sizeof(op.from);
    op.flags = 0;
    WSABUF wsabuf{static_cast<ULONG>(sizeof(op.buf)), op.buf};
    if (WSARecvFrom(sock_, &wsabuf, 1, nullptr, &op.flags, reinterpret_cast<sockaddr*>(&op.from), &op.from_len,
                    &op.io.ov, nullptr) == 0) {
        return true;  // completion is still queued to the port
    }
    return WSAGetLastError() == WSA_IO_PENDING;
}

void UdpSocket::on_recv_done(IoRequest* req, DWORD bytes, DWORD error) {
    auto* op = CONTAINING_RECORD(req, RecvOp, io);
    UdpSocket& self = *op->owner;
    // A truncated datagram (> kRecvBufferSize) arrives as an error and is dropped.
    if (self.sock_ != INVALID_SOCKET && error == 0) {
        self.handler_.on_datagram(self, op->buf, bytes, op->from);
    }
    // busy() stayed true through the callback, so `self` is still alive; the
    // handler may have closed it, in which case the request retires here.
    if (self.sock_ == INVALID_SOCKET || !self.post_recv(*op)) {
        --self.recvs_pending_;
    }
}

bool UdpSocket::send_to(const sockaddr_in& remote, const char* data, size_t len) {
    if (sock_ == INVALID_SOCKET || len > 65507) {
        return false;
    }
    SendOp* op;
    if (!free_sends_.empty()) {
        op = free_sends_.back();
        free_sends_.pop_back();
    } else {
        auto fresh = std::make_unique<SendOp>();
        fresh->io.complete = &UdpSocket::on_send_done;
        fresh->owner = this;
        op = fresh.get();
        send_ops_.push_back(std::move(fresh));
    }
    op->io.ov = OVERLAPPED{};
    op->to = remote;
    op->buf.assign(data, data + len);
    WSABUF wsabuf{static_cast<ULONG>(len), op->buf.data()};
    if (WSASendTo(sock_, &wsabuf, 1, nullptr, 0, reinterpret_cast<const sockaddr*>(&op->to), sizeof(op->to),
                  &op->io.ov, nullptr) != 0 &&
        WSAGetLastError() != WSA_IO_PENDING) {
        free_sends_.push_back(op);
        return false;
    }
    ++sends_pending_;
    return true;
}

void UdpSocket::on_send_done(IoRequest* req, DWORD, DWORD) {
    auto* op = CONTAINING_RECORD(req, SendOp, io);
    UdpSocket& self = *op->owner;
    self.free_sends_.push_back(op);
    --self.sends_pending_;
}

void UdpSocket::close() {
    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
}

bool UdpSocket::busy() const {
    return recvs_pending_ != 0 || sends_pending_ != 0;
}

sockaddr_in UdpSocket::local_address() const {
    return local_;
}

}  // namespace wc::net
