#pragma once
// wc::net internals shared by the socket implementations. Not part of the API.

#include "net/loop.h"

#include <winsock2.h>
#include <mswsock.h>

namespace wc::net::detail {

struct Extensions {
    LPFN_CONNECTEX connect_ex = nullptr;
    LPFN_ACCEPTEX accept_ex = nullptr;
    LPFN_GETACCEPTEXSOCKADDRS get_accept_ex_sockaddrs = nullptr;
};

// Valid after startup(); members stay null if the lookup failed.
const Extensions& extensions();

// The loop reports completions as Win32 errors (RtlNtStatusToDosError). For a
// socket that is still open, recover the WinSock spelling (WSAECONNREFUSED
// rather than ERROR_CONNECTION_REFUSED) from the OVERLAPPED itself.
inline DWORD wsa_error(SOCKET s, OVERLAPPED* ov, DWORD loop_error) {
    if (loop_error == 0 || s == INVALID_SOCKET) {
        return loop_error;
    }
    DWORD bytes = 0;
    DWORD flags = 0;
    if (WSAGetOverlappedResult(s, ov, &bytes, FALSE, &flags)) {
        return loop_error;
    }
    const int err = WSAGetLastError();
    return err == 0 ? loop_error : static_cast<DWORD>(err);
}

// Queues `req` on the loop's port as if the operation had completed, so a
// synchronous failure is still reported asynchronously (nothing completes
// inline). The owner keeps the actual error next to the request.
inline bool post_completion(Loop& loop, IoRequest* req) {
    req->ov = OVERLAPPED{};
    return PostQueuedCompletionStatus(loop.port(), 0, 0, &req->ov) != FALSE;
}

}  // namespace wc::net::detail
