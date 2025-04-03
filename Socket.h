#ifndef SOCKET_H
#define SOCKET_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

class Socket {
private:
    SOCKET sock;          // socket handle
    char* buf;            // current buffer
    int allocatedSize;    // bytes allocated for buf
    int curPos;           // current position in buffer
    std::string ipAddr;   // ip addr of host
    in_addr sin_addr;     // ip addr of host

public:
    Socket();
    ~Socket();

    // read data from the socket with a timeout and dynamic buffer resizing
    bool Read(const size_t& limit);

    void close();
    bool resolveDNS(const std::string& host);
    in_addr getResolvedAddress() const;
    bool connect(const std::string& host, int port);
    bool sendHTTPRequest(const std::string& host, const std::string& request, std::string method);
    bool receiveResponse(std::string& response, int& statusCode, const size_t& limit);

private:
    // helper to resize buffer if needed
    bool resizeBuffer();
};

#endif // SOCKET_H
