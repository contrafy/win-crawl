#include <cctype>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include "Socket.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <chrono>

#define INITIAL_BUF_SIZE 1024
#define THRESHOLD 128

Socket::Socket() : sock(INVALID_SOCKET), buf(nullptr), allocatedSize(0), curPos(0) {
	buf = new char[INITIAL_BUF_SIZE];
	if (!buf) {
		throw std::bad_alloc();
	}
	allocatedSize = INITIAL_BUF_SIZE;
}

Socket::~Socket() {
	close();
	if (buf) {
		delete[] buf;
	}
}

bool Socket::Read(const size_t& limit)
{
	fd_set readfds;
	auto startTime = std::chrono::high_resolution_clock::now();

	while (true)
	{
		// reinitialize on each iteration for multithreading compatibility
		timeval timeout;
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);

		// wait to see if socket has any data (see MSDN)
		int ret = select(0, &readfds, nullptr, nullptr, &timeout);
		if (ret > 0)
		{
			// new data available; make sure there is room left for null terminator
			if (allocatedSize - curPos <= 1) {
				if (!resizeBuffer()) {
					// printf("failed to resize buffer\n");
					return false;
				}
			}

			// now read the next segment
			int bytes = recv(sock, buf + curPos, allocatedSize - curPos - 1, 0);
			if (bytes == SOCKET_ERROR) {
				// print WSAGetLastError()
				// std::cout << "failed with " << WSAGetLastError() << std::endl;
				return false;
			}
			if (bytes == 0) { // connection closed
				if (curPos < allocatedSize) { // ensure within bounds
					buf[curPos] = '\0'; // NULL-terminate buffer
				}
				else {
					// printf("Buffer overflow while null-terminating\n");
					return false;
				}

				return true; // normal completion
			}
			curPos += bytes; // adjust where the next recv goes

			// check for exceeding size limit
			if (curPos > limit) {
				// printf("failed with exceeding max\n");
				return false;
			}

			// check for >10 second download
			auto currentTime = std::chrono::high_resolution_clock::now();
			auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();
			if (elapsedTime > 10) {
				// printf("failed with slow download\n");
				return false;
			}

			// extra byte for null terminator
			if (allocatedSize - curPos - 1 < THRESHOLD) {
				// resize buffer; you can use realloc(), HeapReAlloc(), or
				// memcpy the buffer into a bigger array
				if (!resizeBuffer()) {
					// printf("failed to resize buffer\n");
					return false;
				}
			}
		}
		else if (ret == 0) {
			// report timeout
			// printf("failed with timeout\n");
			return false;
		}
		else {
			// print WSAGetLastError()
			// std::cout << "failed with " << WSAGetLastError() << std::endl;
			return false;;
		}
	}
}

bool Socket::resizeBuffer() {
	//doubling buffer size whenever called
	int newSize = allocatedSize * 2;
	char* newBuf = new char[newSize];

	if (!newBuf) {
		std::cerr << "Memory allocation failed" << std::endl;
		return false;
	}

	memcpy(newBuf, buf, curPos);
	delete[] buf;
	buf = newBuf;
	allocatedSize = newSize;

	return true;
}

void Socket::close() {
	if (sock != INVALID_SOCKET) {
		closesocket(sock);
		sock = INVALID_SOCKET;
	}
}

bool Socket::resolveDNS(const std::string& host) {

	addrinfo hints = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	addrinfo* result = nullptr;
	int res = getaddrinfo(host.c_str(), NULL, &hints, &result);
	if (res != 0) {
		// std::cerr << "getaddrinfo failed with error: " << res << std::endl;
		return false;
	}

	// assume first result is valid
	sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(result->ai_addr);
	sin_addr = sockaddr_ipv4->sin_addr;

	// convert IP address to string
	char ip_str[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &sin_addr, ip_str, INET_ADDRSTRLEN) == NULL) {
		std::cerr << "inet_ntop failed with error: " << WSAGetLastError() << std::endl;
		freeaddrinfo(result);
		return false;
	}
	ipAddr = ip_str;

	freeaddrinfo(result);
	return true;
}

in_addr Socket::getResolvedAddress() const {
	return sin_addr;
}

bool Socket::connect(const std::string& host, int port) {
	
	if (sock != INVALID_SOCKET) {
		closesocket(sock);
		sock = INVALID_SOCKET;
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		printf("socket() generated error %d\n", WSAGetLastError());
		return false;
	}

	// set socket timeouts to 10 seconds
	DWORD timeout = 10000; // timeout in milliseconds
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

	// set all the params to connect to server object
	sockaddr_in server = {};
	server.sin_family = AF_INET;
	server.sin_port = htons(static_cast<u_short>(port));
	server.sin_addr = sin_addr;

	// SO_SNDTIMEO does not apply to connect(); connect non-blocking and bound the wait with select()
	u_long nonBlocking = 1;
	ioctlsocket(sock, FIONBIO, &nonBlocking);
	if (::connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
		if (WSAGetLastError() != WSAEWOULDBLOCK) {
			return false;
		}
		fd_set writefds, exceptfds;
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		FD_SET(sock, &writefds);
		FD_SET(sock, &exceptfds);
		timeval connectTimeout = { 10, 0 };
		if (select(0, nullptr, &writefds, &exceptfds, &connectTimeout) <= 0 || FD_ISSET(sock, &exceptfds)) {
			return false;
		}
	}
	u_long blocking = 0;
	ioctlsocket(sock, FIONBIO, &blocking);
	return true;
}

bool Socket::sendHTTPRequest(const std::string& host, const std::string& request, const std::string method) {
	// assemble request
	std::string httpRequest = method + " " + request + " HTTP/1.0\r\n"
		"Host: " + host + "\r\n"
		"Connection: close\r\n"
		"User-agent: ahmadCrawler/1.3\r\n\r\n";

	// printf("\n%s\n", httpRequest.c_str());

	if(send(sock, httpRequest.c_str(), static_cast<int>(httpRequest.length()), 0) == SOCKET_ERROR) {
		// std::cout << "failed with " << WSAGetLastError() << std::endl;
		return false;
	}

	return true;
}

bool Socket::receiveResponse(std::string& response, int& statusCode, const size_t& limit) {
	// a previous large page may have grown the buffer; give the memory back
	if (allocatedSize > 32 * 1024) {
		delete[] buf;
		buf = new char[INITIAL_BUF_SIZE];
		allocatedSize = INITIAL_BUF_SIZE;
	}
	curPos = 0;

	if (!Read(limit)) {
		return false;
	}

	// status line must look like "HTTP/x.y NNN"
	if (curPos < 12 || strncmp(buf, "HTTP/", 5) != 0) {
		return false;
	}
	const char* code = strchr(buf, ' ');
	if (code == nullptr || code - buf > 8 || !isdigit((unsigned char)code[1]) || !isdigit((unsigned char)code[2]) || !isdigit((unsigned char)code[3])) {
		return false;
	}
	statusCode = (code[1] - '0') * 100 + (code[2] - '0') * 10 + (code[3] - '0');

	response.assign(buf, curPos);
	return true;
}