#pragma once
// Test-only Schannel server (AcceptSecurityContext) with a self-signed ECDSA
// certificate created at runtime, used to run real handshakes in memory.

#include <cstdint>
#include <memory>
#include <vector>

namespace wc::tls::test {

enum class ServerProto : uint8_t { Tls12, Tls13 };

// Process-wide self-signed "CN=localhost" certificate whose CNG key container is
// deleted when the process exits. Returns false if it could not be created.
bool server_identity_ready();

class Server {
public:
    explicit Server(ServerProto proto);
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    bool ok() const { return !failed_; }
    bool established() const { return established_; }
    bool closed() const { return closed_; }
    long last_status() const { return status_; }

    // Consumes client bytes; appends handshake output to wire_out, plaintext to plain_out.
    bool feed(const char* data, size_t len, std::vector<char>& wire_out, std::vector<char>& plain_out);
    bool encrypt(const char* data, size_t len, std::vector<char>& wire_out);
    bool shutdown(std::vector<char>& wire_out);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::vector<char> in_;
    long status_ = 0;
    bool established_ = false;
    bool closed_ = false;
    bool failed_ = false;
};

}  // namespace wc::tls::test
