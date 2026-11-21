#pragma once
// Transport-agnostic Schannel TLS client. A ClientSession never touches a socket:
// the owner feeds it whatever bytes arrived from the network and sends whatever
// it appends to `wire_out`, so it can be driven from IOCP completions on any loop.
//
// A session is single-threaded (use it from one thread at a time); startup() and
// the shared credential handle are process-wide and safe to use concurrently.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace wc::tls {

enum class Verify : uint8_t {
    None,   // accept any certificate
    Chain,  // chain to a locally trusted root + hostname match; never fetches anything over the network
};

// Why a session ended up in State::Failed.
enum class Failure : uint8_t {
    None,
    Credentials,  // startup() failed: no Schannel credential handle
    Handshake,    // peer sent something Schannel rejected during the handshake (not TLS, alert, no common params)
    Certificate,  // Verify::Chain rejected the peer certificate; last_status() is the CERT_E_* code
    Record,       // a post-handshake record failed to decrypt or a post-handshake message was rejected
    Encrypt,      // EncryptMessage failed
    Misuse,       // API called in the wrong state
};

// Acquires the shared client credential handle (TLS 1.2 + 1.3, manual certificate
// validation, no client certificates) and the offline chain engine. Idempotent and
// thread-safe; ClientSession::start() calls it implicitly.
bool startup();

// SP_PROT_* value -> "TLS 1.3" / "TLS 1.2" / "unknown".
const char* protocol_name(uint32_t sp_prot);

class ClientSession {
public:
    enum class State : uint8_t { Idle, Handshaking, Established, Closed, Failed };

    // `server_name` is sent as SNI (unless it is an IP literal) and checked against
    // the certificate when verify == Verify::Chain.
    ClientSession(std::string_view server_name, Verify verify);
    ~ClientSession();
    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    // Begins the handshake; appends the ClientHello to `wire_out`.
    State start(std::vector<char>& wire_out);

    // Feeds raw bytes from the network, split arbitrarily. Appends bytes that must be
    // sent (handshake flights, post-handshake acks) to `wire_out` and decrypted
    // application data to `plain_out`. Partial records are buffered internally.
    // Returns Closed once the peer's close_notify is processed; plaintext that
    // preceded it is still delivered by the same call.
    State feed(const char* data, size_t len, std::vector<char>& wire_out, std::vector<char>& plain_out);

    // Encrypts application data into records (split at the negotiated maximum record
    // size) appended to `wire_out`. Only valid while Established.
    bool encrypt(const char* data, size_t len, std::vector<char>& wire_out);

    // Appends a close_notify alert to `wire_out`. Valid while Established or after the
    // peer's close_notify (Closed); afterwards the session is Closed and inert.
    bool shutdown(std::vector<char>& wire_out);

    State state() const { return state_; }
    Failure failure() const { return failure_; }
    // Last SECURITY_STATUS from Schannel, or the CERT_E_* policy error for Failure::Certificate.
    long last_status() const { return status_; }

    // Negotiated protocol (SP_PROT_* bit) once Established; 0 before.
    uint32_t protocol() const { return protocol_; }
    // Cipher suite name (e.g. "TLS_AES_256_GCM_SHA384"); empty before the handshake completes.
    std::string cipher_suite() const;
    // Bytes buffered awaiting the rest of a record.
    size_t pending_input() const { return in_.size() - in_head_; }

private:
    struct Impl;

    State handshake_step(std::vector<char>& wire_out);
    State decrypt_step(std::vector<char>& plain_out);
    State on_handshake_done();
    long verify_peer();  // 0 or the CERT_E_* / SEC_E_* reason
    State fail(Failure why, long status);
    void consume(size_t n) { in_head_ += n; }

    std::unique_ptr<Impl> impl_;  // keeps SSPI types out of this header
    std::string server_name_;
    std::vector<char> in_;        // undecrypted input; live bytes are [in_head_, size)
    size_t in_head_ = 0;
    size_t need_ = 0;             // don't call Schannel until this many bytes are buffered
    long status_ = 0;
    uint32_t protocol_ = 0;
    uint32_t header_size_ = 0;
    uint32_t trailer_size_ = 0;
    uint32_t max_message_ = 0;
    Verify verify_;
    State state_ = State::Idle;
    Failure failure_ = Failure::None;
};

}  // namespace wc::tls
