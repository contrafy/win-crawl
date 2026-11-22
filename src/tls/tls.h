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

struct StartupOptions {
    // Offer the post-quantum groups (X25519MLKEM768, ...) when this machine's Schannel
    // configuration enables them. Schannel has no per-process way to *add* a group (it
    // is a machine-wide setting, see docs/tls-notes.md), so `true` offers exactly the
    // machine's list and `false` removes the ML-KEM groups from this process's
    // ClientHello via the credential's disabled-crypto list.
    bool post_quantum = true;
};

// Acquires the shared client credential handle (TLS 1.2 + 1.3, manual certificate
// validation, no client certificates) and the offline chain engine. Thread-safe; the
// first call's options win and later calls only report the result. ClientSession::start()
// calls it implicitly with default options.
bool startup(const StartupOptions& options = {});

// True once startup() succeeded and the ClientHello this process sends offers at least
// one post-quantum group (hybrid or pure ML-KEM). Determined at startup by generating a
// ClientHello locally, so it reflects what Schannel actually sends. False before startup().
bool post_quantum_available();

// SP_PROT_* value -> "TLS 1.3" / "TLS 1.2" / "unknown".
const char* protocol_name(uint32_t sp_prot);

// IANA TLS supported-group code point -> IANA name ("x25519", "secp256r1",
// "X25519MLKEM768", ...); "" for code points this table does not know.
const char* group_name(uint16_t group);

// True for hybrid groups that combine a post-quantum KEM with classical ECDH.
bool is_pq_hybrid_group(uint16_t group);

class ClientSession {
public:
    enum class State : uint8_t { Idle, Handshaking, Established, Closed, Failed };

    // What the handshake negotiated.
    struct Info {
        uint32_t protocol = 0;     // SP_PROT_* bit, see protocol_name()
        std::string cipher;        // cipher suite, e.g. "TLS_AES_256_GCM_SHA384"
        // Key-exchange group as its IANA name ("X25519MLKEM768", "x25519", "secp256r1");
        // empty when there is none (TLS 1.2 RSA key transport) or group_name() does not
        // know the code point. A resumed TLS 1.2 session reports the group of the
        // handshake that created it; resumed TLS 1.3 runs a fresh (EC)DHE exchange.
        std::string key_exchange;
        uint16_t group = 0;        // IANA supported-group code point; 0 when there is none
        bool pq_hybrid = false;    // group is a post-quantum hybrid (is_pq_hybrid_group)
        bool resumed = false;      // abbreviated handshake resuming an earlier session
    };

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
    // size) appended to `wire_out`. Returns false unless Established; calling it before
    // the handshake completes is Failure::Misuse, after Closed/Failed it changes nothing.
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
    // Negotiated parameters once Schannel completed the handshake: while Established,
    // after Closed, and after Failure::Certificate (our chain check rejected the peer
    // after negotiation). Default-constructed otherwise. Queries Schannel on each call.
    Info info() const;
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
