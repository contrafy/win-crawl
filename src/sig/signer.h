#pragma once
// Web Bot Auth request signing (RFC 9421 + draft-ietf-webbotauth-httpsig-
// protocol): the three header lines a signed request carries.
//
//   Signature-Agent: "https://bot.example"
//   Signature-Input: sig1=("@authority" "signature-agent");created=1735689600;
//       keyid="<JWK thumbprint>";alg="ed25519";expires=1735689660;nonce="<64 random bytes>";tag="web-bot-auth"
//   Signature: sig1=:<Ed25519 signature, base64>:
//
// Built for the crawler's hot path: one signer per event loop (not
// thread-safe), every buffer reused, so steady-state signing does not
// allocate. Each request gets its own created/expires window and nonce.

#include "sig/crypto.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace wc::sig {

// How Signature-Agent is written.
enum class AgentForm : uint8_t {
    // Signature-Agent: "https://..." covered as "signature-agent". The form
    // Cloudflare verifies today (its docs pin draft-meunier-http-message-
    // signatures-directory-03 and reject the dictionary form).
    String,
    // Signature-Agent: sig1="https://..." covered as "signature-agent";key="sig1".
    // What draft-ietf-webbotauth-httpsig-protocol-01 requires of signers.
    Dictionary,
};

struct SignerOptions {
    // https URL of the key directory (or JWK Set) verifiers fetch. Empty
    // sends no Signature-Agent and covers only @authority.
    std::string signature_agent;
    AgentForm agent_form = AgentForm::String;
    std::string label = "sig1";
    std::string agent_key;  // Dictionary member key; empty means `label`
    int64_t validity_seconds = 60;
    std::string tag = "web-bot-auth";
};

// What init() accepts as a Signature-Agent URL: "https://" plus at least one
// more character, printable ASCII only.
bool valid_signature_agent(std::string_view url);

class RequestSigner {
public:
    // False, with a reason in `error`, for a bad label, member key, tag,
    // validity or Signature-Agent URL (https only, printable ASCII).
    bool init(const Ed25519Key& key, const SignerOptions& options, std::string* error = nullptr);
    bool ready() const { return key_.valid(); }

    // The JWK thumbprint used as keyid.
    const std::string& keyid() const { return keyid_; }

    // Signature-Agent (when configured), Signature-Input and Signature lines,
    // each "Name: value\r\n", for a request to `authority` (host[:port] as in
    // the Host header; lowercased here), valid from now for
    // validity_seconds, with a fresh 64-byte nonce. The view stays valid until
    // the next sign() call. Requires ready().
    std::string_view sign(std::string_view authority);

    // Deterministic form for tests and vectors: explicit window, and `nonce`
    // as the nonce parameter's text (empty leaves the parameter out).
    std::string_view sign(std::string_view authority, int64_t created, int64_t expires, std::string_view nonce);

    // The signature base the last sign() call signed.
    std::string_view last_base() const { return base_; }

private:
    Ed25519Key key_;
    std::string keyid_;
    std::string label_;
    std::string tag_;
    int64_t validity_ = 60;
    std::string agent_header_;  // "Signature-Agent: ...\r\n", or empty
    std::string agent_line_;    // the signature base line for it, or empty
    std::string covered_;       // ("@authority" ...)
    std::string params_;        // reused: the Signature-Input member value
    std::string base_;          // reused: the signature base
    std::string headers_;       // reused: the output
    std::string nonce_;         // reused: base64 nonce
};

}  // namespace wc::sig
