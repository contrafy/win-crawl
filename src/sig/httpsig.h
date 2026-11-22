#pragma once
// RFC 9421 HTTP Message Signatures: signature bases and verification, with
// the Web Bot Auth profile (draft-ietf-webbotauth-httpsig-protocol) and its
// signed key directory responses. Signing requests is RequestSigner
// (sig/signer.h); this side is for tests, tools and fake servers, so it
// favours clarity over allocation counts.

#include "sig/jwk.h"
#include "sig/sfv.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wc::sig {

struct Field {
    std::string_view name;
    std::string_view value;
};

// What a verifier knows about a message. Derived components (RFC 9421 §2.2)
// come from the first five members; a response's ";req" components come
// from `request`.
struct Message {
    std::string_view method;     // "@method"
    std::string_view scheme;     // "@scheme": "http" or "https"
    std::string_view authority;  // "@authority": the Host header, host[:port]; lowercased when used
    std::string_view target;     // origin-form request target, "/path[?query]"
    int status = 0;              // "@status", responses only
    std::vector<Field> fields;   // header fields, in order
    const Message* request = nullptr;
};

enum class SigError : uint8_t {
    None,
    NoSignature,           // no Signature-Input (or no member that qualifies)
    Malformed,             // a signature field, or a covered field read with ;key, does not parse
    MissingComponent,      // a covered component is absent from the message
    UnsupportedComponent,  // a component (parameter) not derived here: @query-param, sf, bs, tr, non-ASCII values
    DuplicateComponent,    // the same component identifier is covered twice
    BadParameters,         // created/expires/keyid/... of the wrong type, or created > expires
    Profile,               // violates the profile: wrong tag, missing required component or parameter
    UnsupportedAlgorithm,  // alg is not "ed25519"
    UnknownKey,            // keyid matches no key
    NotYetValid,           // created is in the future
    Expired,               // expires has passed
    BadSignature,          // the Ed25519 signature does not verify
};

const char* to_string(SigError e);

// RFC 9421 §2.5: the signature base for `covered` (a parsed Signature-Input
// member) over `msg`, written to `out` (replacing its contents).
SigError build_signature_base(const Message& msg, const sfv::InnerList& covered, std::string& out);

enum class Profile : uint8_t {
    Rfc9421,     // plain RFC 9421: no required parameters; created/expires checked when present
    WebBotAuth,  // tag="web-bot-auth"; created, expires, keyid required; covers bare @authority or
                 // @target-uri; Signature-Agent (string or dictionary form) present, https, and covered
    Directory,   // tag="http-message-signatures-directory"; created, expires, keyid required;
                 // covers "@authority";req and content-digest
};

struct VerifyPolicy {
    Profile profile = Profile::WebBotAuth;
    int64_t now = 0;          // unix seconds
    int64_t clock_skew = 5;   // seconds of tolerance on created and expires
    bool require_agent = true;            // WebBotAuth: Signature-Agent must be present
    bool require_content_digest = true;   // Directory: false accepts the older ("@authority";req)-only proof
};

struct SignatureResult {
    std::string label;
    SigError error = SigError::None;
    std::string detail;  // why, when error != None
    std::string keyid, alg, nonce, tag;
    int64_t created = -1;  // -1 when absent
    int64_t expires = -1;
    std::string agent;          // WebBotAuth: the Signature-Agent URL this signature covers
    bool agent_legacy = false;  // that URL came from the sf-string form, not a dictionary member
    std::string base;           // the signature base that was checked (when one was built)
};

// Verifies every member of the message's Signature-Input against `keys`
// under `policy`; one result per label, in field order. Returns None when
// there is at least one signature and all are valid, else the first error
// (NoSignature when there are none).
SigError verify_signatures(const Message& msg, const std::vector<PublicJwk>& keys, const VerifyPolicy& policy,
                           std::vector<SignatureResult>& out);

constexpr std::string_view kDirectoryPath = "/.well-known/http-message-signatures-directory";
constexpr std::string_view kDirectoryMediaType = "application/http-message-signatures-directory+json";

struct DirectoryResult {
    std::string problem;                     // first failure, empty when valid
    std::vector<PublicJwk> keys;             // the Ed25519 keys published
    std::vector<SignatureResult> signatures;  // every directory signature, checked against those keys
    std::vector<bool> proven;                // per key: covered by a valid signature
};

// Validates a key directory response the way a verifier fetching
// https://<request.authority>/.well-known/http-message-signatures-directory
// would: 200, the directory media type, a JWK Set body with at least one
// Ed25519 key, no private members, every "kid" equal to its key's thumbprint,
// a Content-Digest (sha-256) matching the body, and one valid
// http-message-signatures-directory signature per key. Returns true when all
// hold. `response.request` must describe the fetch (its authority).
bool verify_directory(const Message& response, std::string_view body, const VerifyPolicy& policy,
                      DirectoryResult& out);

// "sha-256=:<base64>:" for `body`.
std::string content_digest(std::string_view body);

// Splits HTTP/1.1 message text into `msg` and `body` (views into `text`).
// The start line is optional: "HTTP/1.1 200 ..." makes a response, "GET
// /path HTTP/1.1" a request (absolute-form targets set scheme and
// authority), and text that starts with a header line is a bare header
// block. Lines end in LF or CRLF; a blank line ends the headers. Host
// sets the authority if it is not set yet. Folded lines are rejected.
bool parse_http_message(std::string_view text, Message& msg, std::string_view& body);

}  // namespace wc::sig
