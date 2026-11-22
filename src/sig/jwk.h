#pragma once
// Ed25519 JSON Web Keys (RFC 7517, OKP keys per RFC 8037), JWK Sets, and
// RFC 7638 thumbprints, which Web Bot Auth uses as the signature keyid.
//
// The JSON reader is a strict RFC 8259 parser for the shapes used here (one
// JWK object, or {"keys":[...]}); members it does not need are validated and
// skipped. Nesting is capped at 32 levels.

#include "sig/crypto.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wc::sig {

enum class JwkError : uint8_t {
    None,
    Json,           // not well-formed JSON, or a member of the wrong JSON type
    NotObject,      // top level is not an object
    Duplicate,      // a key member ("kty", "crv", "x", "d", "kid", "keys") appears twice
    Unsupported,    // kty is not "OKP" or crv is not "Ed25519"
    BadPublicKey,   // "x" missing or not 32 bytes of canonical base64url
    BadPrivateKey,  // "d" not 32 bytes of canonical base64url
    KeyMismatch,    // "d" does not derive "x"
    NoPrivateKey,   // a private key was required but "d" is absent
    NoKeys,         // a JWK Set without a "keys" array
};

const char* to_string(JwkError e);

struct PublicJwk {
    std::array<uint8_t, kEd25519PublicKeySize> x{};
    std::string kid;         // as published; empty if absent
    std::string thumbprint;  // RFC 7638 base64url SHA-256, computed
    bool has_private = false;  // the JWK carried "d" (a directory must not)
};

// One Ed25519 JWK object. When `private_key` is non-null, "d" is required and
// loaded into it; otherwise "d", if present, is only checked against "x".
JwkError parse_jwk(std::string_view json, PublicJwk& out, Ed25519Key* private_key = nullptr);

// A JWK Set ({"keys":[...]}) or a single JWK object. Keys of other types
// (RSA, EC, other curves) are skipped, as a directory may publish them; a
// malformed Ed25519 member fails the whole set.
JwkError parse_key_set(std::string_view json, std::vector<PublicJwk>& out);

// An unencrypted PKCS#8 Ed25519 private key in PEM ("-----BEGIN PRIVATE
// KEY-----"), as `openssl genpkey -algorithm ed25519` writes it.
bool parse_pkcs8_pem(std::string_view pem, Ed25519Key& out);

// A private key file's text: a private JWK, or PKCS#8 PEM as above.
JwkError parse_private_key(std::string_view text, Ed25519Key& out);

// Base64url SHA-256 of {"crv":"Ed25519","kty":"OKP","x":"..."} (RFC 7638
// §3.2 with RFC 8037 Appendix A.3). Empty only if CNG hashing fails.
std::string thumbprint(const uint8_t x[kEd25519PublicKeySize]);

// {"kty":"OKP","crv":"Ed25519","kid":<thumbprint>,"x":...,"use":"sig"}
void append_public_jwk(std::string& out, const uint8_t x[kEd25519PublicKeySize]);
// {"kty":"OKP","crv":"Ed25519","kid":<thumbprint>,"x":...,"d":...}
void append_private_jwk(std::string& out, const Ed25519Key& key);
// {"keys":[<public JWK>,...]}: the directory body.
void append_jwks(std::string& out, const std::vector<std::array<uint8_t, kEd25519PublicKeySize>>& keys);

// Looks a Signature-Input keyid up: thumbprint first, then "kid".
const PublicJwk* find_key(const std::vector<PublicJwk>& keys, std::string_view keyid);

}  // namespace wc::sig
