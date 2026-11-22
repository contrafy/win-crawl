#pragma once
// Ed25519 (RFC 8032) keys and signatures, SHA-256 and random bytes.
//
// Windows CNG has no Ed25519 signature algorithm (curve25519 is ECDH only),
// so Ed25519 comes from the vendored Monocypher 4.0.3
// (third_party/monocypher/README.md). SHA-256 and the RNG are CNG's.

#include <cstddef>
#include <cstdint>

namespace wc::sig {

constexpr size_t kEd25519SeedSize = 32;
constexpr size_t kEd25519PublicKeySize = 32;
constexpr size_t kEd25519SignatureSize = 64;
constexpr size_t kSha256Size = 32;

// An Ed25519 private key: the RFC 8032 32-byte seed (JWK "d") and the public
// key derived from it (JWK "x"). The seed is wiped when the object dies.
class Ed25519Key {
public:
    Ed25519Key() = default;
    Ed25519Key(const Ed25519Key&) = default;
    Ed25519Key& operator=(const Ed25519Key&) = default;
    ~Ed25519Key();

    // Derives the public key from `seed`.
    void set_seed(const uint8_t seed[kEd25519SeedSize]);
    // A new key from the OS CSPRNG; false if the RNG failed.
    bool generate();

    bool valid() const { return valid_; }
    const uint8_t* seed() const { return secret_; }
    const uint8_t* public_key() const { return secret_ + kEd25519SeedSize; }

    // Deterministic Ed25519 signature (pure EdDSA, no context). Requires valid().
    void sign(const void* msg, size_t len, uint8_t sig[kEd25519SignatureSize]) const;

private:
    uint8_t secret_[kEd25519SeedSize + kEd25519PublicKeySize] = {};  // Monocypher layout: seed || public key
    bool valid_ = false;
};

// RFC 8032 verification (Monocypher's crypto_ed25519_check: rejects S >= L
// and points off the curve; cofactorless equation).
bool ed25519_verify(const uint8_t public_key[kEd25519PublicKeySize], const void* msg, size_t len,
                    const uint8_t sig[kEd25519SignatureSize]);

// False only if CNG fails.
bool sha256(const void* data, size_t len, uint8_t out[kSha256Size]);

// BCryptGenRandom with the system-preferred RNG. False if it fails.
bool random_bytes(void* out, size_t len);

// Zeroes memory in a way the optimizer cannot drop.
void secure_zero(void* p, size_t len);

}  // namespace wc::sig
