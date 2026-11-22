#include "sig/crypto.h"

#include <windows.h>
#include <bcrypt.h>

#include <climits>
#include <cstring>

#include "monocypher-ed25519.h"

namespace wc::sig {

Ed25519Key::~Ed25519Key() {
    secure_zero(secret_, sizeof secret_);
}

void Ed25519Key::set_seed(const uint8_t seed[kEd25519SeedSize]) {
    // Monocypher wipes the seed it is given; keep the caller's intact.
    uint8_t copy[kEd25519SeedSize];
    std::memcpy(copy, seed, sizeof copy);
    uint8_t pub[kEd25519PublicKeySize];
    wc_monocypher::crypto_ed25519_key_pair(secret_, pub, copy);
    valid_ = true;
}

bool Ed25519Key::generate() {
    uint8_t seed[kEd25519SeedSize];
    if (!random_bytes(seed, sizeof seed)) {
        return false;
    }
    set_seed(seed);
    secure_zero(seed, sizeof seed);
    return true;
}

void Ed25519Key::sign(const void* msg, size_t len, uint8_t sig[kEd25519SignatureSize]) const {
    wc_monocypher::crypto_ed25519_sign(sig, secret_, static_cast<const uint8_t*>(msg), len);
}

bool ed25519_verify(const uint8_t public_key[kEd25519PublicKeySize], const void* msg, size_t len,
                    const uint8_t sig[kEd25519SignatureSize]) {
    return wc_monocypher::crypto_ed25519_check(sig, public_key, static_cast<const uint8_t*>(msg), len) == 0;
}

bool sha256(const void* data, size_t len, uint8_t out[kSha256Size]) {
    if (len > ULONG_MAX) {
        return false;
    }
    // BCryptHash takes a non-const input pointer but does not write through it.
    return BCRYPT_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
                                     static_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(len), out,
                                     static_cast<ULONG>(kSha256Size)));
}

bool random_bytes(void* out, size_t len) {
    if (len > ULONG_MAX) {
        return false;
    }
    return BCRYPT_SUCCESS(
        BCryptGenRandom(nullptr, static_cast<PUCHAR>(out), static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

void secure_zero(void* p, size_t len) {
    SecureZeroMemory(p, len);
}

}  // namespace wc::sig
