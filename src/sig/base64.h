#pragma once
// Base64 (RFC 4648 §4, padded) for Structured Field byte sequences, and
// base64url without padding (§5) for JOSE (JWK members, thumbprints).

#include <cstddef>
#include <string>
#include <string_view>

namespace wc::sig {

constexpr size_t base64_size(size_t n) { return (n + 2) / 3 * 4; }
constexpr size_t base64url_size(size_t n) { return (n * 4 + 2) / 3; }

void append_base64(std::string& out, const void* data, size_t len);
void append_base64url(std::string& out, const void* data, size_t len);

// Standard alphabet. Missing "=" padding and non-zero pad bits are tolerated,
// as RFC 9651 §4.2.7 asks of byte-sequence parsers; anything else outside the
// alphabet (including line breaks) fails. Appends to `out`.
bool decode_base64(std::string_view in, std::string& out);

// URL alphabet, unpadded, canonical only (pad bits must be zero), so every
// byte string has exactly one accepted encoding. Appends to `out`.
bool decode_base64url(std::string_view in, std::string& out);

}  // namespace wc::sig
