#include "sig/base64.h"

#include <cstdint>

namespace wc::sig {
namespace {

constexpr char kStd[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kUrl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void encode(std::string& out, const void* data, size_t len, const char* alphabet, bool pad) {
    const auto* p = static_cast<const uint8_t*>(data);
    const size_t start = out.size();
    out.resize(start + base64_size(len));
    char* w = out.data() + start;
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const uint32_t v = (uint32_t{p[i]} << 16) | (uint32_t{p[i + 1]} << 8) | p[i + 2];
        *w++ = alphabet[v >> 18];
        *w++ = alphabet[(v >> 12) & 63];
        *w++ = alphabet[(v >> 6) & 63];
        *w++ = alphabet[v & 63];
    }
    if (const size_t rest = len - i; rest != 0) {
        uint32_t v = uint32_t{p[i]} << 16;
        if (rest == 2) {
            v |= uint32_t{p[i + 1]} << 8;
        }
        *w++ = alphabet[v >> 18];
        *w++ = alphabet[(v >> 12) & 63];
        if (rest == 2) {
            *w++ = alphabet[(v >> 6) & 63];
        } else if (pad) {
            *w++ = '=';
        }
        if (pad) {
            *w++ = '=';
        }
    }
    out.resize(static_cast<size_t>(w - out.data()));
}

int value_of(char c, bool url) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == (url ? '-' : '+')) return 62;
    if (c == (url ? '_' : '/')) return 63;
    return -1;
}

// Decodes unpadded base64 text. `strict` rejects non-zero pad bits.
bool decode(std::string_view in, std::string& out, bool url, bool strict) {
    if (in.size() % 4 == 1) {
        return false;
    }
    out.reserve(out.size() + in.size() / 4 * 3 + 2);
    uint32_t acc = 0;
    int bits = 0;
    for (const char c : in) {
        const int v = value_of(c, url);
        if (v < 0) {
            return false;
        }
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    // 2 or 4 leftover bits belong to no byte; canonical encodings zero them.
    return !strict || (acc & ((1u << bits) - 1)) == 0;
}

}  // namespace

void append_base64(std::string& out, const void* data, size_t len) {
    encode(out, data, len, kStd, true);
}

void append_base64url(std::string& out, const void* data, size_t len) {
    encode(out, data, len, kUrl, false);
}

bool decode_base64(std::string_view in, std::string& out) {
    // Padding, if present, must complete the final quantum exactly.
    size_t pad = 0;
    while (pad < in.size() && pad < 2 && in[in.size() - 1 - pad] == '=') {
        ++pad;
    }
    if (pad != 0 && in.size() % 4 != 0) {
        return false;
    }
    in.remove_suffix(pad);
    if (pad == 2 && in.size() % 4 != 2) {
        return false;
    }
    if (pad == 1 && in.size() % 4 != 3) {
        return false;
    }
    return decode(in, out, false, false);
}

bool decode_base64url(std::string_view in, std::string& out) {
    return decode(in, out, true, true);
}

}  // namespace wc::sig
