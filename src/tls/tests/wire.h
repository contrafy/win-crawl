#pragma once
// Test-only decoding of the plaintext TLS handshake messages, used to check what
// ClientSession reports against what actually crossed the wire.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace wc::tls::test {

struct ClientHelloGroups {
    bool ok = false;
    std::vector<uint16_t> supported;   // supported_groups, in preference order
    std::vector<uint16_t> key_shares;  // groups the client sent a key_share for
};

struct ServerKeyExchange {
    bool ok = false;      // a ServerHello was found
    uint16_t group = 0;   // TLS 1.3 ServerHello key_share or TLS 1.2 ServerKeyExchange named curve
    bool hello_retry = false;
    bool psk = false;     // TLS 1.3 ServerHello accepted a pre_shared_key (resumption)
};

namespace detail {

struct Reader {
    const unsigned char* p = nullptr;
    size_t n = 0;

    bool skip(size_t k) {
        if (k > n)
            return false;
        p += k;
        n -= k;
        return true;
    }
    bool uint(size_t bytes, uint32_t& v) {
        if (bytes > n)
            return false;
        v = 0;
        for (size_t i = 0; i < bytes; ++i)
            v = (v << 8) | p[i];
        return skip(bytes);
    }
    bool sub(size_t len, Reader& out) {
        if (len > n)
            return false;
        out = {p, len};
        return skip(len);
    }
};

// Concatenates the bodies of the leading handshake (type 22) records, stopping at the
// first record of another type (ChangeCipherSpec, encrypted data).
inline std::vector<unsigned char> handshake_stream(const std::vector<char>& wire) {
    std::vector<unsigned char> out;
    Reader r{reinterpret_cast<const unsigned char*>(wire.data()), wire.size()};
    for (;;) {
        uint32_t type = 0, len = 0;
        Reader body;
        if (!r.uint(1, type) || !r.skip(2) || !r.uint(2, len) || !r.sub(len, body) || type != 22)
            return out;
        out.insert(out.end(), body.p, body.p + body.n);
    }
}

// Calls f(type, body) for each complete handshake message.
template <class F>
void for_each_message(const std::vector<unsigned char>& hs, F&& f) {
    Reader r{hs.data(), hs.size()};
    for (;;) {
        uint32_t type = 0, len = 0;
        Reader body;
        if (!r.uint(1, type) || !r.uint(3, len) || !r.sub(len, body))
            return;
        f(type, body);
    }
}

// Skips the ServerHello/ClientHello fixed part up to the extensions block.
inline bool hello_extensions(Reader hello, bool client, Reader& exts, bool* hrr) {
    static const unsigned char kHrrRandom[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
                                                 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
                                                 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    uint32_t l = 0;
    if (!hello.skip(2) || hello.n < 32)
        return false;
    if (hrr != nullptr) {
        *hrr = true;
        for (size_t i = 0; i < 32; ++i)
            *hrr = *hrr && hello.p[i] == kHrrRandom[i];
    }
    if (!hello.skip(32) || !hello.uint(1, l) || !hello.skip(l))
        return false;
    if (client) {
        if (!hello.uint(2, l) || !hello.skip(l) || !hello.uint(1, l) || !hello.skip(l))
            return false;
    } else if (!hello.skip(2 + 1)) {
        return false;
    }
    return hello.uint(2, l) && hello.sub(l, exts);
}

}  // namespace detail

inline ClientHelloGroups parse_client_hello(const std::vector<char>& wire) {
    ClientHelloGroups out;
    detail::for_each_message(detail::handshake_stream(wire), [&](uint32_t type, detail::Reader body) {
        detail::Reader exts;
        if (type != 1 || out.ok || !detail::hello_extensions(body, true, exts, nullptr))
            return;
        out.ok = true;
        while (exts.n > 0) {
            uint32_t et = 0, el = 0, l = 0, v = 0;
            detail::Reader ext, list;
            if (!exts.uint(2, et) || !exts.uint(2, el) || !exts.sub(el, ext))
                break;
            if (et != 10 && et != 51)  // supported_groups, key_share
                continue;
            if (!ext.uint(2, l) || !ext.sub(l, list))
                break;
            if (et == 10) {
                while (list.uint(2, v))
                    out.supported.push_back(static_cast<uint16_t>(v));
            } else {
                uint32_t kl = 0;
                while (list.uint(2, v) && list.uint(2, kl) && list.skip(kl))
                    out.key_shares.push_back(static_cast<uint16_t>(v));
            }
        }
    });
    return out;
}

// `wire` is everything the server sent before the client finished its handshake.
inline ServerKeyExchange parse_server_flight(const std::vector<char>& wire) {
    ServerKeyExchange out;
    detail::for_each_message(detail::handshake_stream(wire), [&](uint32_t type, detail::Reader body) {
        detail::Reader exts;
        if (type == 2 && !out.ok && detail::hello_extensions(body, false, exts, &out.hello_retry)) {
            out.ok = true;
            while (exts.n > 0) {
                uint32_t et = 0, el = 0, v = 0;
                detail::Reader ext;
                if (!exts.uint(2, et) || !exts.uint(2, el) || !exts.sub(el, ext))
                    break;
                if (et == 51 && ext.uint(2, v))
                    out.group = static_cast<uint16_t>(v);
                else if (et == 41)
                    out.psk = true;
            }
        } else if (type == 12) {
            uint32_t curve_type = 0, v = 0;
            if (body.uint(1, curve_type) && curve_type == 3 && body.uint(2, v))  // named_curve
                out.group = static_cast<uint16_t>(v);
        }
    });
    return out;
}

}  // namespace wc::tls::test
