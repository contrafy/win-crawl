#include "sig/jwk.h"

#include "sig/base64.h"

#include <cstring>

namespace wc::sig {
namespace {

constexpr int kMaxDepth = 32;

// Minimal strict JSON reader (RFC 8259) over a string_view.
class Json {
public:
    explicit Json(std::string_view s) : s_(s) {}

    void ws() {
        while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r')) {
            ++pos_;
        }
    }
    bool at_end() {
        ws();
        return pos_ == s_.size();
    }
    char peek() {
        ws();
        return pos_ < s_.size() ? s_[pos_] : '\0';
    }
    bool eat(char c) {
        if (peek() != c) return false;
        ++pos_;
        return true;
    }

    // Parses a string into `out` (UTF-8, escapes decoded).
    bool string(std::string& out) {
        out.clear();
        if (!eat('"')) return false;
        while (pos_ < s_.size()) {
            const auto c = static_cast<unsigned char>(s_[pos_++]);
            if (c == '"') return true;
            if (c < 0x20) return false;
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                continue;
            }
            if (pos_ >= s_.size()) return false;
            switch (s_[pos_++]) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                uint32_t cp = 0;
                if (!hex4(cp)) return false;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    uint32_t lo = 0;
                    if (pos_ + 2 > s_.size() || s_[pos_] != '\\' || s_[pos_ + 1] != 'u') return false;
                    pos_ += 2;
                    if (!hex4(lo) || lo < 0xDC00 || lo > 0xDFFF) return false;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    return false;
                }
                append_utf8(out, cp);
                break;
            }
            default:
                return false;
            }
        }
        return false;
    }

    // Validates and skips any value.
    bool skip(int depth = 0) {
        if (depth > kMaxDepth) return false;
        const char c = peek();
        if (c == '"') {
            std::string tmp;
            return string(tmp);
        }
        if (c == '{') {
            ++pos_;
            if (eat('}')) return true;
            std::string name;
            do {
                if (!string(name) || !eat(':') || !skip(depth + 1)) return false;
            } while (eat(','));
            return eat('}');
        }
        if (c == '[') {
            ++pos_;
            if (eat(']')) return true;
            do {
                if (!skip(depth + 1)) return false;
            } while (eat(','));
            return eat(']');
        }
        if (c == '-' || (c >= '0' && c <= '9')) return number();
        return literal("true") || literal("false") || literal("null");
    }

private:
    bool hex4(uint32_t& out) {
        if (pos_ + 4 > s_.size()) return false;
        out = 0;
        for (int i = 0; i < 4; ++i) {
            const char h = s_[pos_++];
            out <<= 4;
            if (h >= '0' && h <= '9') {
                out |= static_cast<uint32_t>(h - '0');
            } else if (h >= 'a' && h <= 'f') {
                out |= static_cast<uint32_t>(h - 'a' + 10);
            } else if (h >= 'A' && h <= 'F') {
                out |= static_cast<uint32_t>(h - 'A' + 10);
            } else {
                return false;
            }
        }
        return true;
    }

    static void append_utf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    bool digits() {
        const size_t start = pos_;
        while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
        return pos_ > start;
    }

    bool number() {
        ws();
        if (pos_ < s_.size() && s_[pos_] == '-') ++pos_;
        if (pos_ < s_.size() && s_[pos_] == '0') {
            ++pos_;
        } else if (!digits()) {
            return false;
        }
        if (pos_ < s_.size() && s_[pos_] == '.') {
            ++pos_;
            if (!digits()) return false;
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            if (!digits()) return false;
        }
        return true;
    }

    bool literal(std::string_view word) {
        ws();
        if (s_.substr(pos_, word.size()) != word) return false;
        pos_ += word.size();
        return true;
    }

    std::string_view s_;
    size_t pos_ = 0;
};

// The members of one JWK object that matter here.
struct RawJwk {
    std::string kty, crv, x, d, kid;
    bool has_kty = false, has_crv = false, has_x = false, has_d = false, has_kid = false;
};

// Reads one JWK object (cursor at '{'), keeping the members above.
JwkError read_jwk(Json& j, RawJwk& raw, int depth) {
    if (!j.eat('{')) return JwkError::NotObject;
    if (j.eat('}')) return JwkError::None;
    std::string name;
    do {
        if (!j.string(name) || !j.eat(':')) return JwkError::Json;
        struct Field {
            const char* name;
            std::string* value;
            bool* seen;
        };
        const Field fields[] = {{"kty", &raw.kty, &raw.has_kty},
                                {"crv", &raw.crv, &raw.has_crv},
                                {"x", &raw.x, &raw.has_x},
                                {"d", &raw.d, &raw.has_d},
                                {"kid", &raw.kid, &raw.has_kid}};
        const Field* match = nullptr;
        for (const Field& f : fields) {
            if (name == f.name) match = &f;
        }
        if (match == nullptr) {
            if (!j.skip(depth + 1)) return JwkError::Json;
            continue;
        }
        if (*match->seen) return JwkError::Duplicate;
        *match->seen = true;
        if (!j.string(*match->value)) return JwkError::Json;
    } while (j.eat(','));
    return j.eat('}') ? JwkError::None : JwkError::Json;
}

bool decode_32(std::string_view b64url, uint8_t* out) {
    std::string bytes;
    if (!decode_base64url(b64url, bytes) || bytes.size() != 32) {
        secure_zero(bytes.data(), bytes.size());
        return false;
    }
    std::memcpy(out, bytes.data(), 32);
    secure_zero(bytes.data(), bytes.size());
    return true;
}

bool is_ed25519(const RawJwk& raw) {
    return raw.kty == "OKP" && raw.crv == "Ed25519";
}

// Validates an OKP/Ed25519 RawJwk into `out` (and `private_key` if given).
JwkError finish(RawJwk& raw, PublicJwk& out, Ed25519Key* private_key) {
    if (!is_ed25519(raw)) return JwkError::Unsupported;
    if (!raw.has_x || !decode_32(raw.x, out.x.data())) return JwkError::BadPublicKey;
    out.kid = raw.kid;
    out.has_private = raw.has_d;
    out.thumbprint = thumbprint(out.x.data());
    if (raw.has_d) {
        uint8_t seed[kEd25519SeedSize];
        const bool ok = decode_32(raw.d, seed);
        secure_zero(raw.d.data(), raw.d.size());
        if (!ok) return JwkError::BadPrivateKey;
        Ed25519Key key;
        key.set_seed(seed);
        secure_zero(seed, sizeof seed);
        if (std::memcmp(key.public_key(), out.x.data(), kEd25519PublicKeySize) != 0) return JwkError::KeyMismatch;
        if (private_key != nullptr) *private_key = key;
    } else if (private_key != nullptr) {
        return JwkError::NoPrivateKey;
    }
    return JwkError::None;
}

void append_key_members(std::string& out, const uint8_t x[kEd25519PublicKeySize]) {
    out.append(R"({"kty":"OKP","crv":"Ed25519","kid":")");
    out.append(thumbprint(x));
    out.append(R"(","x":")");
    append_base64url(out, x, kEd25519PublicKeySize);
    out.push_back('"');
}

}  // namespace

const char* to_string(JwkError e) {
    switch (e) {
    case JwkError::None: return "ok";
    case JwkError::Json: return "malformed JSON";
    case JwkError::NotObject: return "not a JSON object";
    case JwkError::Duplicate: return "duplicate JWK member";
    case JwkError::Unsupported: return "not an OKP/Ed25519 key";
    case JwkError::BadPublicKey: return "bad or missing \"x\"";
    case JwkError::BadPrivateKey: return "bad \"d\"";
    case JwkError::KeyMismatch: return "\"d\" does not match \"x\"";
    case JwkError::NoPrivateKey: return "no private key (\"d\")";
    case JwkError::NoKeys: return "no \"keys\" array";
    }
    return "unknown";
}

JwkError parse_jwk(std::string_view json, PublicJwk& out, Ed25519Key* private_key) {
    Json j(json);
    RawJwk raw;
    if (const JwkError e = read_jwk(j, raw, 0); e != JwkError::None) return e;
    if (!j.at_end()) return JwkError::Json;
    return finish(raw, out, private_key);
}

JwkError parse_key_set(std::string_view json, std::vector<PublicJwk>& out) {
    out.clear();
    Json j(json);
    if (!j.eat('{')) return JwkError::NotObject;
    // A bare JWK: re-read the whole text as one key.
    RawJwk single;
    bool saw_keys = false;
    if (!j.eat('}')) {
        std::string name;
        do {
            if (!j.string(name) || !j.eat(':')) return JwkError::Json;
            if (name != "keys") {
                if (name == "kty") single.has_kty = true;
                if (!j.skip(1)) return JwkError::Json;
                continue;
            }
            if (saw_keys) return JwkError::Duplicate;
            saw_keys = true;
            if (!j.eat('[')) return JwkError::Json;
            if (j.eat(']')) continue;
            do {
                RawJwk raw;
                if (const JwkError e = read_jwk(j, raw, 2); e != JwkError::None) {
                    return e == JwkError::NotObject ? JwkError::Json : e;
                }
                if (!is_ed25519(raw)) continue;
                PublicJwk key;
                if (const JwkError e = finish(raw, key, nullptr); e != JwkError::None) return e;
                out.push_back(std::move(key));
            } while (j.eat(','));
            if (!j.eat(']')) return JwkError::Json;
        } while (j.eat(','));
        if (!j.eat('}')) return JwkError::Json;
    }
    if (!j.at_end()) return JwkError::Json;
    if (saw_keys) return JwkError::None;
    if (!single.has_kty) return JwkError::NoKeys;
    PublicJwk key;
    if (const JwkError e = parse_jwk(json, key); e != JwkError::None) return e;
    out.push_back(std::move(key));
    return JwkError::None;
}

bool parse_pkcs8_pem(std::string_view pem, Ed25519Key& out) {
    constexpr std::string_view kBegin = "-----BEGIN PRIVATE KEY-----";
    constexpr std::string_view kEnd = "-----END PRIVATE KEY-----";
    // RFC 8410 §7: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
    // OCTET STRING { OCTET STRING (32-byte seed) } }; no attributes, no public key.
    constexpr uint8_t kPrefix[] = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                                   0x04, 0x22, 0x04, 0x20};
    const size_t b = pem.find(kBegin);
    if (b == std::string_view::npos) return false;
    const size_t e = pem.find(kEnd, b + kBegin.size());
    if (e == std::string_view::npos) return false;
    std::string b64;
    for (const char c : pem.substr(b + kBegin.size(), e - b - kBegin.size())) {
        if (c != '\r' && c != '\n' && c != ' ' && c != '\t') b64.push_back(c);
    }
    std::string der;
    const bool ok = decode_base64(b64, der) && der.size() == sizeof kPrefix + kEd25519SeedSize &&
                    std::memcmp(der.data(), kPrefix, sizeof kPrefix) == 0;
    if (ok) out.set_seed(reinterpret_cast<const uint8_t*>(der.data()) + sizeof kPrefix);
    secure_zero(b64.data(), b64.size());
    secure_zero(der.data(), der.size());
    return ok;
}

JwkError parse_private_key(std::string_view text, Ed25519Key& out) {
    if (text.find("-----BEGIN") != std::string_view::npos) {
        return parse_pkcs8_pem(text, out) ? JwkError::None : JwkError::BadPrivateKey;
    }
    PublicJwk pub;
    return parse_jwk(text, pub, &out);
}

std::string thumbprint(const uint8_t x[kEd25519PublicKeySize]) {
    std::string canonical = R"({"crv":"Ed25519","kty":"OKP","x":")";
    append_base64url(canonical, x, kEd25519PublicKeySize);
    canonical.append("\"}");
    uint8_t digest[kSha256Size];
    if (!sha256(canonical.data(), canonical.size(), digest)) return {};
    std::string out;
    append_base64url(out, digest, sizeof digest);
    return out;
}

void append_public_jwk(std::string& out, const uint8_t x[kEd25519PublicKeySize]) {
    append_key_members(out, x);
    out.append(R"(,"use":"sig"})");
}

void append_private_jwk(std::string& out, const Ed25519Key& key) {
    append_key_members(out, key.public_key());
    out.append(R"(,"d":")");
    append_base64url(out, key.seed(), kEd25519SeedSize);
    out.append("\"}");
}

void append_jwks(std::string& out, const std::vector<std::array<uint8_t, kEd25519PublicKeySize>>& keys) {
    out.append(R"({"keys":[)");
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i != 0) out.push_back(',');
        append_public_jwk(out, keys[i].data());
    }
    out.append("]}");
}

const PublicJwk* find_key(const std::vector<PublicJwk>& keys, std::string_view keyid) {
    for (const PublicJwk& k : keys) {
        if (k.thumbprint == keyid) return &k;
    }
    for (const PublicJwk& k : keys) {
        if (!k.kid.empty() && k.kid == keyid) return &k;
    }
    return nullptr;
}

}  // namespace wc::sig
