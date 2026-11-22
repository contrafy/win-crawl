// wincrawl-botauth: Web Bot Auth keys, request signatures and key directories
// (docs/web-bot-auth.md).
//   keygen            new Ed25519 private key as a JWK, owner-only ACL
//   jwks              the public JWK Set (key directory body) for keys
//   sign              signature headers for one request (debugging)
//   verify            offline verification of a signed request against a JWK Set
//   verify-directory  offline check of a fetched key directory response
//   bench             signing and verification cost
// Exit codes: 0 ok, 1 failed (verification, I/O), 2 usage error.

#include "sig/base64.h"
#include "sig/crypto.h"
#include "sig/httpsig.h"
#include "sig/jwk.h"
#include "sig/signer.h"

#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <sddl.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <string_view>
#include <vector>

namespace {
std::atomic<uint64_t> g_allocations{0};
}  // namespace

// Counts heap allocations, so `bench` can show that signing does not allocate.
void* operator new(size_t n) {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    if (void* p = std::malloc(n == 0 ? 1 : n)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept {
    std::free(p);
}
void operator delete(void* p, size_t) noexcept {
    std::free(p);
}

using namespace wc::sig;

namespace {

const char kUsage[] =
    "usage:\n"
    "  wincrawl-botauth keygen --out FILE [--force]\n"
    "      New Ed25519 key, written as a private JWK readable only by the current user\n"
    "      (--out - writes it to stdout instead). Prints the keyid and the public JWK.\n"
    "  wincrawl-botauth jwks --key FILE [--key FILE ...]\n"
    "      The public JWK Set for the keys (private JWK, PKCS#8 PEM, or public JWK):\n"
    "      the body of /.well-known/http-message-signatures-directory.\n"
    "  wincrawl-botauth sign --key FILE --authority HOST[:PORT] [--agent URL] [sign options]\n"
    "      Prints the Signature-Agent, Signature-Input and Signature header lines for a\n"
    "      request to HOST (usable as curl -H @file).\n"
    "        --agent URL      Signature-Agent: your key directory (https)\n"
    "        --dict           dictionary form (sig1=\"URL\"; draft-ietf-webbotauth-httpsig-protocol-01)\n"
    "                         instead of the sf-string form Cloudflare verifies today\n"
    "        --label L        signature label (default sig1)\n"
    "        --ttl S          seconds until expires (default 60)\n"
    "        --created T      fixed created time (unix seconds) instead of now\n"
    "        --nonce TEXT     fixed nonce instead of 64 random bytes; --no-nonce omits it\n"
    "        --base           also print the signature base to stderr\n"
    "  wincrawl-botauth verify --jwks FILE [--message FILE] [verify options]\n"
    "      Verifies every signature on an HTTP request (request line + headers, or only\n"
    "      header lines) read from FILE (default stdin) against a JWK Set or JWK.\n"
    "        --authority H    @authority (default: the Host header)\n"
    "        --now T          verification time (default now); --skew S (default 5)\n"
    "        --rfc9421        plain RFC 9421 instead of the Web Bot Auth profile\n"
    "        --agent-optional accept Web Bot Auth signatures without Signature-Agent\n"
    "        --base           print each signature base\n"
    "  wincrawl-botauth verify-directory --authority HOST [--response FILE] [--now T] [--legacy] [--base]\n"
    "      Checks a key directory response (status line, headers, body: curl -si output)\n"
    "      fetched from https://HOST/.well-known/http-message-signatures-directory.\n"
    "      --legacy accepts proofs that do not cover content-digest (directory-03).\n"
    "  wincrawl-botauth bench [--key FILE] [--n N]\n"
    "      Per-request signing cost and allocations, and verification cost.\n";

int usage_error(const std::string& message) {
    std::fprintf(stderr, "wincrawl-botauth: %s\n(see wincrawl-botauth --help)\n", message.c_str());
    return 2;
}

int fail(const std::string& message) {
    std::fprintf(stderr, "wincrawl-botauth: %s\n", message.c_str());
    return 1;
}

bool read_file(const std::string& path, std::string& out) {
    out.clear();
    FILE* f = nullptr;
    if (path == "-") {
        _setmode(_fileno(stdin), _O_BINARY);
        f = stdin;
    } else {
        f = std::fopen(path.c_str(), "rb");
        if (f == nullptr) return false;
    }
    char buf[16384];
    size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
    const bool ok = std::ferror(f) == 0;
    if (f != stdin) std::fclose(f);
    return ok;
}

// Creates `path` with a protected DACL that grants the current user alone
// full access. CREATE_NEW, because overwriting keeps an existing file's ACL.
bool write_private_file(const std::string& path, std::string_view data, bool force, std::string& error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = "OpenProcessToken failed";
        return false;
    }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> user(size);
    const bool got = GetTokenInformation(token, TokenUser, user.data(), size, &size) != 0;
    CloseHandle(token);
    LPSTR sid = nullptr;
    if (!got || !ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid)) {
        error = "cannot read the current user's SID";
        return false;
    }
    const std::string sddl = std::string("D:P(A;;FA;;;") + sid + ")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        error = "cannot build the security descriptor";
        return false;
    }
    SECURITY_ATTRIBUTES sa{sizeof sa, sd, FALSE};
    if (force) DeleteFileA(path.c_str());
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(sd);
    if (h == INVALID_HANDLE_VALUE) {
        error = GetLastError() == ERROR_FILE_EXISTS ? path + " exists (use --force to replace it)"
                                                    : "cannot create " + path;
        return false;
    }
    DWORD written = 0;
    const bool ok =
        WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) && written == data.size();
    CloseHandle(h);
    if (!ok) error = "cannot write " + path;
    return ok;
}

bool load_private_key(const std::string& path, Ed25519Key& key, std::string& error) {
    std::string text;
    if (!read_file(path, text)) {
        error = "cannot read " + path;
        return false;
    }
    const JwkError e = parse_private_key(text, key);
    secure_zero(text.data(), text.size());
    if (e != JwkError::None) {
        error = path + ": " + to_string(e);
        return false;
    }
    return true;
}

int64_t unix_now() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

bool parse_int(std::string_view s, int64_t& out) {
    if (s.empty() || s.size() > 15) return false;
    int64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}

// Options after the command: flags and "--name value" pairs.
class Options {
public:
    Options(int argc, char** argv) : argc_(argc), argv_(argv) {}
    bool next(std::string_view& name) {
        if (i_ >= argc_) return false;
        name = argv_[i_++];
        return true;
    }
    bool value(std::string& out) {
        if (i_ >= argc_) return false;
        out = argv_[i_++];
        return true;
    }

private:
    int argc_;
    char** argv_;
    int i_ = 2;
};

void print_lf(std::string_view s) {
    for (const char c : s) {
        if (c != '\r') std::fputc(c, stdout);
    }
}

void print_result(const SignatureResult& r, int64_t now, bool show_base) {
    if (r.error == SigError::None) {
        std::printf("%s: valid  keyid=%s", r.label.c_str(), r.keyid.c_str());
        if (!r.agent.empty()) {
            std::printf("  agent=%s (%s)", r.agent.c_str(), r.agent_legacy ? "sf-string" : "dictionary");
        }
        if (r.expires >= 0) {
            std::printf("  expires in %lld s", static_cast<long long>(r.expires - now));
        }
        std::printf("\n");
    } else {
        std::printf("%s: INVALID  %s: %s\n", r.label.empty() ? "(fields)" : r.label.c_str(), to_string(r.error),
                    r.detail.c_str());
    }
    if (show_base && !r.base.empty()) std::printf("--- signature base ---\n%s\n----------------------\n", r.base.c_str());
}

int cmd_keygen(Options& opt) {
    std::string out;
    bool force = false;
    std::string_view name;
    while (opt.next(name)) {
        if (name == "--out") {
            if (!opt.value(out)) return usage_error("--out needs a file");
        } else if (name == "--force") {
            force = true;
        } else {
            return usage_error("keygen: unknown option " + std::string(name));
        }
    }
    if (out.empty()) return usage_error("keygen needs --out FILE (or --out - for stdout)");
    Ed25519Key key;
    if (!key.generate()) return fail("the system RNG failed");
    std::string jwk;
    append_private_jwk(jwk, key);
    jwk.push_back('\n');
    std::string error;
    const bool to_stdout = out == "-";
    const bool ok = to_stdout ? std::fwrite(jwk.data(), 1, jwk.size(), stdout) == jwk.size()
                              : write_private_file(out, jwk, force, error);
    secure_zero(jwk.data(), jwk.size());
    if (!ok) return fail(error.empty() ? "write failed" : error);
    std::string pub;
    append_public_jwk(pub, key.public_key());
    FILE* info = to_stdout ? stderr : stdout;
    if (!to_stdout) std::fprintf(info, "wrote %s (Ed25519 private JWK, owner-only ACL)\n", out.c_str());
    std::fprintf(info, "keyid  %s\npublic %s\n", thumbprint(key.public_key()).c_str(), pub.c_str());
    return 0;
}

int cmd_jwks(Options& opt) {
    std::vector<std::array<uint8_t, kEd25519PublicKeySize>> xs;
    std::string_view name;
    while (opt.next(name)) {
        if (name != "--key") return usage_error("jwks: unknown option " + std::string(name));
        std::string path;
        if (!opt.value(path)) return usage_error("--key needs a file");
        std::string text;
        if (!read_file(path, text)) return fail("cannot read " + path);
        std::array<uint8_t, kEd25519PublicKeySize> x{};
        if (text.find("-----BEGIN") != std::string::npos) {
            Ed25519Key key;
            const bool ok = parse_pkcs8_pem(text, key);
            secure_zero(text.data(), text.size());
            if (!ok) return fail(path + ": not an Ed25519 PKCS#8 private key");
            std::memcpy(x.data(), key.public_key(), x.size());
        } else {
            PublicJwk pub;
            const JwkError e = parse_jwk(text, pub);
            secure_zero(text.data(), text.size());
            if (e != JwkError::None) return fail(path + ": " + to_string(e));
            x = pub.x;
        }
        xs.push_back(x);
    }
    if (xs.empty()) return usage_error("jwks needs at least one --key FILE");
    std::string out;
    append_jwks(out, xs);
    std::printf("%s\n", out.c_str());
    return 0;
}

bool valid_authority(std::string_view a) {
    if (a.empty()) return false;
    for (const char c : a) {
        if (c <= ' ' || c >= 0x7F || c == '/' || c == '?' || c == '#' || c == '"' || c == '\\') return false;
    }
    return true;
}

int cmd_sign(Options& opt) {
    std::string key_path, authority, value, nonce;
    SignerOptions so;
    int64_t created = -1;
    bool fixed_nonce = false, show_base = false;
    std::string_view name;
    while (opt.next(name)) {
        if (name == "--dict") {
            so.agent_form = AgentForm::Dictionary;
        } else if (name == "--no-nonce") {
            fixed_nonce = true;
            nonce.clear();
        } else if (name == "--base") {
            show_base = true;
        } else if (!opt.value(value)) {
            return usage_error(std::string(name) + " needs a value (or is unknown)");
        } else if (name == "--key") {
            key_path = value;
        } else if (name == "--authority") {
            authority = value;
        } else if (name == "--agent") {
            so.signature_agent = value;
        } else if (name == "--label") {
            so.label = value;
        } else if (name == "--ttl") {
            if (!parse_int(value, so.validity_seconds)) return usage_error("--ttl needs seconds");
        } else if (name == "--created") {
            if (!parse_int(value, created)) return usage_error("--created needs unix seconds");
        } else if (name == "--nonce") {
            fixed_nonce = true;
            nonce = value;
        } else {
            return usage_error("sign: unknown option " + std::string(name));
        }
    }
    if (key_path.empty() || authority.empty()) return usage_error("sign needs --key FILE and --authority HOST");
    if (!valid_authority(authority)) return usage_error("--authority must be host[:port]");
    Ed25519Key key;
    std::string error;
    if (!load_private_key(key_path, key, error)) return fail(error);
    RequestSigner signer;
    if (!signer.init(key, so, &error)) return usage_error(error);
    std::string_view headers;
    if (created < 0 && !fixed_nonce) {
        headers = signer.sign(authority);
    } else {
        if (created < 0) created = unix_now();
        if (!fixed_nonce) {
            uint8_t raw[64];
            if (!random_bytes(raw, sizeof raw)) return fail("the system RNG failed");
            append_base64(nonce, raw, sizeof raw);
        }
        headers = signer.sign(authority, created, created + so.validity_seconds, nonce);
    }
    print_lf(headers);
    if (show_base) {
        std::fprintf(stderr, "%.*s\n", static_cast<int>(signer.last_base().size()), signer.last_base().data());
    }
    return 0;
}

struct CommonVerify {
    int64_t now = -1;
    int64_t skew = 5;
    bool show_base = false;
};

int cmd_verify(Options& opt) {
    std::string jwks_path, message_path = "-", authority, value;
    VerifyPolicy policy;
    CommonVerify c;
    std::string_view name;
    while (opt.next(name)) {
        if (name == "--rfc9421") {
            policy.profile = Profile::Rfc9421;
        } else if (name == "--agent-optional") {
            policy.require_agent = false;
        } else if (name == "--base") {
            c.show_base = true;
        } else if (!opt.value(value)) {
            return usage_error(std::string(name) + " needs a value (or is unknown)");
        } else if (name == "--jwks") {
            jwks_path = value;
        } else if (name == "--message") {
            message_path = value;
        } else if (name == "--authority") {
            authority = value;
        } else if (name == "--now") {
            if (!parse_int(value, c.now)) return usage_error("--now needs unix seconds");
        } else if (name == "--skew") {
            if (!parse_int(value, c.skew)) return usage_error("--skew needs seconds");
        } else {
            return usage_error("verify: unknown option " + std::string(name));
        }
    }
    if (jwks_path.empty()) return usage_error("verify needs --jwks FILE");
    std::string jwks_text, message_text;
    if (!read_file(jwks_path, jwks_text)) return fail("cannot read " + jwks_path);
    std::vector<PublicJwk> keys;
    if (const JwkError e = parse_key_set(jwks_text, keys); e != JwkError::None) return fail(jwks_path + ": " + to_string(e));
    if (!read_file(message_path, message_text)) return fail("cannot read " + message_path);
    Message msg;
    msg.authority = authority;
    std::string_view body;
    if (!parse_http_message(message_text, msg, body)) return fail("the message is not an HTTP header block");
    policy.now = c.now < 0 ? unix_now() : c.now;
    policy.clock_skew = c.skew;
    std::vector<SignatureResult> results;
    const SigError e = verify_signatures(msg, keys, policy, results);
    if (e == SigError::NoSignature) return fail("no Signature-Input on the message");
    for (const SignatureResult& r : results) print_result(r, policy.now, c.show_base);
    return e == SigError::None ? 0 : 1;
}

int cmd_verify_directory(Options& opt) {
    std::string response_path = "-", authority, value;
    VerifyPolicy policy;
    CommonVerify c;
    std::string_view name;
    while (opt.next(name)) {
        if (name == "--legacy") {
            policy.require_content_digest = false;
        } else if (name == "--base") {
            c.show_base = true;
        } else if (!opt.value(value)) {
            return usage_error(std::string(name) + " needs a value (or is unknown)");
        } else if (name == "--response") {
            response_path = value;
        } else if (name == "--authority") {
            authority = value;
        } else if (name == "--now") {
            if (!parse_int(value, c.now)) return usage_error("--now needs unix seconds");
        } else {
            return usage_error("verify-directory: unknown option " + std::string(name));
        }
    }
    if (!valid_authority(authority)) return usage_error("verify-directory needs --authority HOST[:PORT]");
    std::string text;
    if (!read_file(response_path, text)) return fail("cannot read " + response_path);
    Message request;
    request.method = "GET";
    request.scheme = "https";
    request.authority = authority;
    request.target = kDirectoryPath;
    Message response;
    std::string_view body;
    if (!parse_http_message(text, response, body) || response.status == 0) {
        return fail("the input is not an HTTP response (status line, headers, blank line, body)");
    }
    response.request = &request;
    policy.now = c.now < 0 ? unix_now() : c.now;
    DirectoryResult result;
    const bool ok = verify_directory(response, body, policy, result);
    for (size_t i = 0; i < result.keys.size(); ++i) {
        std::printf("key %s  %s\n", result.keys[i].thumbprint.c_str(),
                    i < result.proven.size() && result.proven[i] ? "proven" : "NOT proven");
    }
    for (const SignatureResult& r : result.signatures) print_result(r, policy.now, c.show_base);
    if (!ok) return fail("directory invalid: " + result.problem);
    std::printf("directory valid: %zu Ed25519 key(s), each with a valid http-message-signatures-directory signature\n",
                result.keys.size());
    return 0;
}

int cmd_bench(Options& opt) {
    std::string key_path, value;
    int64_t n = 20000;
    std::string_view name;
    while (opt.next(name)) {
        if (!opt.value(value)) return usage_error(std::string(name) + " needs a value");
        if (name == "--key") {
            key_path = value;
        } else if (name == "--n") {
            if (!parse_int(value, n) || n < 100) return usage_error("--n needs a count >= 100");
        } else {
            return usage_error("bench: unknown option " + std::string(name));
        }
    }
    Ed25519Key key;
    std::string error;
    if (key_path.empty() ? !key.generate() : !load_private_key(key_path, key, error)) {
        return fail(error.empty() ? "the system RNG failed" : error);
    }
    SignerOptions so;
    so.signature_agent = "https://bot.example.com";
    RequestSigner signer;
    if (!signer.init(key, so, &error)) return fail(error);
    const std::string_view authority = "www.example-site-name.com";
    using clock = std::chrono::steady_clock;
    auto per_op_us = [&](clock::time_point t0) {
        return std::chrono::duration<double, std::micro>(clock::now() - t0).count() / static_cast<double>(n);
    };

    size_t header_bytes = 0;
    for (int i = 0; i < 100; ++i) header_bytes = signer.sign(authority).size();  // warm-up
    const uint64_t allocs_before = g_allocations.load();
    auto t0 = clock::now();
    for (int64_t i = 0; i < n; ++i) signer.sign(authority);
    const double sign_us = per_op_us(t0);
    const uint64_t sign_allocs = g_allocations.load() - allocs_before;

    const std::string base(signer.last_base());
    uint8_t sig[kEd25519SignatureSize];
    t0 = clock::now();
    for (int64_t i = 0; i < n; ++i) key.sign(base.data(), base.size(), sig);
    const double ed_us = per_op_us(t0);

    uint8_t nonce[64];
    t0 = clock::now();
    for (int64_t i = 0; i < n; ++i) random_bytes(nonce, sizeof nonce);
    const double rng_us = per_op_us(t0);

    const std::string headers(signer.sign(authority));
    const std::string request = "GET / HTTP/1.1\r\nHost: " + std::string(authority) + "\r\n" + headers + "\r\n";
    std::vector<PublicJwk> keys(1);
    std::memcpy(keys[0].x.data(), key.public_key(), kEd25519PublicKeySize);
    keys[0].thumbprint = signer.keyid();
    VerifyPolicy policy;
    policy.now = unix_now();
    std::vector<SignatureResult> results;
    const int64_t verify_n = n / 4;
    t0 = clock::now();
    for (int64_t i = 0; i < verify_n; ++i) {
        Message msg;
        std::string_view body;
        parse_http_message(request, msg, body);
        if (verify_signatures(msg, keys, policy, results) != SigError::None) return fail("self-verification failed");
    }
    const double verify_us =
        std::chrono::duration<double, std::micro>(clock::now() - t0).count() / static_cast<double>(verify_n);

    std::printf("requests signed         %lld (authority %.*s, Signature-Agent sf-string)\n", static_cast<long long>(n),
                static_cast<int>(authority.size()), authority.data());
    std::printf("sign() per request      %.2f us  (%.0f requests/s on one core)\n", sign_us, 1e6 / sign_us);
    std::printf("  Ed25519 sign alone    %.2f us  over a %zu-byte signature base\n", ed_us, base.size());
    std::printf("  64-byte nonce (CNG)   %.2f us\n", rng_us);
    std::printf("heap allocations        %llu in %lld sign() calls after warm-up\n",
                static_cast<unsigned long long>(sign_allocs), static_cast<long long>(n));
    std::printf("header bytes added      %zu per request\n", header_bytes);
    std::printf("verify per request      %.2f us  (parse + base + Ed25519 verify; %lld runs)\n", verify_us,
                static_cast<long long>(verify_n));
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fputs(kUsage, stderr);
        return 2;
    }
    const std::string_view cmd = argv[1];
    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        std::fputs(kUsage, stdout);
        return 0;
    }
    Options opt(argc, argv);
    if (cmd == "keygen") return cmd_keygen(opt);
    if (cmd == "jwks") return cmd_jwks(opt);
    if (cmd == "sign") return cmd_sign(opt);
    if (cmd == "verify") return cmd_verify(opt);
    if (cmd == "verify-directory") return cmd_verify_directory(opt);
    if (cmd == "bench") return cmd_bench(opt);
    return usage_error("unknown command " + std::string(cmd));
}
