#include "tls/tls.h"

#include "tls/sspi_include.h"

#include <atomic>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <mutex>

namespace wc::tls {
namespace {

constexpr ULONG kIscFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_EXTENDED_ERROR |
                            ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_USE_SUPPLIED_CREDS;

// An incomplete record header (5 bytes) is the least Schannel can make progress on.
constexpr size_t kRecordHeader = 5;

struct Globals {
    CredHandle cred{};
    HCERTCHAINENGINE engine = nullptr;
    // Published with release order so post_quantum_available() may be called from
    // threads that did not call startup() themselves.
    std::atomic<bool> ok{false};
    bool pq_offered = false;
};

Globals g;
std::once_flag g_once;

struct GroupInfo {
    uint16_t id;
    const char* name;  // IANA TLS Supported Groups registry name
    bool pq;           // has a post-quantum KEM component
    bool hybrid;       // ... combined with classical ECDH
};

constexpr GroupInfo kGroups[] = {
    {0x0017, "secp256r1", false, false},
    {0x0018, "secp384r1", false, false},
    {0x0019, "secp521r1", false, false},
    {0x001a, "brainpoolP256r1", false, false},
    {0x001b, "brainpoolP384r1", false, false},
    {0x001c, "brainpoolP512r1", false, false},
    {0x001d, "x25519", false, false},
    {0x001e, "x448", false, false},
    {0x0100, "ffdhe2048", false, false},
    {0x0101, "ffdhe3072", false, false},
    {0x0102, "ffdhe4096", false, false},
    {0x0103, "ffdhe6144", false, false},
    {0x0104, "ffdhe8192", false, false},
    {0x0200, "MLKEM512", true, false},
    {0x0201, "MLKEM768", true, false},
    {0x0202, "MLKEM1024", true, false},
    {0x11eb, "SecP256r1MLKEM768", true, true},
    {0x11ec, "X25519MLKEM768", true, true},
    {0x11ed, "SecP384r1MLKEM1024", true, true},
    {0x6399, "X25519Kyber768Draft00", true, true},  // pre-standard hybrid, still seen on servers
};

const GroupInfo* find_group(uint32_t id) {
    for (const GroupInfo& gi : kGroups)
        if (gi.id == id)
            return &gi;
    return nullptr;
}

// Schannel's configuration names for the ML-KEM groups (the Enable-TlsEccCurve /
// "ECC Curve Order" strings). Listing a name in the credential's disabled crypto
// removes that group from the ClientHello even when the machine enables it; names
// Schannel does not know are ignored. "X25519_MLKEM768" was verified on 26200.9974;
// the match looked case-sensitive there, so the lowercase spellings from the Learn
// group table are listed as well.
constexpr const wchar_t* kPqGroupConfigNames[] = {
    L"X25519_MLKEM768",  L"SecP256r1_MLKEM768", L"SecP384r1_MLKEM1024", L"MLKEM512", L"MLKEM768", L"MLKEM1024",
    L"x25519_mlkem768",  L"secp256r1_mlkem768", L"secp384r1_mlkem1024", L"mlkem512", L"mlkem768", L"mlkem1024",
};
static_assert(std::size(kPqGroupConfigNames) <= SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS);

// Bounds-checked big-endian reader over a TLS structure.
struct Reader {
    const unsigned char* p;
    size_t n;

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
    // Splits off the next `len` bytes as their own reader.
    bool sub(size_t len, Reader& out) {
        if (len > n)
            return false;
        out = {p, len};
        return skip(len);
    }
};

// True if the supported_groups extension of a ClientHello (one handshake record, as
// Schannel's first token is) lists a post-quantum group.
bool client_hello_offers_pq(const unsigned char* data, size_t len) {
    Reader r{data, len}, rec{}, hs{}, exts{};
    uint32_t v = 0, l = 0;
    if (!r.uint(1, v) || v != 22 || !r.skip(2) || !r.uint(2, l) || !r.sub(l, rec))
        return false;
    if (!rec.uint(1, v) || v != 1 || !rec.uint(3, l) || !rec.sub(l, hs))
        return false;
    // legacy_version, random, session_id, cipher_suites, compression_methods, extensions
    if (!hs.skip(2 + 32) || !hs.uint(1, l) || !hs.skip(l) || !hs.uint(2, l) || !hs.skip(l) || !hs.uint(1, l) ||
        !hs.skip(l) || !hs.uint(2, l) || !hs.sub(l, exts))
        return false;
    while (exts.n > 0) {
        uint32_t type = 0;
        Reader ext{}, list{};
        if (!exts.uint(2, type) || !exts.uint(2, l) || !exts.sub(l, ext))
            return false;
        if (type != 10)  // supported_groups
            continue;
        if (!ext.uint(2, l) || !ext.sub(l, list))
            return false;
        while (list.uint(2, v)) {
            const GroupInfo* gi = find_group(v);
            if (gi != nullptr && gi->pq)
                return true;
        }
        return false;
    }
    return false;
}

// Builds a ClientHello locally (nothing is sent) to see which groups this credential
// really offers: the machine configuration plus our disabled list decide it, and
// neither is queryable directly.
bool credential_offers_pq() {
    SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
    CtxtHandle ctx{};
    ULONG attrs = 0;
    char target[] = "pq-probe.invalid";
    const SECURITY_STATUS st = InitializeSecurityContextA(&g.cred, nullptr, target, kIscFlags, 0, 0, nullptr, 0, &ctx,
                                                          &out_desc, &attrs, nullptr);
    bool pq = false;
    if (st == SEC_I_CONTINUE_NEEDED && out_buf.pvBuffer != nullptr)
        pq = client_hello_offers_pq(static_cast<const unsigned char*>(out_buf.pvBuffer), out_buf.cbBuffer);
    if (out_buf.pvBuffer != nullptr)
        FreeContextBuffer(out_buf.pvBuffer);
    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK)
        DeleteSecurityContext(&ctx);
    return pq;
}

void init_globals(const StartupOptions& options) {
    // Only TLS 1.2/1.3 are enabled; Schannel picks the highest both sides support.
    TLS_PARAMETERS params{};
    params.grbitDisabledProtocols = ~static_cast<DWORD>(SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT);

    CRYPTO_SETTINGS no_pq[std::size(kPqGroupConfigNames)]{};
    if (!options.post_quantum) {
        for (size_t i = 0; i < std::size(kPqGroupConfigNames); ++i) {
            const wchar_t* name = kPqGroupConfigNames[i];
            const auto bytes = static_cast<USHORT>(wcslen(name) * sizeof(wchar_t));
            no_pq[i].eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange;
            no_pq[i].strCngAlgId = {bytes, bytes, const_cast<PWSTR>(name)};
        }
        params.cDisabledCrypto = static_cast<DWORD>(std::size(no_pq));
        params.pDisabledCrypto = no_pq;
    }

    SCH_CREDENTIALS creds{};
    creds.dwVersion = SCH_CREDENTIALS_VERSION;
    // Certificates are validated by verify_peer() with an offline chain engine, never
    // by Schannel itself (which could fetch CRLs/AIA on the IOCP thread).
    creds.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    creds.cTlsParameters = 1;
    creds.pTlsParameters = &params;

    TimeStamp expiry{};
    SECURITY_STATUS st = AcquireCredentialsHandleA(nullptr, const_cast<char*>(UNISP_NAME_A), SECPKG_CRED_OUTBOUND,
                                                   nullptr, &creds, nullptr, nullptr, &g.cred, &expiry);
    if (st != SEC_E_OK)
        return;

    // A private engine so the flags apply to every lookup it performs: cache-only URL
    // retrieval keeps AIA/CRL fetches off the network, and disabling the AuthRoot
    // auto-update stops Windows from downloading roots it has not cached yet.
    CERT_CHAIN_ENGINE_CONFIG cfg{};
    cfg.cbSize = sizeof(cfg);
    cfg.dwFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE;
    if (!CertCreateCertificateChainEngine(&cfg, &g.engine)) {
        FreeCredentialsHandle(&g.cred);
        return;
    }
    g.pq_offered = credential_offers_pq();
    g.ok.store(true, std::memory_order_release);
}

// Moves an SSPI-allocated output token into `out` and frees it.
void drain_token(SecBuffer& b, std::vector<char>& out) {
    if (b.pvBuffer == nullptr)
        return;
    if (b.cbBuffer > 0) {
        const char* p = static_cast<const char*>(b.pvBuffer);
        out.insert(out.end(), p, p + b.cbBuffer);
    }
    FreeContextBuffer(b.pvBuffer);
    b.pvBuffer = nullptr;
}

const SecBuffer* find_buffer(const SecBuffer* bufs, size_t n, ULONG type) {
    for (size_t i = 0; i < n; ++i)
        if (bufs[i].BufferType == type)
            return &bufs[i];
    return nullptr;
}

}  // namespace

struct ClientSession::Impl {
    CtxtHandle ctx{};
    bool has_ctx = false;
    bool verified = false;       // the chain is checked once, not again after post-handshake messages
    bool close_sent = false;
};

bool startup(const StartupOptions& options) {
    std::call_once(g_once, init_globals, options);
    return g.ok;
}

bool post_quantum_available() {
    return g.ok.load(std::memory_order_acquire) && g.pq_offered;
}

const char* group_name(uint16_t group) {
    const GroupInfo* gi = find_group(group);
    return gi != nullptr ? gi->name : "";
}

bool is_pq_hybrid_group(uint16_t group) {
    const GroupInfo* gi = find_group(group);
    return gi != nullptr && gi->hybrid;
}

const char* protocol_name(uint32_t sp_prot) {
    if (sp_prot & SP_PROT_TLS1_3)
        return "TLS 1.3";
    if (sp_prot & SP_PROT_TLS1_2)
        return "TLS 1.2";
    if (sp_prot & SP_PROT_TLS1_1)
        return "TLS 1.1";
    if (sp_prot & SP_PROT_TLS1_0)
        return "TLS 1.0";
    return "unknown";
}

ClientSession::ClientSession(std::string_view server_name, Verify verify)
    : impl_(std::make_unique<Impl>()), server_name_(server_name), verify_(verify) {}

ClientSession::~ClientSession() {
    if (impl_->has_ctx)
        DeleteSecurityContext(&impl_->ctx);
}

ClientSession::State ClientSession::fail(Failure why, long status) {
    failure_ = why;
    status_ = status;
    state_ = State::Failed;
    return state_;
}

ClientSession::State ClientSession::start(std::vector<char>& wire_out) {
    if (state_ != State::Idle)
        return fail(Failure::Misuse, SEC_E_INVALID_HANDLE);
    if (!startup())
        return fail(Failure::Credentials, SEC_E_NO_CREDENTIALS);

    SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
    ULONG attrs = 0;
    SECURITY_STATUS st = InitializeSecurityContextA(&g.cred, nullptr, server_name_.data(), kIscFlags, 0, 0, nullptr,
                                                    0, &impl_->ctx, &out_desc, &attrs, nullptr);
    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK)
        impl_->has_ctx = true;
    drain_token(out_buf, wire_out);
    status_ = st;
    if (st != SEC_I_CONTINUE_NEEDED)
        return fail(Failure::Handshake, st);
    state_ = State::Handshaking;
    return state_;
}

ClientSession::State ClientSession::feed(const char* data, size_t len, std::vector<char>& wire_out,
                                         std::vector<char>& plain_out) {
    if (state_ != State::Handshaking && state_ != State::Established)
        return state_;
    in_.insert(in_.end(), data, data + len);

    // Handshaking can turn into Established and back (post-handshake messages), and
    // each transition may leave input for the other phase.
    for (;;) {
        const State before = state_;
        const size_t pending = pending_input();
        if (state_ == State::Handshaking)
            handshake_step(wire_out);
        else if (state_ == State::Established)
            decrypt_step(plain_out);
        if (state_ == before && pending_input() == pending)
            break;  // waiting for more input
        if (state_ != State::Handshaking && state_ != State::Established)
            break;
    }

    // Drop consumed bytes. Whatever is left is a single partial record that stays at
    // the front until it completes, so each byte is moved at most once.
    if (in_head_ == in_.size()) {
        in_.clear();
        in_head_ = 0;
    } else if (in_head_ > 0) {
        in_.erase(in_.begin(), in_.begin() + static_cast<ptrdiff_t>(in_head_));
        in_head_ = 0;
    }
    return state_;
}

ClientSession::State ClientSession::handshake_step(std::vector<char>& wire_out) {
    bool retried_creds = false;
    while (state_ == State::Handshaking) {
        const size_t avail = pending_input();
        if (avail == 0 || avail < need_)
            return state_;

        SecBuffer in_bufs[2] = {
            {static_cast<ULONG>(avail), SECBUFFER_TOKEN, in_.data() + in_head_},
            {0, SECBUFFER_EMPTY, nullptr},
        };
        SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in_bufs};
        SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
        ULONG attrs = 0;
        SECURITY_STATUS st = InitializeSecurityContextA(&g.cred, &impl_->ctx, server_name_.data(), kIscFlags, 0, 0,
                                                        &in_desc, 0, nullptr, &out_desc, &attrs, nullptr);
        // On failure the token may hold an alert for the peer; send it either way.
        drain_token(out_buf, wire_out);
        status_ = st;

        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            const SecBuffer* missing = find_buffer(in_bufs, 2, SECBUFFER_MISSING);
            need_ = avail + ((missing && missing->cbBuffer > 0) ? missing->cbBuffer : 1);
            if (need_ < kRecordHeader)
                need_ = kRecordHeader;
            return state_;
        }
        need_ = 0;
        if (st == SEC_I_INCOMPLETE_CREDENTIALS && !retried_creds) {
            // The server asked for a client certificate. As in the SSPI sample client,
            // call again with the same (unconsumed) input; Schannel then sends none.
            retried_creds = true;
            continue;
        }
        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED)
            return fail(impl_->verified ? Failure::Record : Failure::Handshake, st);

        const SecBuffer* extra = find_buffer(in_bufs, 2, SECBUFFER_EXTRA);
        const size_t left = extra ? extra->cbBuffer : 0;
        consume(avail - left);
        if (st == SEC_E_OK)
            return on_handshake_done();
        if (avail == left)
            return state_;  // nothing consumed; wait for more instead of spinning
    }
    return state_;
}

ClientSession::State ClientSession::on_handshake_done() {
    SecPkgContext_StreamSizes sizes{};
    SECURITY_STATUS st = QueryContextAttributesA(&impl_->ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (st != SEC_E_OK)
        return fail(Failure::Handshake, st);
    header_size_ = sizes.cbHeader;
    trailer_size_ = sizes.cbTrailer;
    max_message_ = sizes.cbMaximumMessage;

    SecPkgContext_ConnectionInfo info{};
    if (QueryContextAttributesA(&impl_->ctx, SECPKG_ATTR_CONNECTION_INFO, &info) == SEC_E_OK)
        protocol_ = info.dwProtocol;

    if (verify_ == Verify::Chain && !impl_->verified) {
        const long err = verify_peer();
        if (err != 0)
            return fail(Failure::Certificate, err);
    }
    impl_->verified = true;
    state_ = State::Established;
    return state_;
}

long ClientSession::verify_peer() {
    PCCERT_CONTEXT cert = nullptr;
    SECURITY_STATUS st = QueryContextAttributesA(&impl_->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert);
    if (st != SEC_E_OK || cert == nullptr)
        return st != SEC_E_OK ? st : SEC_E_CERT_UNKNOWN;

    char server_auth[] = szOID_PKIX_KP_SERVER_AUTH;
    char* usages[] = {server_auth};
    CERT_CHAIN_PARA para{};
    para.cbSize = sizeof(para);
    para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = usages;

    // The server's intermediates travel in cert->hCertStore. No revocation flags:
    // checking revocation offline only produces "unknown" results.
    PCCERT_CHAIN_CONTEXT chain = nullptr;
    long err = 0;
    if (!CertGetCertificateChain(g.engine, cert, nullptr, cert->hCertStore, &para,
                                 CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, nullptr, &chain)) {
        err = static_cast<long>(GetLastError());
    } else {
        std::wstring wide_name(server_name_.begin(), server_name_.end());  // hostnames are ASCII (IDNs arrive as punycode)
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
        ssl.cbSize = sizeof(ssl);
        ssl.dwAuthType = AUTHTYPE_SERVER;
        ssl.pwszServerName = wide_name.data();
        CERT_CHAIN_POLICY_PARA policy{};
        policy.cbSize = sizeof(policy);
        policy.pvExtraPolicyPara = &ssl;
        CERT_CHAIN_POLICY_STATUS status{};
        status.cbSize = sizeof(status);
        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy, &status))
            err = static_cast<long>(GetLastError());
        else
            err = static_cast<long>(status.dwError);
        CertFreeCertificateChain(chain);
    }
    CertFreeCertificateContext(cert);
    return err;
}

ClientSession::State ClientSession::decrypt_step(std::vector<char>& plain_out) {
    while (state_ == State::Established) {
        const size_t avail = pending_input();
        if (avail == 0 || avail < need_)
            return state_;

        SecBuffer bufs[4] = {
            {static_cast<ULONG>(avail), SECBUFFER_DATA, in_.data() + in_head_},
            {0, SECBUFFER_EMPTY, nullptr},
            {0, SECBUFFER_EMPTY, nullptr},
            {0, SECBUFFER_EMPTY, nullptr},
        };
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
        SECURITY_STATUS st = DecryptMessage(&impl_->ctx, &desc, 0, nullptr);
        status_ = st;

        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            const SecBuffer* missing = find_buffer(bufs, 4, SECBUFFER_MISSING);
            need_ = avail + ((missing && missing->cbBuffer > 0) ? missing->cbBuffer : 1);
            if (need_ < kRecordHeader)
                need_ = kRecordHeader;
            return state_;
        }
        need_ = 0;
        if (st != SEC_E_OK && st != SEC_I_RENEGOTIATE && st != SEC_I_CONTEXT_EXPIRED)
            return fail(Failure::Record, st);

        // Decryption is in place, so the plaintext points into in_ and must be copied
        // out before the extra bytes are processed. Only SEC_E_OK carries application
        // data; with the other codes the DATA buffer holds the alert/handshake body.
        const SecBuffer* data = find_buffer(bufs, 4, SECBUFFER_DATA);
        const SecBuffer* extra = find_buffer(bufs, 4, SECBUFFER_EXTRA);
        if (st == SEC_E_OK && data && data->cbBuffer > 0) {
            const char* p = static_cast<const char*>(data->pvBuffer);
            plain_out.insert(plain_out.end(), p, p + data->cbBuffer);
        }
        consume(avail - (extra ? extra->cbBuffer : 0));

        if (st == SEC_I_CONTEXT_EXPIRED) {
            state_ = State::Closed;  // peer's close_notify
            return state_;
        }
        if (st == SEC_I_RENEGOTIATE) {
            // TLS 1.3 post-handshake message (NewSessionTicket, KeyUpdate). Schannel
            // leaves the whole record in EXTRA; InitializeSecurityContext consumes it
            // (and may emit a KeyUpdate reply) before decryption resumes.
            state_ = State::Handshaking;
            return state_;
        }
    }
    return state_;
}

bool ClientSession::encrypt(const char* data, size_t len, std::vector<char>& wire_out) {
    if (state_ != State::Established) {
        // Writing after close is an ordinary race with the peer, not a bug; writing
        // before the handshake finished is.
        if (state_ == State::Idle || state_ == State::Handshaking)
            fail(Failure::Misuse, SEC_E_INVALID_HANDLE);
        return false;
    }
    while (len > 0) {
        const size_t chunk = len < max_message_ ? len : max_message_;
        const size_t base = wire_out.size();
        wire_out.resize(base + header_size_ + chunk + trailer_size_);
        char* p = wire_out.data() + base;
        std::memcpy(p + header_size_, data, chunk);

        SecBuffer bufs[4] = {
            {header_size_, SECBUFFER_STREAM_HEADER, p},
            {static_cast<ULONG>(chunk), SECBUFFER_DATA, p + header_size_},
            {trailer_size_, SECBUFFER_STREAM_TRAILER, p + header_size_ + chunk},
            {0, SECBUFFER_EMPTY, nullptr},
        };
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
        SECURITY_STATUS st = EncryptMessage(&impl_->ctx, 0, &desc, 0);
        if (st != SEC_E_OK) {
            wire_out.resize(base);
            fail(Failure::Encrypt, st);
            return false;
        }
        // The trailer may come out shorter than its maximum (block padding); the header
        // and data never move, so trimming the tail is enough.
        wire_out.resize(base + bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
        data += chunk;
        len -= chunk;
    }
    return true;
}

bool ClientSession::shutdown(std::vector<char>& wire_out) {
    if ((state_ != State::Established && state_ != State::Closed) || impl_->close_sent)
        return false;
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer ctl{sizeof(type), SECBUFFER_TOKEN, &type};
    SecBufferDesc ctl_desc{SECBUFFER_VERSION, 1, &ctl};
    SECURITY_STATUS st = ApplyControlToken(&impl_->ctx, &ctl_desc);
    if (st != SEC_E_OK) {
        status_ = st;
        return false;
    }
    SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
    ULONG attrs = 0;
    st = InitializeSecurityContextA(&g.cred, &impl_->ctx, server_name_.data(), kIscFlags, 0, 0, nullptr, 0,
                                    nullptr, &out_desc, &attrs, nullptr);
    drain_token(out_buf, wire_out);
    status_ = st;
    impl_->close_sent = true;
    state_ = State::Closed;
    return st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED;
}

ClientSession::Info ClientSession::info() const {
    Info out;
    if (!impl_->has_ctx || protocol_ == 0)
        return out;
    out.protocol = protocol_;
    SecPkgContext_CipherInfo ci{};
    ci.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    if (QueryContextAttributesA(&impl_->ctx, SECPKG_ATTR_CIPHER_INFO, &ci) == SEC_E_OK) {
        for (const WCHAR* w = ci.szCipherSuite; *w != 0; ++w)
            out.cipher.push_back(static_cast<char>(*w));
        // Not documented beyond "the key type", but on 26200 dwKeyType is the negotiated
        // supported-group code point for TLS 1.3 and TLS 1.2 ECDHE alike (29 = x25519,
        // 4588 = X25519MLKEM768; checked against the ServerHello key_share and the TLS 1.2
        // ServerKeyExchange on the wire) and 0 for RSA key transport. Neither
        // CONNECTION_INFO(_EX) nor KEY_INFO names the group.
        if (ci.dwKeyType <= 0xffff)
            out.group = static_cast<uint16_t>(ci.dwKeyType);
    }
    out.key_exchange = group_name(out.group);
    out.pq_hybrid = is_pq_hybrid_group(out.group);
    SecPkgContext_SessionInfo session{};
    if (QueryContextAttributesA(&impl_->ctx, SECPKG_ATTR_SESSION_INFO, &session) == SEC_E_OK)
        out.resumed = (session.dwFlags & SSL_SESSION_RECONNECT) != 0;
    return out;
}

}  // namespace wc::tls
