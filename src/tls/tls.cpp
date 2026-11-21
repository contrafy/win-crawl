#include "tls/tls.h"

#include "tls/sspi_include.h"

#include <cstring>
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
    bool ok = false;
};

Globals g;
std::once_flag g_once;

void init_globals() {
    // Only TLS 1.2/1.3 are enabled; Schannel picks the highest both sides support.
    TLS_PARAMETERS params{};
    params.grbitDisabledProtocols = ~static_cast<DWORD>(SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT);

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
    g.ok = true;
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

bool startup() {
    std::call_once(g_once, init_globals);
    return g.ok;
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
        if (state_ != State::Failed)
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

std::string ClientSession::cipher_suite() const {
    if (!impl_->has_ctx || protocol_ == 0)
        return {};
    SecPkgContext_CipherInfo info{};
    info.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    if (QueryContextAttributesA(&impl_->ctx, SECPKG_ATTR_CIPHER_INFO, &info) != SEC_E_OK)
        return {};
    std::string out;
    for (const WCHAR* w = info.szCipherSuite; *w != 0; ++w)
        out.push_back(static_cast<char>(*w));
    return out;
}

}  // namespace wc::tls
