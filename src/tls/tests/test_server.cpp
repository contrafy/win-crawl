#include "test_server.h"

#include "tls/sspi_include.h"

#include <ncrypt.h>

#include <cstring>
#include <string>

namespace wc::tls::test {
namespace {

// Schannel runs the server's private-key operations through the key isolation
// service, which opens the key by container name, so the key has to be persisted;
// the container is unique per process and deleted on exit.
struct Identity {
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    PCCERT_CONTEXT cert = nullptr;
    std::wstring container;
    bool ok = false;

    Identity() {
        container = L"wincrawl-tls-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                    std::to_wstring(GetTickCount64());
        if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
            return;
        if (NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, container.c_str(), 0,
                                     NCRYPT_OVERWRITE_KEY_FLAG) != ERROR_SUCCESS)
            return;
        if (NCryptFinalizeKey(key, 0) != ERROR_SUCCESS)
            return;

        BYTE name_buf[256];
        DWORD name_len = sizeof(name_buf);
        if (!CertStrToNameW(X509_ASN_ENCODING, L"CN=localhost", CERT_X500_NAME_STR, nullptr, name_buf, &name_len,
                            nullptr))
            return;
        CERT_NAME_BLOB subject{name_len, name_buf};

        CRYPT_KEY_PROV_INFO prov_info{};
        prov_info.pwszContainerName = container.data();
        prov_info.pwszProvName = const_cast<wchar_t*>(MS_KEY_STORAGE_PROVIDER);
        CRYPT_ALGORITHM_IDENTIFIER sig_alg{};
        char ecdsa_sha256[] = szOID_ECDSA_SHA256;
        sig_alg.pszObjId = ecdsa_sha256;
        cert = CertCreateSelfSignCertificate(key, &subject, 0, &prov_info, &sig_alg, nullptr, nullptr, nullptr);
        ok = cert != nullptr;
    }

    ~Identity() {
        if (cert)
            CertFreeCertificateContext(cert);
        if (key)
            NCryptDeleteKey(key, 0);  // also frees the handle
        if (prov)
            NCryptFreeObject(prov);
    }
};

Identity& identity() {
    static Identity id;
    return id;
}

constexpr ULONG kAscFlags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM | ASC_REQ_EXTENDED_ERROR;

void drain(SecBuffer& b, std::vector<char>& out) {
    if (b.pvBuffer == nullptr)
        return;
    const char* p = static_cast<const char*>(b.pvBuffer);
    out.insert(out.end(), p, p + b.cbBuffer);
    FreeContextBuffer(b.pvBuffer);
    b.pvBuffer = nullptr;
}

}  // namespace

bool server_identity_ready() {
    return identity().ok;
}

struct Server::Impl {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool has_cred = false;
    bool has_ctx = false;
    SecPkgContext_StreamSizes sizes{};
};

Server::Server(ServerProto proto) : impl_(std::make_unique<Impl>()) {
    Identity& id = identity();
    if (!id.ok) {
        failed_ = true;
        return;
    }
    TLS_PARAMETERS params{};
    const DWORD enabled = proto == ServerProto::Tls13 ? SP_PROT_TLS1_3_SERVER : SP_PROT_TLS1_2_SERVER;
    params.grbitDisabledProtocols = ~enabled;
    SCH_CREDENTIALS creds{};
    creds.dwVersion = SCH_CREDENTIALS_VERSION;
    creds.cCreds = 1;
    creds.paCred = &id.cert;
    creds.cTlsParameters = 1;
    creds.pTlsParameters = &params;
    TimeStamp expiry{};
    status_ = AcquireCredentialsHandleA(nullptr, const_cast<char*>(UNISP_NAME_A), SECPKG_CRED_INBOUND, nullptr,
                                        &creds, nullptr, nullptr, &impl_->cred, &expiry);
    impl_->has_cred = status_ == SEC_E_OK;
    failed_ = !impl_->has_cred;
}

Server::~Server() {
    if (impl_->has_ctx)
        DeleteSecurityContext(&impl_->ctx);
    if (impl_->has_cred)
        FreeCredentialsHandle(&impl_->cred);
}

bool Server::feed(const char* data, size_t len, std::vector<char>& wire_out, std::vector<char>& plain_out) {
    in_.insert(in_.end(), data, data + len);
    while (!failed_ && !closed_ && !in_.empty()) {
        size_t left = 0;
        if (!established_) {
            SecBuffer in_bufs[2] = {{static_cast<ULONG>(in_.size()), SECBUFFER_TOKEN, in_.data()},
                                    {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in_bufs};
            SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
            ULONG attrs = 0;
            SECURITY_STATUS st = AcceptSecurityContext(&impl_->cred, impl_->has_ctx ? &impl_->ctx : nullptr,
                                                       &in_desc, kAscFlags, 0, &impl_->ctx, &out_desc, &attrs,
                                                       nullptr);
            status_ = st;
            drain(out_buf, wire_out);
            if (st == SEC_E_INCOMPLETE_MESSAGE)
                return true;
            if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) {
                failed_ = true;
                return false;
            }
            impl_->has_ctx = true;
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA)
                left = in_bufs[1].cbBuffer;
            if (st == SEC_E_OK) {
                established_ = true;
                QueryContextAttributesA(&impl_->ctx, SECPKG_ATTR_STREAM_SIZES, &impl_->sizes);
            }
        } else {
            SecBuffer bufs[4] = {{static_cast<ULONG>(in_.size()), SECBUFFER_DATA, in_.data()},
                                 {0, SECBUFFER_EMPTY, nullptr},
                                 {0, SECBUFFER_EMPTY, nullptr},
                                 {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
            SECURITY_STATUS st = DecryptMessage(&impl_->ctx, &desc, 0, nullptr);
            status_ = st;
            if (st == SEC_E_INCOMPLETE_MESSAGE)
                return true;
            if (st != SEC_E_OK && st != SEC_I_CONTEXT_EXPIRED) {
                failed_ = true;
                return false;
            }
            for (const SecBuffer& b : bufs) {
                if (b.BufferType == SECBUFFER_DATA) {
                    const char* p = static_cast<const char*>(b.pvBuffer);
                    plain_out.insert(plain_out.end(), p, p + b.cbBuffer);
                } else if (b.BufferType == SECBUFFER_EXTRA) {
                    left = b.cbBuffer;
                }
            }
            if (st == SEC_I_CONTEXT_EXPIRED)
                closed_ = true;
        }
        in_.erase(in_.begin(), in_.end() - static_cast<ptrdiff_t>(left));
    }
    return !failed_;
}

bool Server::encrypt(const char* data, size_t len, std::vector<char>& wire_out) {
    const SecPkgContext_StreamSizes& s = impl_->sizes;
    while (len > 0) {
        const size_t chunk = len < s.cbMaximumMessage ? len : s.cbMaximumMessage;
        const size_t base = wire_out.size();
        wire_out.resize(base + s.cbHeader + chunk + s.cbTrailer);
        char* p = wire_out.data() + base;
        std::memcpy(p + s.cbHeader, data, chunk);
        SecBuffer bufs[4] = {{s.cbHeader, SECBUFFER_STREAM_HEADER, p},
                             {static_cast<ULONG>(chunk), SECBUFFER_DATA, p + s.cbHeader},
                             {s.cbTrailer, SECBUFFER_STREAM_TRAILER, p + s.cbHeader + chunk},
                             {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
        status_ = EncryptMessage(&impl_->ctx, 0, &desc, 0);
        if (status_ != SEC_E_OK)
            return false;
        wire_out.resize(base + bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
        data += chunk;
        len -= chunk;
    }
    return true;
}

bool Server::shutdown(std::vector<char>& wire_out) {
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer ctl{sizeof(type), SECBUFFER_TOKEN, &type};
    SecBufferDesc ctl_desc{SECBUFFER_VERSION, 1, &ctl};
    status_ = ApplyControlToken(&impl_->ctx, &ctl_desc);
    if (status_ != SEC_E_OK)
        return false;
    SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
    ULONG attrs = 0;
    status_ = AcceptSecurityContext(&impl_->cred, &impl_->ctx, nullptr, kAscFlags, 0, nullptr, &out_desc, &attrs,
                                    nullptr);
    drain(out_buf, wire_out);
    return status_ == SEC_E_OK || status_ == SEC_I_CONTINUE_NEEDED;
}

}  // namespace wc::tls::test
