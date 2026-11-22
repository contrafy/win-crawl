#include "sig/signer.h"

#include "sig/base64.h"
#include "sig/jwk.h"
#include "sig/sfv.h"

#include <chrono>
#include <charconv>

namespace wc::sig {
namespace {

constexpr int64_t kMaxValidity = 24 * 60 * 60;  // the draft RECOMMENDS expires <= created + 24 h
constexpr size_t kNonceBytes = 64;              // as Cloudflare's reference signers send

void append_int(std::string& out, int64_t v) {
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof buf, v);
    out.append(buf, r.ptr);
}

}  // namespace

bool valid_signature_agent(std::string_view url) {
    return url.starts_with("https://") && url.size() > 8 && sfv::valid_string(url);
}

bool RequestSigner::init(const Ed25519Key& key, const SignerOptions& options, std::string* error) {
    key_ = Ed25519Key();
    auto bad = [&](const char* why) {
        if (error != nullptr) *error = why;
        return false;
    };
    const std::string& member = options.agent_key.empty() ? options.label : options.agent_key;
    if (!key.valid()) return bad("no signing key");
    if (!sfv::valid_key(options.label)) return bad("signature label must match [a-z*][a-z0-9_.*-]*");
    if (!sfv::valid_key(member)) return bad("Signature-Agent member key must match [a-z*][a-z0-9_.*-]*");
    if (options.tag.empty() || !sfv::valid_string(options.tag)) return bad("tag must be printable ASCII");
    if (options.validity_seconds < 1 || options.validity_seconds > kMaxValidity) {
        return bad("validity must be 1 to 86400 seconds");
    }
    const std::string& url = options.signature_agent;
    if (!url.empty() && !valid_signature_agent(url)) {
        return bad("Signature-Agent must be an https:// URL in printable ASCII");
    }
    keyid_ = thumbprint(key.public_key());
    if (keyid_.empty()) return bad("SHA-256 (CNG) failed");

    label_ = options.label;
    tag_ = options.tag;
    validity_ = options.validity_seconds;
    agent_header_.clear();
    agent_line_.clear();
    covered_ = "(\"@authority\"";
    if (!url.empty()) {
        std::string value;
        sfv::append_string(value, url);
        std::string id = "\"signature-agent\"";
        agent_header_ = "Signature-Agent: ";
        if (options.agent_form == AgentForm::Dictionary) {
            // `member` is a valid Key, so it needs no escaping as a String.
            id += ";key=\"" + member + "\"";
            agent_header_ += member + "=";
        }
        agent_header_ += value + "\r\n";
        agent_line_ = id + ": " + value + "\n";
        covered_ += " " + id;
    }
    covered_ += ")";
    // Room for the longest authority (253-byte host + port) without growing.
    params_.reserve(covered_.size() + keyid_.size() + tag_.size() + 256);
    base_.reserve(params_.capacity() + agent_line_.size() + 320);
    headers_.reserve(params_.capacity() + agent_header_.size() + 160);
    nonce_.reserve(base64_size(kNonceBytes));
    key_ = key;
    return true;
}

std::string_view RequestSigner::sign(std::string_view authority) {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    uint8_t raw[kNonceBytes];
    nonce_.clear();
    // The nonce is optional in the protocol; without randomness, leave it out.
    if (random_bytes(raw, sizeof raw)) append_base64(nonce_, raw, sizeof raw);
    return sign(authority, now, now + validity_, nonce_);
}

std::string_view RequestSigner::sign(std::string_view authority, int64_t created, int64_t expires,
                                     std::string_view nonce) {
    params_.assign(covered_);
    params_.append(";created=");
    append_int(params_, created);
    params_.append(";keyid=\"");
    params_.append(keyid_);
    params_.append("\";alg=\"ed25519\";expires=");
    append_int(params_, expires);
    if (!nonce.empty()) {
        params_.append(";nonce=");
        sfv::append_string(params_, nonce);
    }
    params_.append(";tag=");
    sfv::append_string(params_, tag_);

    base_.assign("\"@authority\": ");
    for (const char c : authority) base_.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c);
    base_.push_back('\n');
    base_.append(agent_line_);
    base_.append("\"@signature-params\": ");
    base_.append(params_);

    uint8_t sig[kEd25519SignatureSize];
    key_.sign(base_.data(), base_.size(), sig);

    headers_.assign(agent_header_);
    headers_.append("Signature-Input: ");
    headers_.append(label_);
    headers_.push_back('=');
    headers_.append(params_);
    headers_.append("\r\nSignature: ");
    headers_.append(label_);
    headers_.append("=:");
    append_base64(headers_, sig, sizeof sig);
    headers_.append(":\r\n");
    return headers_;
}

}  // namespace wc::sig
