// Web Bot Auth parsers and signer (sig/): Structured Field Values, JWKs and
// JWK Sets, HTTP message text, signature verification, and sign/verify round
// trips.
//
// Input: byte 0 selects the mode (low two bits); the rest is the data.
//
// 0 sfv: the data as a Dictionary and as an Item. Anything that parses
//   serializes; the serialization reparses to an equal value and is a fixed
//   point (canonical). Each Dictionary member value serializes the same way
//   alone (what a "key"-parameter component signs).
// 1 jwk: the data as one JWK (public, and requiring "d") and as a key set.
//   Every key found has a 43-character thumbprint equal to thumbprint(x);
//   its canonical public JWK (and private JWK, when "d" loaded) parses back to
//   the same key; find_key finds it by thumbprint.
// 2 verify: the data as HTTP message text (request, response or header
//   block), verified under each profile against the RFC 9421 test key, and
//   as a directory response. Results are deterministic; the overall result is
//   valid exactly when every signature is; a valid signature names a known
//   key and was checked over a base that ends in its @signature-params line;
//   a valid directory has every key proven.
// 3 sign: fuzz-chosen authority, Signature-Agent URL, label, form, window and
//   nonce. Whatever RequestSigner accepts must verify (Web Bot Auth profile)
//   under its own key and fail for a different authority.

#include "sig/base64.h"
#include "sig/crypto.h"
#include "sig/httpsig.h"
#include "sig/jwk.h"
#include "sig/sfv.h"
#include "sig/signer.h"

#include "check.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace wc::sig;

namespace {

constexpr std::string_view kTestJwk =
    R"({"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","d":"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"})";

struct TestKey {
    Ed25519Key key;
    std::vector<PublicJwk> set;
    TestKey() {
        PublicJwk pub;
        FUZZ_CHECK(parse_jwk(kTestJwk, pub, &key) == JwkError::None);
        set.push_back(pub);
    }
};

const TestKey& test_key() {
    static const TestKey k;
    return k;
}

void check_sfv(std::string_view data) {
    sfv::Dictionary d;
    if (sfv::parse_dictionary(data, d)) {
        std::string s;
        FUZZ_CHECK(sfv::append_dictionary(s, d));
        sfv::Dictionary again;
        FUZZ_CHECK(sfv::parse_dictionary(s, again));
        FUZZ_CHECK(again == d);
        std::string s2;
        FUZZ_CHECK(sfv::append_dictionary(s2, again));
        FUZZ_CHECK(s2 == s);
        for (const sfv::Member& m : d) {
            FUZZ_CHECK(sfv::find(d, m.key) == &m);
            std::string v;
            FUZZ_CHECK(sfv::append_member_value(v, m));
            sfv::Dictionary one;
            FUZZ_CHECK(sfv::parse_dictionary(m.key + "=" + v, one));
            FUZZ_CHECK(one.size() == 1 && one[0] == m);
        }
    }
    sfv::Item it;
    if (sfv::parse_item(data, it)) {
        std::string s;
        FUZZ_CHECK(sfv::append_item(s, it));
        sfv::Item again;
        FUZZ_CHECK(sfv::parse_item(s, again));
        FUZZ_CHECK(again == it);
    }
}

void check_key(const PublicJwk& k) {
    FUZZ_CHECK(k.thumbprint.size() == 43);
    FUZZ_CHECK(k.thumbprint == thumbprint(k.x.data()));
    std::string pub;
    append_public_jwk(pub, k.x.data());
    PublicJwk back;
    FUZZ_CHECK(parse_jwk(pub, back) == JwkError::None);
    FUZZ_CHECK(back.x == k.x && back.thumbprint == k.thumbprint && back.kid == k.thumbprint);
}

void check_jwk(std::string_view data) {
    PublicJwk pub;
    if (parse_jwk(data, pub) == JwkError::None) check_key(pub);
    Ed25519Key priv;
    PublicJwk with_d;
    if (parse_jwk(data, with_d, &priv) == JwkError::None) {
        FUZZ_CHECK(priv.valid() && with_d.has_private);
        FUZZ_CHECK(std::memcmp(priv.public_key(), with_d.x.data(), 32) == 0);
        std::string text;
        append_private_jwk(text, priv);
        Ed25519Key again;
        FUZZ_CHECK(parse_private_key(text, again) == JwkError::None);
        FUZZ_CHECK(std::memcmp(again.seed(), priv.seed(), 32) == 0);
    }
    std::vector<PublicJwk> set;
    if (parse_key_set(data, set) == JwkError::None) {
        for (const PublicJwk& k : set) {
            check_key(k);
            const PublicJwk* found = find_key(set, k.thumbprint);
            FUZZ_CHECK(found != nullptr && found->x == k.x);
        }
    }
}

void check_results(const std::vector<SignatureResult>& results, SigError first) {
    bool all_valid = !results.empty();
    for (const SignatureResult& r : results) {
        if (r.error != SigError::None) {
            all_valid = false;
            continue;
        }
        // A valid signature was checked over a whole base ending in its parameters.
        FUZZ_CHECK(r.base.starts_with("\"@signature-params\": (") ||
                   r.base.find("\n\"@signature-params\": (") != std::string::npos);
        const PublicJwk* k = r.keyid.empty() ? &test_key().set[0] : find_key(test_key().set, r.keyid);
        FUZZ_CHECK(k != nullptr);
    }
    FUZZ_CHECK((first == SigError::None) == all_valid);
}

void check_verify(std::string_view data) {
    Message msg;
    std::string_view body;
    if (!parse_http_message(data, msg, body)) return;
    for (const Profile profile : {Profile::Rfc9421, Profile::WebBotAuth, Profile::Directory}) {
        VerifyPolicy p;
        p.profile = profile;
        p.now = 1735689600;
        std::vector<SignatureResult> a;
        std::vector<SignatureResult> b;
        const SigError ea = verify_signatures(msg, test_key().set, p, a);
        const SigError eb = verify_signatures(msg, test_key().set, p, b);
        FUZZ_CHECK(ea == eb && a.size() == b.size());
        for (size_t i = 0; i < a.size(); ++i) {
            FUZZ_CHECK(a[i].error == b[i].error && a[i].base == b[i].base && a[i].label == b[i].label);
        }
        if (ea != SigError::NoSignature) check_results(a, ea);
    }
    // As a directory response fetched from the message's own authority.
    Message request;
    request.method = "GET";
    request.scheme = "https";
    request.authority = msg.authority.empty() ? std::string_view("signature-agent.test") : msg.authority;
    request.target = kDirectoryPath;
    msg.request = &request;
    VerifyPolicy p;
    p.now = 1735689600;
    DirectoryResult r;
    const bool ok = verify_directory(msg, body, p, r);
    FUZZ_CHECK(ok == r.problem.empty());
    if (ok) {
        FUZZ_CHECK(!r.keys.empty() && r.proven.size() == r.keys.size());
        for (const bool proven : r.proven) FUZZ_CHECK(proven);
    }
}

// Splits `data` on '\n' into up to `n` fields.
std::vector<std::string_view> split_fields(std::string_view data, size_t n) {
    std::vector<std::string_view> out;
    while (out.size() + 1 < n) {
        const size_t nl = data.find('\n');
        if (nl == std::string_view::npos) break;
        out.push_back(data.substr(0, nl));
        data.remove_prefix(nl + 1);
    }
    out.push_back(data);
    return out;
}

void check_sign(uint8_t flags, std::string_view data) {
    // authority \n agent \n label \n nonce
    const std::vector<std::string_view> f = split_fields(data, 4);
    const std::string_view authority = f[0];
    if (authority.empty() || authority.size() > 300) return;
    for (const char c : authority) {
        if (c <= ' ' || c >= 0x7F) return;
    }
    SignerOptions o;
    o.signature_agent = f.size() > 1 ? std::string(f[1]) : std::string();
    if (f.size() > 2 && !f[2].empty()) o.label = std::string(f[2]);
    o.agent_form = (flags & 4) ? AgentForm::Dictionary : AgentForm::String;
    o.validity_seconds = 1 + (flags >> 3) * 1000;
    RequestSigner signer;
    if (!signer.init(test_key().key, o)) return;
    const std::string_view nonce = f.size() > 3 ? f[3] : std::string_view();
    if (!sfv::valid_string(nonce)) return;
    const int64_t created = 1735689600;
    const std::string headers(signer.sign(authority, created, created + o.validity_seconds, nonce));

    Message msg;
    msg.authority = authority;
    std::string_view body;
    FUZZ_CHECK(parse_http_message(headers, msg, body));
    FUZZ_CHECK(body.empty());
    VerifyPolicy p;
    p.now = created;
    p.require_agent = !o.signature_agent.empty();
    std::vector<SignatureResult> results;
    FUZZ_CHECK(verify_signatures(msg, test_key().set, p, results) == SigError::None);
    FUZZ_CHECK(results.size() == 1 && results[0].label == o.label && results[0].nonce == nonce);
    FUZZ_CHECK(results[0].agent == o.signature_agent);
    FUZZ_CHECK(results[0].base == signer.last_base());

    std::string other(authority);
    const char last = (other.back() >= 'A' && other.back() <= 'Z') ? static_cast<char>(other.back() + 32) : other.back();
    other.back() = last == 'x' ? 'y' : 'x';  // differs after the verifier lowercases it
    msg.authority = other;
    FUZZ_CHECK(verify_signatures(msg, test_key().set, p, results) == SigError::BadSignature);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data + 1), size - 1);
    switch (data[0] & 3) {
    case 0: check_sfv(rest); break;
    case 1: check_jwk(rest); break;
    case 2: check_verify(rest); break;
    default: check_sign(data[0], rest); break;
    }
    return 0;
}
