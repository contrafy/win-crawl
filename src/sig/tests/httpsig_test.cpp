// RFC 9421 signature bases and verification, the Web Bot Auth signer and
// directory checks, against the published vectors:
//  - RFC 9421 Appendix B.2.6 (Ed25519 over test-request);
//  - draft-ietf-webbotauth-httpsig-protocol-01 Appendix E.2.1-E.2.3;
//  - cloudflare/web-bot-auth packages/web-bot-auth/test/test_data
//    (web_bot_auth_architecture_v1/v2.json, web_bot_auth_directory_response_v1.json);
//  - a directory response captured from Cloudflare Research's public example
//    server (2026-11-22), which signs ("@authority";req) only.

#include "sig/base64.h"
#include "sig/httpsig.h"
#include "sig/signer.h"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

using namespace wc::sig;

namespace {

constexpr std::string_view kTestJwk =
    R"({"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","d":"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"})";
constexpr std::string_view kKeyid = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
constexpr int64_t kCreated = 1735689600;

Ed25519Key test_key() {
    Ed25519Key key;
    PublicJwk pub;
    REQUIRE(parse_jwk(kTestJwk, pub, &key) == JwkError::None);
    return key;
}

std::vector<PublicJwk> test_keys() {
    std::vector<PublicJwk> keys;
    REQUIRE(parse_key_set(kTestJwk, keys) == JwkError::None);
    return keys;
}

// Verifies a request whose signature header block is `headers`.
SigError verify_headers(std::string_view headers, std::string_view authority, const VerifyPolicy& policy,
                        std::vector<SignatureResult>& results, const std::vector<PublicJwk>& keys) {
    Message msg;
    msg.method = "GET";
    msg.scheme = "https";
    msg.authority = authority;
    msg.target = "/path/to/resource";
    std::string_view body;
    REQUIRE(parse_http_message(headers, msg, body));
    return verify_signatures(msg, keys, policy, results);
}

SigError verify_headers(std::string_view headers, std::string_view authority, const VerifyPolicy& policy) {
    std::vector<SignatureResult> results;
    return verify_headers(headers, authority, policy, results, test_keys());
}

VerifyPolicy wba_at(int64_t now) {
    VerifyPolicy p;
    p.now = now;
    return p;
}

struct WbaVector {
    const char* name;
    AgentForm form;
    const char* label;
    const char* agent_key;
    const char* agent;  // empty: no Signature-Agent
    int64_t expires;
    const char* nonce;
    const char* headers;
};

const WbaVector kWbaVectors[] = {
    {"draft-01 E.2.1 dictionary", AgentForm::Dictionary, "sig2", "", "https://signature-agent.test", 4889289600,
     "n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==",
     "Signature-Agent: sig2=\"https://signature-agent.test\"\r\n"
     "Signature-Input: sig2=(\"@authority\" \"signature-agent\";key=\"sig2\");created=1735689600;"
     "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=4889289600;"
     "nonce=\"n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==\";tag=\"web-bot-auth\"\r\n"
     "Signature: sig2=:CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==:\r\n"},
    {"draft-01 E.2.2 sf-string (Cloudflare)", AgentForm::String, "sig2", "", "https://signature-agent.test", 1735693200,
     "e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==",
     "Signature-Agent: \"https://signature-agent.test\"\r\n"
     "Signature-Input: sig2=(\"@authority\" \"signature-agent\");created=1735689600;"
     "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1735693200;"
     "nonce=\"e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==\";tag=\"web-bot-auth\"\r\n"
     "Signature: sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:\r\n"},
    {"architecture_v2 sig1 (@authority only)", AgentForm::String, "sig1", "", "", 4889289600,
     "zIW8+cdmA3vdYagbxojpONwa/l0EKJ/O3/wD486VvsQjO/RxPaSt6ZxvQaMcQzNnqKN/mQ6hpGiFro2L2qkz5A==",
     "Signature-Input: sig1=(\"@authority\");created=1735689600;"
     "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=4889289600;"
     "nonce=\"zIW8+cdmA3vdYagbxojpONwa/l0EKJ/O3/wD486VvsQjO/RxPaSt6ZxvQaMcQzNnqKN/mQ6hpGiFro2L2qkz5A==\";tag=\"web-bot-auth\"\r\n"
     "Signature: sig1=:QKN4fTdIYfh82fvoZCQiQA1weuozfCS/Led2zTMbewMMqH8PI2Wsy/5c4ao6B6D09nraNQdBNOADg8aM1MqfCg==:\r\n"},
    {"architecture_v2 sig2 (member agent2)", AgentForm::Dictionary, "sig2", "agent2", "https://signature-agent.test",
     4889289600, "n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==",
     "Signature-Agent: agent2=\"https://signature-agent.test\"\r\n"
     "Signature-Input: sig2=(\"@authority\" \"signature-agent\";key=\"agent2\");created=1735689600;"
     "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=4889289600;"
     "nonce=\"n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==\";tag=\"web-bot-auth\"\r\n"
     "Signature: sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:\r\n"},
    {"architecture_v1 sig1 (@authority only)", AgentForm::String, "sig1", "", "", 1735693200,
     "mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==",
     "Signature-Input: sig1=(\"@authority\");created=1735689600;"
     "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1735693200;"
     "nonce=\"mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==\";tag=\"web-bot-auth\"\r\n"
     "Signature: sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0BtvdnrpDEuwSAbiTeElXDzHL3WWKCw==:\r\n"},
};

constexpr std::string_view kDirectoryBody =
    R"({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]})";

bool check_directory(std::string_view head, std::string_view authority, int64_t now, bool require_digest,
                     DirectoryResult& result) {
    Message request;
    request.method = "GET";
    request.scheme = "https";
    request.authority = authority;
    request.target = kDirectoryPath;
    Message response;
    std::string_view body;
    REQUIRE(parse_http_message(head, response, body));
    response.request = &request;
    VerifyPolicy p;
    p.now = now;
    p.require_content_digest = require_digest;
    return verify_directory(response, body, p, result);
}

}  // namespace

TEST_CASE("RFC 9421 B.2.6: signature base and Ed25519 signature over test-request") {
    const std::string text =
        "POST /foo?param=Value&Pet=dog HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Date: Tue, 20 Apr 2021 02:07:55 GMT\r\n"
        "Content-Type: application/json\r\n"
        "Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\r\n"
        "Content-Length: 18\r\n"
        "Signature-Input: sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"\r\n"
        "Signature: sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:\r\n"
        "\r\n"
        "{\"hello\": \"world\"}";
    Message msg;
    std::string_view body;
    REQUIRE(parse_http_message(text, msg, body));
    CHECK(msg.method == "POST");
    CHECK(msg.target == "/foo?param=Value&Pet=dog");
    CHECK(msg.authority == "example.com");
    CHECK(body == "{\"hello\": \"world\"}");

    sfv::Dictionary inputs;
    REQUIRE(msg.fields[5].name == "Signature-Input");
    REQUIRE(sfv::parse_dictionary(msg.fields[5].value, inputs));
    std::string base;
    REQUIRE(build_signature_base(msg, inputs[0].list, base) == SigError::None);
    CHECK(base ==
          "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
          "\"@method\": POST\n"
          "\"@path\": /foo\n"
          "\"@authority\": example.com\n"
          "\"content-type\": application/json\n"
          "\"content-length\": 18\n"
          "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");"
          "created=1618884473;keyid=\"test-key-ed25519\"");

    uint8_t sig[kEd25519SignatureSize];
    test_key().sign(base.data(), base.size(), sig);
    std::string b64;
    append_base64(b64, sig, sizeof sig);
    CHECK(b64 == "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==");

    VerifyPolicy p;
    p.profile = Profile::Rfc9421;
    p.now = 1618884473;
    std::vector<SignatureResult> results;
    CHECK(verify_signatures(msg, test_keys(), p, results) == SigError::None);
    REQUIRE(results.size() == 1);
    CHECK(results[0].label == "sig-b26");
    CHECK(results[0].keyid == "test-key-ed25519");
    CHECK(results[0].base == base);
    // Web Bot Auth asks for more than RFC 9421 does.
    p.profile = Profile::WebBotAuth;
    CHECK(verify_signatures(msg, test_keys(), p, results) == SigError::Profile);
}

TEST_CASE("derived components") {
    Message req;
    req.method = "GET";
    req.scheme = "HTTPS";
    req.authority = "Example.COM:8443";
    req.target = "/a/b";
    req.fields = {{"X-Multi", " one "}, {"x-multi", "two"}, {"Dict", "a=1, b=(2 3);p"}, {"Num", "1"}, {"Bin", "caf\xc3\xa9"}};
    auto base_of = [&](std::string_view covered, const Message& m) {
        sfv::Dictionary d;
        REQUIRE(sfv::parse_dictionary(std::string("s=") + std::string(covered), d));
        std::string out;
        const SigError e = build_signature_base(m, d[0].list, out);
        return e == SigError::None ? out.substr(0, out.find("\"@signature-params\"")) : std::string(to_string(e));
    };
    CHECK(base_of(R"(("@authority" "@scheme" "@target-uri"))", req) ==
          "\"@authority\": example.com:8443\n\"@scheme\": https\n\"@target-uri\": https://example.com:8443/a/b\n");
    CHECK(base_of(R"(("@query" "@path" "@request-target"))", req) == "\"@query\": ?\n\"@path\": /a/b\n\"@request-target\": /a/b\n");
    req.target = "/a?x=1&y";
    CHECK(base_of(R"(("@query" "@path"))", req) == "\"@query\": ?x=1&y\n\"@path\": /a\n");
    CHECK(base_of(R"(("x-multi"))", req) == "\"x-multi\": one, two\n");
    CHECK(base_of(R"(("dict";key="b" "dict";key="a"))", req) == "\"dict\";key=\"b\": (2 3);p\n\"dict\";key=\"a\": 1\n");
    CHECK(base_of(R"(("dict";key="c"))", req) == "missing component");
    CHECK(base_of(R"(("num";key="a"))", req) == "malformed");
    CHECK(base_of(R"(("x-multi";key="one"))", req) == "\"x-multi\";key=\"one\": ?1\n");
    CHECK(base_of(R"(("missing"))", req) == "missing component");
    CHECK(base_of(R"(("bin"))", req) == "unsupported component");
    CHECK(base_of(R"(("x-multi";sf))", req) == "unsupported component");
    CHECK(base_of(R"(("@query-param";name="x"))", req) == "unsupported component");
    CHECK(base_of(R"(("@status"))", req) == "missing component");
    CHECK(base_of(R"(("@signature-params"))", req) == "malformed");
    CHECK(base_of(R"(("X-Multi"))", req) == "malformed");
    CHECK(base_of(R"(("@method" "@method"))", req) == "duplicate component");
    CHECK(base_of(R"((date))", req) == "malformed");

    Message resp;
    resp.status = 200;
    resp.fields = {{"Content-Type", "text/plain"}};
    resp.request = &req;
    CHECK(base_of(R"(("@status" "@authority";req "content-type" "x-multi";req))", resp) ==
          "\"@status\": 200\n\"@authority\";req: example.com:8443\n\"content-type\": text/plain\n\"x-multi\";req: one, two\n");
    CHECK(base_of(R"(("@authority"))", resp) == "missing component");
    resp.request = nullptr;
    CHECK(base_of(R"(("@authority";req))", resp) == "missing component");
}

TEST_CASE("RequestSigner reproduces the Web Bot Auth vectors, and the verifier accepts them") {
    const Ed25519Key key = test_key();
    for (const WbaVector& v : kWbaVectors) {
        CAPTURE(v.name);
        SignerOptions o;
        o.signature_agent = v.agent;
        o.agent_form = v.form;
        o.label = v.label;
        o.agent_key = v.agent_key;
        RequestSigner signer;
        std::string error;
        REQUIRE(signer.init(key, o, &error));
        CHECK(signer.keyid() == kKeyid);
        const std::string_view headers = signer.sign("example.com", kCreated, v.expires, v.nonce);
        CHECK(headers == v.headers);

        VerifyPolicy p = wba_at(kCreated);
        p.require_agent = *v.agent != '\0';
        std::vector<SignatureResult> results;
        CHECK(verify_headers(headers, "example.com", p, results, test_keys()) == SigError::None);
        REQUIRE(results.size() == 1);
        CHECK(results[0].base == signer.last_base());
        CHECK(results[0].agent == v.agent);
        CHECK(results[0].agent_legacy == (*v.agent != '\0' && v.form == AgentForm::String));
        CHECK(results[0].created == kCreated);
        CHECK(results[0].expires == v.expires);
        CHECK(results[0].nonce == v.nonce);
        CHECK(results[0].tag == "web-bot-auth");
        // The Host header supplies @authority when the caller does not, as for a fake server.
        const std::string request = "GET /x HTTP/1.1\r\nHost: Example.com\r\n" + std::string(headers) + "\r\n";
        Message msg;
        std::string_view body;
        REQUIRE(parse_http_message(request, msg, body));
        CHECK(verify_signatures(msg, test_keys(), p, results) == SigError::None);
        // A different authority breaks it.
        CHECK(verify_headers(headers, "example.org", p) == SigError::BadSignature);
    }
}

TEST_CASE("draft-01 E.2.1 signature base") {
    SignerOptions o;
    o.signature_agent = "https://signature-agent.test";
    o.agent_form = AgentForm::Dictionary;
    o.label = "sig2";
    RequestSigner signer;
    REQUIRE(signer.init(test_key(), o));
    signer.sign("example.com", kCreated, 4889289600, kWbaVectors[0].nonce);
    CHECK(signer.last_base() ==
          "\"@authority\": example.com\n"
          "\"signature-agent\";key=\"sig2\": \"https://signature-agent.test\"\n"
          "\"@signature-params\": (\"@authority\" \"signature-agent\";key=\"sig2\");created=1735689600;"
          "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=4889289600;"
          "nonce=\"n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==\";tag=\"web-bot-auth\"");
}

TEST_CASE("live signing: fresh window and nonce, lowercased authority, buffers reused") {
    SignerOptions o;
    o.signature_agent = "https://bot.example";
    RequestSigner signer;
    REQUIRE(signer.init(test_key(), o));
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    std::string first(signer.sign("WWW.Example.com:8080"));
    std::vector<SignatureResult> results;
    REQUIRE(verify_headers(first, "www.example.com:8080", wba_at(now), results, test_keys()) == SigError::None);
    CHECK(results[0].expires - results[0].created == 60);
    CHECK(results[0].created >= now - 2);
    CHECK(results[0].created <= now + 2);
    std::string decoded;
    REQUIRE(decode_base64(results[0].nonce, decoded));
    CHECK(decoded.size() == 64);
    const std::string nonce = results[0].nonce;

    const char* data = signer.sign("www.example.com:8080").data();
    for (int i = 0; i < 100; ++i) {
        const std::string_view h = signer.sign("www.example.com:8080");
        CHECK(h.data() == data);  // no reallocation
    }
    REQUIRE(verify_headers(signer.sign("www.example.com:8080"), "www.example.com:8080", wba_at(now), results, test_keys()) ==
            SigError::None);
    CHECK(results[0].nonce != nonce);

    // Outside the window.
    CHECK(verify_headers(first, "www.example.com:8080", wba_at(now + 120)) == SigError::Expired);
    CHECK(verify_headers(first, "www.example.com:8080", wba_at(now - 120)) == SigError::NotYetValid);
}

TEST_CASE("signer configuration is validated") {
    RequestSigner signer;
    std::string error;
    SignerOptions o;
    o.signature_agent = "http://bot.example";
    CHECK_FALSE(signer.init(test_key(), o, &error));
    CHECK(error.find("https") != std::string::npos);
    o.signature_agent = "https://";
    CHECK_FALSE(signer.init(test_key(), o, &error));
    o.signature_agent = "https://bot.example/\n";
    CHECK_FALSE(signer.init(test_key(), o, &error));
    o.signature_agent = "https://bot.example";
    o.label = "Sig1";
    CHECK_FALSE(signer.init(test_key(), o, &error));
    o.label = "sig1";
    o.validity_seconds = 0;
    CHECK_FALSE(signer.init(test_key(), o, &error));
    o.validity_seconds = 90000;
    CHECK_FALSE(signer.init(test_key(), o, &error));
    o.validity_seconds = 60;
    CHECK_FALSE(signer.init(Ed25519Key(), o, &error));
    CHECK_FALSE(signer.ready());
    CHECK(signer.init(test_key(), o, &error));
    CHECK(signer.ready());
}

TEST_CASE("verifier rejects what Web Bot Auth forbids") {
    SignerOptions o;
    o.signature_agent = "https://signature-agent.test";
    RequestSigner signer;
    REQUIRE(signer.init(test_key(), o));
    const std::string good(signer.sign("example.com", kCreated, kCreated + 60, "bm9uY2U="));
    REQUIRE(verify_headers(good, "example.com", wba_at(kCreated)) == SigError::None);

    auto replace = [](std::string s, std::string_view from, std::string_view to) {
        const size_t at = s.find(from);
        REQUIRE(at != std::string::npos);
        return s.replace(at, from.size(), to);
    };
    // The Signature-Agent value is signed.
    CHECK(verify_headers(replace(good, "signature-agent.test\"", "evil.test\""), "example.com", wba_at(kCreated)) ==
          SigError::BadSignature);
    // A signed parameter changes.
    CHECK(verify_headers(replace(good, "nonce=\"bm9uY2U=\"", "nonce=\"bm9uY2X=\""), "example.com", wba_at(kCreated)) ==
          SigError::BadSignature);
    CHECK(verify_headers(replace(good, "tag=\"web-bot-auth\"", "tag=\"other\""), "example.com", wba_at(kCreated)) ==
          SigError::Profile);
    CHECK(verify_headers(replace(good, "alg=\"ed25519\"", "alg=\"rsa-pss-sha512\""), "example.com", wba_at(kCreated)) ==
          SigError::UnsupportedAlgorithm);
    CHECK(verify_headers(replace(good, "keyid=\"poqk", "keyid=\"xoqk"), "example.com", wba_at(kCreated)) ==
          SigError::UnknownKey);
    CHECK(verify_headers(replace(good, ";created=1735689600", ""), "example.com", wba_at(kCreated)) == SigError::Profile);
    CHECK(verify_headers(replace(good, "created=1735689600", "created=\"1735689600\""), "example.com", wba_at(kCreated)) ==
          SigError::BadParameters);
    CHECK(verify_headers(replace(good, "expires=1735689660", "expires=1735689000"), "example.com", wba_at(kCreated)) ==
          SigError::BadParameters);
    // Signature-Agent must be covered, https, and present when required.
    CHECK(verify_headers(replace(good, " \"signature-agent\"", ""), "example.com", wba_at(kCreated)) == SigError::Profile);
    CHECK(verify_headers(replace(good, "\"https://signature-agent.test\"", "\"http://signature-agent.test\""), "example.com",
                         wba_at(kCreated)) == SigError::Profile);
    CHECK(verify_headers(replace(good, "Signature-Agent: \"https://signature-agent.test\"\r\n", ""), "example.com",
                         wba_at(kCreated)) == SigError::Profile);
    CHECK(verify_headers(replace(good, "Signature-Agent: \"https://signature-agent.test\"",
                                 "Signature-Agent: sig1=\"https://signature-agent.test\""),
                         "example.com", wba_at(kCreated)) == SigError::Profile);
    CHECK(verify_headers(replace(good, "Signature-Agent: \"https://", "Signature-Agent: \"https:\\/\\/"), "example.com",
                         wba_at(kCreated)) == SigError::Malformed);
    // Signature and Signature-Input must parse and pair up.
    CHECK(verify_headers(replace(good, "Signature: sig1=", "Signature: sig9="), "example.com", wba_at(kCreated)) ==
          SigError::Malformed);
    CHECK(verify_headers(replace(good, "Signature: sig1=:", "Signature: sig1=:AAAA"), "example.com", wba_at(kCreated)) ==
          SigError::BadSignature);
    CHECK(verify_headers(replace(good, "Signature-Input: sig1=(", "Signature-Input: sig1=,("), "example.com",
                         wba_at(kCreated)) == SigError::Malformed);
    CHECK(verify_headers("Signature-Agent: \"https://x.test\"\r\n", "example.com", wba_at(kCreated)) ==
          SigError::NoSignature);

    // Dictionary form: the covered member must be the one present.
    o.agent_form = AgentForm::Dictionary;
    REQUIRE(signer.init(test_key(), o));
    const std::string dict(signer.sign("example.com", kCreated, kCreated + 60, ""));
    REQUIRE(verify_headers(dict, "example.com", wba_at(kCreated)) == SigError::None);
    CHECK(verify_headers(replace(dict, "Signature-Agent: sig1=", "Signature-Agent: sig2="), "example.com",
                         wba_at(kCreated)) == SigError::MissingComponent);
    CHECK(verify_headers(replace(dict, "test\"\r\nSignature-Input", "test\";p\r\nSignature-Input"), "example.com",
                         wba_at(kCreated)) == SigError::Profile);
    // Two signers' members in one dictionary are fine.
    CHECK(verify_headers(replace(dict, "Signature-Agent: sig1=\"https://signature-agent.test\"",
                                 "Signature-Agent: other=\"https://other.test\", sig1=\"https://signature-agent.test\""),
                         "example.com", wba_at(kCreated)) == SigError::None);
}

TEST_CASE("draft-01 E.2.3 signed directory response") {
    std::vector<std::array<uint8_t, 32>> xs(1);
    const Ed25519Key key = test_key();
    std::copy(key.public_key(), key.public_key() + 32, xs[0].begin());
    std::string body;
    append_jwks(body, xs);
    CHECK(body == kDirectoryBody);  // append_jwks writes exactly the vector's body
    CHECK(content_digest(body) == "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:");

    const std::string head =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/http-message-signatures-directory+json\r\n"
        "Content-Digest: sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:\r\n"
        "Signature-Input: binding=(\"@authority\";req \"content-digest\");created=1735689600;expires=4889289600;"
        "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";tag=\"http-message-signatures-directory\"\r\n"
        "Signature: binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:\r\n"
        "\r\n" + body;
    DirectoryResult r;
    CHECK(check_directory(head, "signature-agent.test", kCreated, true, r));
    CHECK(r.problem.empty());
    REQUIRE(r.signatures.size() == 1);
    CHECK(r.signatures[0].base ==
          "\"@authority\";req: signature-agent.test\n"
          "\"content-digest\": sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:\n"
          "\"@signature-params\": (\"@authority\";req \"content-digest\");created=1735689600;expires=4889289600;"
          "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";tag=\"http-message-signatures-directory\"");
    REQUIRE(r.proven.size() == 1);
    CHECK(r.proven[0]);

    // Re-served under another authority, or with another body, it fails.
    CHECK_FALSE(check_directory(head, "mirror.test", kCreated, true, r));
    CHECK(r.problem.find("no valid directory signature") != std::string::npos);
    std::string swapped = head;
    swapped.replace(swapped.find("\"use\":\"sig\""), 11, "\"use\":\"enc\"");
    CHECK_FALSE(check_directory(swapped, "signature-agent.test", kCreated, true, r));
    CHECK(r.problem == "Content-Digest does not match the body");
    std::string media = head;
    media.replace(media.find("application/http-message"), 4, "text");
    CHECK_FALSE(check_directory(media, "signature-agent.test", kCreated, true, r));
}

TEST_CASE("web-bot-auth directory_response_v1 fixture") {
    const std::string head =
        "HTTP/1.1 200 OK\r\n"
        "content-type: application/http-message-signatures-directory+json\r\n"
        "content-digest: sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:\r\n"
        "Signature: binding0=:yiHq0TXrbpzbmlttAQMpYoAufitFJUWuNsakB7QQMoN0EHbo5o51bZRVR8az/ptTWCwllix9clrKXfGKwdPzBg==:\r\n"
        "Signature-Input: binding0=(\"@authority\";req \"content-digest\");created=1735689600;"
        "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=4889289600;"
        "tag=\"http-message-signatures-directory\"\r\n"
        "\r\n" + std::string(kDirectoryBody);
    DirectoryResult r;
    CHECK(check_directory(head, "signature-agent.test", kCreated, true, r));
    CHECK(r.problem.empty());
    // A proof dated in the future is rejected (draft-01 Appendix B.1).
    CHECK_FALSE(check_directory(head, "signature-agent.test", kCreated - 3600, true, r));
}

TEST_CASE("Cloudflare Research example directory (legacy proof without content-digest)") {
    const std::string head =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/http-message-signatures-directory+json\r\n"
        "Signature: binding0=:a7ZUovKUWQfWmawlxSCSmWgUvhHHpKHe7HgWSRs9uTGAn/+w9MpgVnSdhRnd3eg+k7MKycGbXbOfrhEetWX+AQ==:\r\n"
        "Signature-Input: binding0=(\"@authority\";req);created=1795372499;"
        "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1795372799;"
        "tag=\"http-message-signatures-directory\"\r\n"
        "\r\n"
        R"({"keys":[{"kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","nbf":1743465600000}],"purpose":"rag"})";
    DirectoryResult r;
    CHECK(check_directory(head, "http-message-signatures-example.research.cloudflare.com", 1795372500, false, r));
    CHECK(r.problem.empty());
    CHECK_FALSE(check_directory(head, "http-message-signatures-example.research.cloudflare.com", 1795372500, true, r));
    CHECK(r.problem == "no Content-Digest");
}

TEST_CASE("parse_http_message forms") {
    Message m;
    std::string_view body;
    REQUIRE(parse_http_message("GET https://Example.com HTTP/1.1\nHost: other\n\n", m, body));
    CHECK(m.scheme == "https");
    CHECK(m.authority == "Example.com");
    CHECK(m.target == "/");
    m = {};
    REQUIRE(parse_http_message("HTTP/1.1 404 Not Found\r\nA: b\r\n", m, body));
    CHECK(m.status == 404);
    REQUIRE(m.fields.size() == 1);
    CHECK(body.empty());
    m = {};
    REQUIRE(parse_http_message("Signature: x\r\nSignature-Input: y\r\n", m, body));
    CHECK(m.fields.size() == 2);
    CHECK(m.method.empty());
    CHECK_FALSE(parse_http_message("A: b\r\n folded\r\n", m, body));
    CHECK_FALSE(parse_http_message("A b: c\r\n", m, body));
    CHECK_FALSE(parse_http_message("HTTP/1.1 2\r\n", m, body));
    CHECK_FALSE(parse_http_message("GET\r\n", m, body));
}
