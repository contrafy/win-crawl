// JWK / JWK Set parsing, serialization and RFC 7638 thumbprints.

#include "sig/jwk.h"

#include <doctest/doctest.h>

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace wc::sig;

namespace {

// RFC 8037 Appendix A.1 (the RFC 8032 TEST 1 key).
constexpr std::string_view kRfc8037Private =
    R"({"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";

// RFC 9421 Appendix B.1.4, test-key-ed25519.
constexpr std::string_view kRfc9421Jwk = R"({
  "kty": "OKP",
  "crv": "Ed25519",
  "kid": "test-key-ed25519",
  "d": "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
})";
constexpr std::string_view kRfc9421Pem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n"
    "-----END PRIVATE KEY-----\n";
constexpr std::string_view kRfc9421Thumbprint = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

}  // namespace

TEST_CASE("RFC 8037 Appendix A.3 thumbprint") {
    PublicJwk pub;
    Ed25519Key key;
    REQUIRE(parse_jwk(kRfc8037Private, pub, &key) == JwkError::None);
    CHECK(pub.thumbprint == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    CHECK(thumbprint(pub.x.data()) == pub.thumbprint);
    CHECK(pub.has_private);
    CHECK(pub.kid.empty());
    REQUIRE(key.valid());
    CHECK(std::memcmp(key.public_key(), pub.x.data(), 32) == 0);
}

TEST_CASE("RFC 9421 test key: JWK, PEM and the Web Bot Auth keyid") {
    PublicJwk pub;
    Ed25519Key from_jwk;
    REQUIRE(parse_jwk(kRfc9421Jwk, pub, &from_jwk) == JwkError::None);
    CHECK(pub.kid == "test-key-ed25519");
    CHECK(pub.thumbprint == kRfc9421Thumbprint);
    Ed25519Key from_pem;
    REQUIRE(parse_pkcs8_pem(kRfc9421Pem, from_pem));
    CHECK(std::memcmp(from_pem.seed(), from_jwk.seed(), 32) == 0);
    CHECK(std::memcmp(from_pem.public_key(), pub.x.data(), 32) == 0);
    CHECK_FALSE(parse_pkcs8_pem("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=\n-----END PUBLIC KEY-----\n", from_pem));
    CHECK_FALSE(parse_pkcs8_pem("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50\n-----END PRIVATE KEY-----\n", from_pem));
    Ed25519Key any;
    REQUIRE(parse_private_key(kRfc9421Pem, any) == JwkError::None);
    CHECK(std::memcmp(any.seed(), from_jwk.seed(), 32) == 0);
    REQUIRE(parse_private_key(kRfc9421Jwk, any) == JwkError::None);
    CHECK(std::memcmp(any.seed(), from_jwk.seed(), 32) == 0);
    CHECK(parse_private_key("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----", any) == JwkError::BadPrivateKey);
    CHECK(parse_private_key(R"({"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"})", any) ==
          JwkError::NoPrivateKey);
}

TEST_CASE("private JWK and JWK Set serialization round-trip") {
    Ed25519Key key;
    REQUIRE(key.generate());
    std::string priv;
    append_private_jwk(priv, key);
    PublicJwk pub;
    Ed25519Key back;
    REQUIRE(parse_jwk(priv, pub, &back) == JwkError::None);
    CHECK(std::memcmp(back.seed(), key.seed(), 32) == 0);
    CHECK(pub.kid == pub.thumbprint);

    std::string single;
    append_public_jwk(single, key.public_key());
    CHECK(single.find("\"d\"") == std::string::npos);
    CHECK(single.find("\"use\":\"sig\"") != std::string::npos);
    PublicJwk only;
    REQUIRE(parse_jwk(single, only) == JwkError::None);
    CHECK_FALSE(only.has_private);
    CHECK(parse_jwk(single, only, &back) == JwkError::NoPrivateKey);

    Ed25519Key other;
    REQUIRE(other.generate());
    std::string jwks;
    std::vector<std::array<uint8_t, 32>> xs(2);
    std::memcpy(xs[0].data(), key.public_key(), 32);
    std::memcpy(xs[1].data(), other.public_key(), 32);
    append_jwks(jwks, xs);
    std::vector<PublicJwk> set;
    REQUIRE(parse_key_set(jwks, set) == JwkError::None);
    REQUIRE(set.size() == 2);
    CHECK(set[0].x == xs[0]);
    CHECK(set[1].x == xs[1]);
    CHECK(find_key(set, set[1].thumbprint) == &set[1]);
    CHECK(find_key(set, "nope") == nullptr);
}

TEST_CASE("key sets skip other key types and accept a bare JWK") {
    const std::string_view mixed = R"({"keys":[
        {"kty":"RSA","n":"AQAB","e":"AQAB","kid":"rsa"},
        {"kty":"OKP","crv":"X25519","x":"AAAA"},
        {"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
         "x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","nbf":1743465600000,"key_ops":["verify"]}
      ],"purpose":"rag"})";
    std::vector<PublicJwk> set;
    REQUIRE(parse_key_set(mixed, set) == JwkError::None);
    REQUIRE(set.size() == 1);
    CHECK(set[0].thumbprint == kRfc9421Thumbprint);
    CHECK(set[0].kid == kRfc9421Thumbprint);
    CHECK(find_key(set, "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U") == &set[0]);

    REQUIRE(parse_key_set(kRfc9421Jwk, set) == JwkError::None);
    REQUIRE(set.size() == 1);
    CHECK(find_key(set, "test-key-ed25519") == &set[0]);  // by kid
    CHECK(find_key(set, kRfc9421Thumbprint) == &set[0]);  // by thumbprint

    CHECK(parse_key_set(R"({"keys":[]})", set) == JwkError::None);
    CHECK(set.empty());
}

TEST_CASE("malformed keys are rejected with a reason") {
    PublicJwk pub;
    std::vector<PublicJwk> set;
    CHECK(parse_jwk("", pub) == JwkError::NotObject);
    CHECK(parse_jwk("[]", pub) == JwkError::NotObject);
    CHECK(parse_jwk(R"({"kty":"OKP")", pub) == JwkError::Json);
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"} x)", pub) == JwkError::Json);
    CHECK(parse_jwk(R"({"kty":"OKP","kty":"OKP","crv":"Ed25519"})", pub) == JwkError::Duplicate);
    CHECK(parse_jwk(R"({"kty":"EC","crv":"P-256","x":"a","y":"b"})", pub) == JwkError::Unsupported);
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed25519"})", pub) == JwkError::BadPublicKey);
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs="})", pub) ==
          JwkError::BadPublicKey);  // padded
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bt"})", pub) ==
          JwkError::BadPublicKey);  // non-canonical: would alias the thumbprint
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","d":"short"})", pub) ==
          JwkError::BadPrivateKey);
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"})", pub) ==
          JwkError::KeyMismatch);
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed25519","x":1})", pub) == JwkError::Json);
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"Ed\u00325519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"})", pub) ==
          JwkError::None);  // escapes decode before comparison
    CHECK(parse_jwk(R"({"kty":"OKP","crv":"ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"})", pub) ==
          JwkError::Unsupported);
    CHECK(parse_jwk(R"({"kty":"\u004fKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","z":[1,-2.5e3,true,null,{"a":"\ud83d\ude00"}]})", pub) ==
          JwkError::None);
    CHECK(parse_jwk(R"({"kty":"OKP","z":"\ud83d"})", pub) == JwkError::Json);  // lone surrogate
    CHECK(parse_jwk(R"({"kty":"OKP","z":01})", pub) == JwkError::Json);
    CHECK(parse_jwk(std::string(40, '[') + std::string(40, ']'), pub) == JwkError::NotObject);
    CHECK(parse_key_set(R"({"z":)" + std::string(40, '[') + std::string(40, ']') + "}", set) == JwkError::Json);
    CHECK(parse_key_set(R"({"purpose":"rag"})", set) == JwkError::NoKeys);
    CHECK(parse_key_set(R"({"keys":{}})", set) == JwkError::Json);
    CHECK(parse_key_set(R"({"keys":[1]})", set) == JwkError::Json);
    CHECK(parse_key_set(R"({"keys":[],"keys":[]})", set) == JwkError::Duplicate);
    CHECK(to_string(JwkError::KeyMismatch) == std::string_view("\"d\" does not match \"x\""));
}
