// Structured Field Values (RFC 9651): parsing, canonical serialization.

#include "sig/sfv.h"

#include <doctest/doctest.h>

#include <string>
#include <string_view>

using namespace wc::sig::sfv;

namespace {

// Parses a dictionary and returns its canonical serialization, or "<fail>".
std::string dict_roundtrip(std::string_view field) {
    Dictionary d;
    if (!parse_dictionary(field, d)) return "<fail>";
    std::string out;
    if (!append_dictionary(out, d)) return "<unserializable>";
    return out;
}

std::string item_roundtrip(std::string_view field) {
    Item it;
    if (!parse_item(field, it)) return "<fail>";
    std::string out;
    if (!append_item(out, it)) return "<unserializable>";
    return out;
}

}  // namespace

TEST_CASE("Signature-Input parses into inner lists with parameters") {
    const std::string_view field =
        R"(sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqk";alg="ed25519";expires=1735693200;nonce="ab+/==";tag="web-bot-auth")";
    Dictionary d;
    REQUIRE(parse_dictionary(field, d));
    REQUIRE(d.size() == 1);
    const Member& m = d[0];
    CHECK(m.key == "sig1");
    REQUIRE(m.is_list);
    REQUIRE(m.list.items.size() == 2);
    CHECK(m.list.items[0].value == BareItem::string("@authority"));
    CHECK(m.list.items[0].params.empty());
    CHECK(m.list.items[1].value == BareItem::string("signature-agent"));
    REQUIRE(m.list.items[1].params.size() == 1);
    CHECK(m.list.items[1].params[0].first == "key");
    CHECK(m.list.items[1].params[0].second == BareItem::string("sig1"));
    REQUIRE(m.list.params.size() == 6);
    CHECK(*find(m.list.params, "created") == BareItem::number(1735689600));
    CHECK(*find(m.list.params, "nonce") == BareItem::string("ab+/=="));
    CHECK(find(m.list.params, "missing") == nullptr);
    std::string out;
    REQUIRE(append_dictionary(out, d));
    CHECK(out == field);
}

TEST_CASE("Signature byte sequences decode") {
    Dictionary d;
    REQUIRE(parse_dictionary("sig1=:aGVsbG8=:, sig2=:d29ybGQ:", d));
    REQUIRE(d.size() == 2);
    CHECK(d[0].item.value == BareItem::bytes("hello"));
    CHECK(d[1].item.value == BareItem::bytes("world"));  // missing padding tolerated
    CHECK(dict_roundtrip("sig1=:aGVsbG8=:, sig2=:d29ybGQ:") == "sig1=:aGVsbG8=:, sig2=:d29ybGQ=:");
    CHECK(dict_roundtrip("a=:aGVs bG8=:") == "<fail>");
    CHECK(dict_roundtrip("a=:aGVsbG8=") == "<fail>");
    CHECK(dict_roundtrip("a=:-_:") == "<fail>");
}

TEST_CASE("dictionary syntax: whitespace, booleans, duplicates, errors") {
    CHECK(dict_roundtrip("  a=1,b=2  ") == "a=1, b=2");
    CHECK(dict_roundtrip("a=1 ,\tb=2") == "a=1, b=2");
    CHECK(dict_roundtrip("a, b;x=?0, c=?1") == "a, b;x=?0, c");
    CHECK(dict_roundtrip("a=1, b=2, a=3") == "a=3, b=2");  // last wins, first position kept
    CHECK(dict_roundtrip("a=(1 2);p, b=()") == "a=(1 2);p, b=()");
    CHECK(dict_roundtrip("a=(  1   2  )") == "a=(1 2)");
    CHECK(dict_roundtrip("") == "");
    CHECK(dict_roundtrip("a=1,") == "<fail>");
    CHECK(dict_roundtrip("a=1,,b=2") == "<fail>");
    CHECK(dict_roundtrip("A=1") == "<fail>");
    CHECK(dict_roundtrip("a=1 b=2") == "<fail>");
    CHECK(dict_roundtrip("a=(1 2") == "<fail>");
    CHECK(dict_roundtrip("a=(1,2)") == "<fail>");
    CHECK(dict_roundtrip("\ta=1") == "<fail>");  // only SP is trimmed at the edges
    CHECK(dict_roundtrip("a=\"caf\xc3\xa9\"") == "<fail>");
    CHECK(dict_roundtrip("a=@1659578233") == "<fail>");  // Dates are not supported
}

TEST_CASE("bare items: numbers, strings, tokens, booleans") {
    CHECK(item_roundtrip("42") == "42");
    CHECK(item_roundtrip("-0") == "0");
    CHECK(item_roundtrip("999999999999999") == "999999999999999");
    CHECK(item_roundtrip("1000000000000000") == "<fail>");
    CHECK(item_roundtrip("1.5") == "1.5");
    CHECK(item_roundtrip("-1.250") == "-1.25");
    CHECK(item_roundtrip("0.000") == "0.0");
    CHECK(item_roundtrip("123456789012.123") == "123456789012.123");
    CHECK(item_roundtrip("1234567890123.1") == "<fail>");
    CHECK(item_roundtrip("1.1234") == "<fail>");
    CHECK(item_roundtrip("1.") == "<fail>");
    CHECK(item_roundtrip("-") == "<fail>");
    CHECK(item_roundtrip(R"("a\"b\\c")") == R"("a\"b\\c")");
    CHECK(item_roundtrip(R"("a\nb")") == "<fail>");
    CHECK(item_roundtrip("\"unterminated") == "<fail>");
    CHECK(item_roundtrip("\"tab\there\"") == "<fail>");
    CHECK(item_roundtrip("foo/bar:baz*") == "foo/bar:baz*");
    CHECK(item_roundtrip("*tok") == "*tok");
    CHECK(item_roundtrip("?1;a;b=?0") == "?1;a;b=?0");
    CHECK(item_roundtrip("?2") == "<fail>");
    CHECK(item_roundtrip("\"https://signature-agent.test\"") == "\"https://signature-agent.test\"");
    CHECK(item_roundtrip("\"x\";key=\"y\";req") == "\"x\";key=\"y\";req");
    CHECK(item_roundtrip("\"x\" ;a") == "<fail>");
    CHECK(item_roundtrip("\"x\"; a=1") == "\"x\";a=1");
    CHECK(item_roundtrip("1 2") == "<fail>");
}

TEST_CASE("serialization refuses values that are not structured") {
    std::string out;
    CHECK_FALSE(append_bare_item(out, BareItem::string("line\nbreak")));
    CHECK_FALSE(append_bare_item(out, BareItem::token("1abc")));
    CHECK_FALSE(append_bare_item(out, BareItem::number(1'000'000'000'000'000)));
    Parameters bad_key = {{"Upper", BareItem::boolean(true)}};
    CHECK_FALSE(append_params(out, bad_key));
    CHECK(valid_key("sig1"));
    CHECK(valid_key("*a.b_c-d"));
    CHECK_FALSE(valid_key("1sig"));
    CHECK_FALSE(valid_key(""));
    CHECK(valid_string("https://a.example/x?y=\"z\""));
    CHECK_FALSE(valid_string("caf\xc3\xa9"));
    out.clear();
    append_string(out, R"(a"b\c)");
    CHECK(out == R"("a\"b\\c")");
}
