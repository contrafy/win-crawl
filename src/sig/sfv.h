#pragma once
// Structured Field Values (RFC 9651, the RFC 8941 types): the parser and
// serializer behind Signature-Input, Signature, Signature-Agent and
// Content-Digest. Dates and Display Strings (RFC 9651 additions) are not
// supported and fail parsing; none of these fields uses them.
//
// Parsing follows RFC 9651 §4.2 exactly (top-level SP trimming, OWS between
// members, last duplicate key wins in its original position). Serializing a
// parsed value gives its canonical form, which is what RFC 9421 signs.

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace wc::sig::sfv {

enum class Type : uint8_t { Integer, Decimal, String, Token, ByteSequence, Boolean };

struct BareItem {
    Type type = Type::Boolean;
    int64_t integer = 0;  // Integer value; Decimal value in thousandths; Boolean 0/1
    std::string text;     // String/Token text, or the decoded Byte Sequence

    static BareItem boolean(bool b) { return {Type::Boolean, b ? 1 : 0, {}}; }
    static BareItem number(int64_t v) { return {Type::Integer, v, {}}; }
    static BareItem string(std::string_view s) { return {Type::String, 0, std::string(s)}; }
    static BareItem token(std::string_view s) { return {Type::Token, 0, std::string(s)}; }
    static BareItem bytes(std::string_view b) { return {Type::ByteSequence, 0, std::string(b)}; }

    bool is_true() const { return type == Type::Boolean && integer == 1; }
    bool operator==(const BareItem&) const = default;
};

using Parameters = std::vector<std::pair<std::string, BareItem>>;

struct Item {
    BareItem value;
    Parameters params;
    bool operator==(const Item&) const = default;
};

struct InnerList {
    std::vector<Item> items;
    Parameters params;
    bool operator==(const InnerList&) const = default;
};

// A Dictionary or List member: an Item, or an Inner List when `is_list`.
struct Member {
    std::string key;  // empty for List members
    bool is_list = false;
    Item item;
    InnerList list;
    bool operator==(const Member&) const = default;
};

using Dictionary = std::vector<Member>;

// Whole-field parsers. `field` is the combined field value (all lines joined
// with ", "); bytes outside ASCII fail. On failure the output is unspecified.
bool parse_dictionary(std::string_view field, Dictionary& out);
bool parse_item(std::string_view field, Item& out);

const Member* find(const Dictionary& dict, std::string_view key);
const BareItem* find(const Parameters& params, std::string_view key);

// True if `s` serializes as a String (printable ASCII only).
bool valid_string(std::string_view s);
// True if `s` is a valid Key ([a-z*][a-z0-9_.*-]*).
bool valid_key(std::string_view s);

// Canonical serialization (RFC 9651 §4.1). Appends to `out`. Values that
// cannot be serialized (a String with control characters, an invalid Key or
// Token, an out-of-range number) make the call return false; what was appended
// is then unspecified.
bool append_bare_item(std::string& out, const BareItem& item);
bool append_params(std::string& out, const Parameters& params);
bool append_item(std::string& out, const Item& item);
bool append_inner_list(std::string& out, const InnerList& list);
// The member's value (Item or Inner List, with parameters), without the key.
bool append_member_value(std::string& out, const Member& member);
bool append_dictionary(std::string& out, const Dictionary& dict);
// `"` + s with `"` and `\` escaped + `"`; `s` must satisfy valid_string().
void append_string(std::string& out, std::string_view s);

}  // namespace wc::sig::sfv
