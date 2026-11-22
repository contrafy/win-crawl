#include "sig/sfv.h"

#include "sig/base64.h"

#include <charconv>

namespace wc::sig::sfv {
namespace {

constexpr bool is_digit(char c) { return c >= '0' && c <= '9'; }
constexpr bool is_lcalpha(char c) { return c >= 'a' && c <= 'z'; }
constexpr bool is_alpha(char c) { return is_lcalpha(c) || (c >= 'A' && c <= 'Z'); }

// RFC 9110 tchar.
constexpr bool is_tchar(char c) {
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+':
    case '-': case '.': case '^': case '_': case '`': case '|': case '~':
        return true;
    default:
        return is_alpha(c) || is_digit(c);
    }
}

constexpr bool is_key_char(char c) {
    return is_lcalpha(c) || is_digit(c) || c == '_' || c == '-' || c == '.' || c == '*';
}

constexpr bool is_b64_char(char c) {
    return is_alpha(c) || is_digit(c) || c == '+' || c == '/' || c == '=';
}

constexpr int64_t kMaxInteger = 999'999'999'999'999;
constexpr int64_t kMaxDecimalThousandths = 999'999'999'999'999;  // 12 integer + 3 fraction digits

class Parser {
public:
    explicit Parser(std::string_view s) : s_(s) {}

    bool empty() const { return s_.empty(); }
    char peek() const { return s_.empty() ? '\0' : s_.front(); }
    void skip_sp() {
        while (!s_.empty() && s_.front() == ' ') s_.remove_prefix(1);
    }
    void skip_ows() {
        while (!s_.empty() && (s_.front() == ' ' || s_.front() == '\t')) s_.remove_prefix(1);
    }
    bool consume(char c) {
        if (s_.empty() || s_.front() != c) return false;
        s_.remove_prefix(1);
        return true;
    }

    bool key(std::string& out) {
        if (s_.empty() || !(is_lcalpha(s_.front()) || s_.front() == '*')) return false;
        size_t n = 1;
        while (n < s_.size() && is_key_char(s_[n])) ++n;
        out.assign(s_.substr(0, n));
        s_.remove_prefix(n);
        return true;
    }

    bool bare_item(BareItem& out) {
        const char c = peek();
        if (c == '-' || is_digit(c)) return number(out);
        if (c == '"') return string(out);
        if (is_alpha(c) || c == '*') return token(out);
        if (c == ':') return bytes(out);
        if (c == '?') return boolean(out);
        return false;
    }

    bool params(Parameters& out) {
        out.clear();
        std::string k;
        while (consume(';')) {
            skip_sp();
            if (!key(k)) return false;
            BareItem v = BareItem::boolean(true);
            if (consume('=') && !bare_item(v)) return false;
            set(out, k, std::move(v));
        }
        return true;
    }

    bool item(Item& out) { return bare_item(out.value) && params(out.params); }

    bool inner_list(InnerList& out) {
        if (!consume('(')) return false;
        out.items.clear();
        while (!s_.empty()) {
            skip_sp();
            if (consume(')')) return params(out.params);
            Item it;
            if (!item(it)) return false;
            out.items.push_back(std::move(it));
            if (peek() != ' ' && peek() != ')') return false;
        }
        return false;
    }

    bool item_or_inner_list(Member& m) {
        m.is_list = peek() == '(';
        if (m.is_list) {
            m.item = {};
            return inner_list(m.list);
        }
        m.list = {};
        return item(m.item);
    }

    // After a member: OWS, then end or "," OWS and another member.
    // Returns 1 to continue, 0 at the end, -1 on error.
    int next_member() {
        skip_ows();
        if (s_.empty()) return 0;
        if (!consume(',')) return -1;
        skip_ows();
        return s_.empty() ? -1 : 1;
    }

private:
    template <typename T>
    static void set(std::vector<std::pair<std::string, T>>& v, const std::string& k, T&& value) {
        for (auto& [name, existing] : v) {
            if (name == k) {
                existing = std::forward<T>(value);
                return;
            }
        }
        v.emplace_back(k, std::forward<T>(value));
    }

    bool number(BareItem& out) {
        bool neg = consume('-');
        if (!is_digit(peek())) return false;
        size_t n = 0;
        size_t dot = std::string_view::npos;
        while (n < s_.size()) {
            const char c = s_[n];
            if (is_digit(c)) {
                ++n;
            } else if (c == '.' && dot == std::string_view::npos) {
                if (n > 12) return false;
                dot = n++;
            } else {
                break;
            }
            if (dot == std::string_view::npos ? n > 15 : n > 16) return false;
        }
        const std::string_view text = s_.substr(0, n);
        s_.remove_prefix(n);
        int64_t v = 0;
        if (dot == std::string_view::npos) {
            std::from_chars(text.data(), text.data() + text.size(), v);
            out = BareItem::number(neg ? -v : v);
            return true;
        }
        const size_t frac = text.size() - dot - 1;
        if (frac == 0 || frac > 3) return false;
        for (const char c : text) {
            if (c != '.') v = v * 10 + (c - '0');
        }
        for (size_t i = frac; i < 3; ++i) v *= 10;
        out.type = Type::Decimal;
        out.integer = neg ? -v : v;
        out.text.clear();
        return true;
    }

    bool string(BareItem& out) {
        if (!consume('"')) return false;
        out.type = Type::String;
        out.integer = 0;
        out.text.clear();
        while (!s_.empty()) {
            const char c = s_.front();
            s_.remove_prefix(1);
            if (c == '\\') {
                if (s_.empty() || (s_.front() != '"' && s_.front() != '\\')) return false;
                out.text.push_back(s_.front());
                s_.remove_prefix(1);
            } else if (c == '"') {
                return true;
            } else if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7F) {
                return false;
            } else {
                out.text.push_back(c);
            }
        }
        return false;
    }

    bool token(BareItem& out) {
        size_t n = 1;  // first char checked by bare_item()
        while (n < s_.size() && (is_tchar(s_[n]) || s_[n] == ':' || s_[n] == '/')) ++n;
        out.type = Type::Token;
        out.integer = 0;
        out.text.assign(s_.substr(0, n));
        s_.remove_prefix(n);
        return true;
    }

    bool bytes(BareItem& out) {
        consume(':');
        const size_t end = s_.find(':');
        if (end == std::string_view::npos) return false;
        const std::string_view b64 = s_.substr(0, end);
        s_.remove_prefix(end + 1);
        for (const char c : b64) {
            if (!is_b64_char(c)) return false;
        }
        out.type = Type::ByteSequence;
        out.integer = 0;
        out.text.clear();
        return decode_base64(b64, out.text);
    }

    bool boolean(BareItem& out) {
        consume('?');
        if (consume('1')) {
            out = BareItem::boolean(true);
            return true;
        }
        if (consume('0')) {
            out = BareItem::boolean(false);
            return true;
        }
        return false;
    }

    std::string_view s_;
};

bool ascii_only(std::string_view s) {
    for (const char c : s) {
        if (static_cast<unsigned char>(c) >= 0x80) return false;
    }
    return true;
}

}  // namespace

bool parse_dictionary(std::string_view field, Dictionary& out) {
    out.clear();
    if (!ascii_only(field)) return false;
    Parser p(field);
    p.skip_sp();
    while (!p.empty()) {
        Member m;
        if (!p.key(m.key)) return false;
        if (p.consume('=')) {
            if (!p.item_or_inner_list(m)) return false;
        } else {
            m.item.value = BareItem::boolean(true);
            if (!p.params(m.item.params)) return false;
        }
        bool replaced = false;
        for (Member& existing : out) {
            if (existing.key == m.key) {
                existing = std::move(m);
                replaced = true;
                break;
            }
        }
        if (!replaced) out.push_back(std::move(m));
        const int next = p.next_member();
        if (next < 0) return false;
        if (next == 0) break;
    }
    p.skip_sp();
    return p.empty();
}

bool parse_item(std::string_view field, Item& out) {
    if (!ascii_only(field)) return false;
    Parser p(field);
    p.skip_sp();
    if (!p.item(out)) return false;
    p.skip_sp();
    return p.empty();
}

const Member* find(const Dictionary& dict, std::string_view key) {
    for (const Member& m : dict) {
        if (m.key == key) return &m;
    }
    return nullptr;
}

const BareItem* find(const Parameters& params, std::string_view key) {
    for (const auto& [name, value] : params) {
        if (name == key) return &value;
    }
    return nullptr;
}

bool valid_string(std::string_view s) {
    for (const char c : s) {
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7F) return false;
    }
    return true;
}

bool valid_key(std::string_view s) {
    if (s.empty() || !(is_lcalpha(s[0]) || s[0] == '*')) return false;
    for (const char c : s) {
        if (!is_key_char(c)) return false;
    }
    return true;
}

void append_string(std::string& out, std::string_view s) {
    out.push_back('"');
    for (const char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
}

bool append_bare_item(std::string& out, const BareItem& item) {
    char buf[24];
    switch (item.type) {
    case Type::Integer: {
        if (item.integer > kMaxInteger || item.integer < -kMaxInteger) return false;
        const auto r = std::to_chars(buf, buf + sizeof buf, item.integer);
        out.append(buf, r.ptr);
        return true;
    }
    case Type::Decimal: {
        if (item.integer > kMaxDecimalThousandths || item.integer < -kMaxDecimalThousandths) return false;
        const int64_t mag = item.integer < 0 ? -item.integer : item.integer;
        if (item.integer < 0) out.push_back('-');
        const auto r = std::to_chars(buf, buf + sizeof buf, mag / 1000);
        out.append(buf, r.ptr);
        out.push_back('.');
        int64_t frac = mag % 1000;
        // At least one fractional digit, no trailing zeros.
        int digits = 3;
        while (digits > 1 && frac % 10 == 0) {
            frac /= 10;
            --digits;
        }
        char f[3];
        for (int i = digits - 1; i >= 0; --i) {
            f[i] = static_cast<char>('0' + frac % 10);
            frac /= 10;
        }
        out.append(f, static_cast<size_t>(digits));
        return true;
    }
    case Type::String:
        if (!valid_string(item.text)) return false;
        append_string(out, item.text);
        return true;
    case Type::Token: {
        const std::string_view t = item.text;
        if (t.empty() || !(is_alpha(t[0]) || t[0] == '*')) return false;
        for (const char c : t) {
            if (!is_tchar(c) && c != ':' && c != '/') return false;
        }
        out.append(t);
        return true;
    }
    case Type::ByteSequence:
        out.push_back(':');
        append_base64(out, item.text.data(), item.text.size());
        out.push_back(':');
        return true;
    case Type::Boolean:
        out.append(item.integer ? "?1" : "?0");
        return true;
    }
    return false;
}

bool append_params(std::string& out, const Parameters& params) {
    for (const auto& [key, value] : params) {
        if (!valid_key(key)) return false;
        out.push_back(';');
        out.append(key);
        if (!value.is_true()) {
            out.push_back('=');
            if (!append_bare_item(out, value)) return false;
        }
    }
    return true;
}

bool append_item(std::string& out, const Item& item) {
    return append_bare_item(out, item.value) && append_params(out, item.params);
}

bool append_inner_list(std::string& out, const InnerList& list) {
    out.push_back('(');
    for (size_t i = 0; i < list.items.size(); ++i) {
        if (i != 0) out.push_back(' ');
        if (!append_item(out, list.items[i])) return false;
    }
    out.push_back(')');
    return append_params(out, list.params);
}

bool append_member_value(std::string& out, const Member& member) {
    return member.is_list ? append_inner_list(out, member.list) : append_item(out, member.item);
}

bool append_dictionary(std::string& out, const Dictionary& dict) {
    for (size_t i = 0; i < dict.size(); ++i) {
        const Member& m = dict[i];
        if (i != 0) out.append(", ");
        if (!valid_key(m.key)) return false;
        out.append(m.key);
        if (!m.is_list && m.item.value.is_true()) {
            if (!append_params(out, m.item.params)) return false;
        } else {
            out.push_back('=');
            if (!append_member_value(out, m)) return false;
        }
    }
    return true;
}

}  // namespace wc::sig::sfv
