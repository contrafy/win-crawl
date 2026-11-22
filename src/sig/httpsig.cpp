#include "sig/httpsig.h"

#include "sig/base64.h"
#include "sig/crypto.h"

#include <charconv>

namespace wc::sig {
namespace {

constexpr char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (to_lower(a[i]) != to_lower(b[i])) return false;
    }
    return true;
}

std::string_view trim_ows(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

void append_lower(std::string& out, std::string_view s) {
    for (const char c : s) out.push_back(to_lower(c));
}

// RFC 9421 §2.1: every field line with this name, trimmed, joined with ", ".
bool combined_field(const Message& msg, std::string_view name, std::string& out) {
    out.clear();
    bool found = false;
    for (const Field& f : msg.fields) {
        if (!iequals(f.name, name)) continue;
        if (found) out.append(", ");
        out.append(trim_ows(f.value));
        found = true;
    }
    return found;
}

// Values outside VCHAR/SP/HTAB would need the "bs" parameter.
bool base_safe(std::string_view v) {
    for (const char c : v) {
        const auto u = static_cast<unsigned char>(c);
        if ((u < 0x20 && u != '\t') || u >= 0x7F) return false;
    }
    return true;
}

std::string_view path_of(std::string_view target) {
    return target.substr(0, target.find('?'));
}

struct Ctx {
    std::string scratch;
    sfv::Dictionary dict;
    std::string detail;
};

SigError fail(Ctx& ctx, SigError e, std::string why) {
    ctx.detail = std::move(why);
    return e;
}

// RFC 9421 §2.1-2.2: the value of one covered component.
SigError component_value(const Message& msg, const sfv::Item& c, std::string& value, Ctx& ctx) {
    if (c.value.type != sfv::Type::String || c.value.text.empty()) {
        return fail(ctx, SigError::Malformed, "component identifier is not a non-empty string");
    }
    const std::string& name = c.value.text;
    for (const char ch : name) {
        if (ch >= 'A' && ch <= 'Z') return fail(ctx, SigError::Malformed, "component name \"" + name + "\" is not lowercase");
    }
    bool req = false;
    const std::string* key = nullptr;
    for (const auto& [pname, pvalue] : c.params) {
        if (pname == "req" && pvalue.is_true()) {
            req = true;
        } else if (pname == "key" && pvalue.type == sfv::Type::String && name[0] != '@') {
            key = &pvalue.text;
        } else {
            return fail(ctx, SigError::UnsupportedComponent, "unsupported component parameter \"" + pname + "\" on \"" + name + "\"");
        }
    }
    const Message* src = &msg;
    if (req) {
        if (msg.request == nullptr) return fail(ctx, SigError::MissingComponent, "\"" + name + "\";req without a request");
        src = msg.request;
    }
    value.clear();
    auto need = [&](std::string_view v) {
        return v.empty() ? fail(ctx, SigError::MissingComponent, "message has no " + name) : SigError::None;
    };
    if (name[0] == '@') {
        if (name == "@method") {
            if (const SigError e = need(src->method); e != SigError::None) return e;
            value.append(src->method);
        } else if (name == "@authority") {
            if (const SigError e = need(src->authority); e != SigError::None) return e;
            append_lower(value, src->authority);
        } else if (name == "@scheme") {
            if (const SigError e = need(src->scheme); e != SigError::None) return e;
            append_lower(value, src->scheme);
        } else if (name == "@target-uri") {
            if (src->scheme.empty() || src->authority.empty() || src->target.empty()) {
                return fail(ctx, SigError::MissingComponent, "message has no @target-uri");
            }
            append_lower(value, src->scheme);
            value.append("://");
            append_lower(value, src->authority);
            value.append(src->target);
        } else if (name == "@request-target") {
            if (const SigError e = need(src->target); e != SigError::None) return e;
            value.append(src->target);
        } else if (name == "@path") {
            if (const SigError e = need(src->target); e != SigError::None) return e;
            value.append(path_of(src->target));
        } else if (name == "@query") {
            if (const SigError e = need(src->target); e != SigError::None) return e;
            const size_t q = src->target.find('?');
            // RFC 9421 §2.2.7: an absent query is "?".
            value.append(q == std::string_view::npos ? std::string_view("?") : src->target.substr(q));
        } else if (name == "@status") {
            if (req || src->status < 100 || src->status > 999) {
                return fail(ctx, SigError::MissingComponent, "@status is only defined for responses");
            }
            char buf[4];
            const auto r = std::to_chars(buf, buf + sizeof buf, src->status);
            value.append(buf, r.ptr);
        } else if (name == "@signature-params") {
            return fail(ctx, SigError::Malformed, "@signature-params cannot be covered");
        } else {
            return fail(ctx, SigError::UnsupportedComponent, "unsupported derived component " + name);
        }
    } else {
        if (!combined_field(*src, name, ctx.scratch)) {
            return fail(ctx, SigError::MissingComponent, "message has no " + name + " field");
        }
        if (key == nullptr) {
            value = ctx.scratch;
        } else {
            if (!sfv::parse_dictionary(ctx.scratch, ctx.dict)) {
                return fail(ctx, SigError::Malformed, name + " is not a structured dictionary");
            }
            const sfv::Member* m = sfv::find(ctx.dict, *key);
            if (m == nullptr) return fail(ctx, SigError::MissingComponent, name + " has no member \"" + *key + "\"");
            if (!sfv::append_member_value(value, *m)) return fail(ctx, SigError::Malformed, "cannot serialize " + name);
        }
    }
    if (!base_safe(value)) {
        return fail(ctx, SigError::UnsupportedComponent, name + " has a value outside printable ASCII");
    }
    return SigError::None;
}

SigError base_impl(const Message& msg, const sfv::InnerList& covered, std::string& out, Ctx& ctx) {
    out.clear();
    std::vector<std::string> seen;
    std::string id;
    std::string value;
    for (const sfv::Item& c : covered.items) {
        if (const SigError e = component_value(msg, c, value, ctx); e != SigError::None) return e;
        id.clear();
        if (!sfv::append_item(id, c)) return fail(ctx, SigError::Malformed, "cannot serialize a component identifier");
        for (const std::string& s : seen) {
            if (s == id) return fail(ctx, SigError::DuplicateComponent, id + " is covered twice");
        }
        seen.push_back(id);
        out.append(id);
        out.append(": ");
        out.append(value);
        out.push_back('\n');
    }
    out.append("\"@signature-params\": ");
    if (!sfv::append_inner_list(out, covered)) return fail(ctx, SigError::Malformed, "cannot serialize the signature parameters");
    return SigError::None;
}

bool covers_bare(const sfv::InnerList& covered, std::string_view name) {
    for (const sfv::Item& c : covered.items) {
        if (c.value.type == sfv::Type::String && c.value.text == name && c.params.empty()) return true;
    }
    return false;
}

// Web Bot Auth: the Signature-Agent URL this signature covers.
SigError check_agent(const Message& msg, const sfv::InnerList& covered, const VerifyPolicy& policy,
                     SignatureResult& r, Ctx& ctx) {
    std::string text;
    if (!combined_field(msg, "signature-agent", text)) {
        return policy.require_agent ? fail(ctx, SigError::Profile, "no Signature-Agent header") : SigError::None;
    }
    if (!text.empty() && text.front() == '"') {
        // draft-meunier-http-message-signatures-directory-03 form: one sf-string.
        sfv::Item item;
        if (!sfv::parse_item(text, item) || item.value.type != sfv::Type::String || !item.params.empty()) {
            return fail(ctx, SigError::Malformed, "Signature-Agent is not a structured string");
        }
        if (!covers_bare(covered, "signature-agent")) {
            return fail(ctx, SigError::Profile, "signature does not cover \"signature-agent\"");
        }
        r.agent = item.value.text;
        r.agent_legacy = true;
    } else {
        // draft-ietf-webbotauth-httpsig-protocol-01: a dictionary, one member per signature.
        sfv::Dictionary dict;
        if (!sfv::parse_dictionary(text, dict)) return fail(ctx, SigError::Malformed, "Signature-Agent is not a structured dictionary");
        const std::string* key = nullptr;
        int count = 0;
        for (const sfv::Item& c : covered.items) {
            if (c.value.type != sfv::Type::String || c.value.text != "signature-agent") continue;
            ++count;
            if (c.params.size() == 1 && c.params[0].first == "key" && c.params[0].second.type == sfv::Type::String) {
                key = &c.params[0].second.text;
            }
        }
        if (count != 1 || key == nullptr) {
            return fail(ctx, SigError::Profile, "signature must cover exactly one \"signature-agent\";key=<member>");
        }
        const sfv::Member* m = sfv::find(dict, *key);
        if (m == nullptr) return fail(ctx, SigError::MissingComponent, "Signature-Agent has no member \"" + *key + "\"");
        if (m->is_list || m->item.value.type != sfv::Type::String || !m->item.params.empty()) {
            return fail(ctx, SigError::Profile, "Signature-Agent member \"" + *key + "\" is not a plain string");
        }
        r.agent = m->item.value.text;
    }
    if (!r.agent.starts_with("https://")) return fail(ctx, SigError::Profile, "Signature-Agent is not an https URL");
    return SigError::None;
}

SigError verify_one(const Message& msg, const sfv::Member& input, const sfv::Dictionary& sigs,
                    const std::vector<PublicJwk>& keys, const VerifyPolicy& policy, SignatureResult& r, Ctx& ctx) {
    if (!input.is_list) return fail(ctx, SigError::Malformed, "Signature-Input member is not an inner list");
    const sfv::InnerList& covered = input.list;

    bool has_created = false, has_expires = false, has_keyid = false, has_alg = false, has_tag = false;
    for (const auto& [name, v] : covered.params) {
        if (name == "created" || name == "expires") {
            if (v.type != sfv::Type::Integer || v.integer < 0) return fail(ctx, SigError::BadParameters, name + " is not a timestamp");
            (name == "created" ? r.created : r.expires) = v.integer;
            (name == "created" ? has_created : has_expires) = true;
        } else if (name == "keyid" || name == "alg" || name == "nonce" || name == "tag") {
            if (v.type != sfv::Type::String) return fail(ctx, SigError::BadParameters, name + " is not a string");
            if (name == "keyid") {
                r.keyid = v.text;
                has_keyid = true;
            } else if (name == "alg") {
                r.alg = v.text;
                has_alg = true;
            } else if (name == "nonce") {
                r.nonce = v.text;
            } else {
                r.tag = v.text;
                has_tag = true;
            }
        }
    }

    std::string_view want_tag;
    if (policy.profile == Profile::WebBotAuth) want_tag = "web-bot-auth";
    if (policy.profile == Profile::Directory) want_tag = "http-message-signatures-directory";
    if (!want_tag.empty()) {
        if (!has_tag || r.tag != want_tag) return fail(ctx, SigError::Profile, "tag is not \"" + std::string(want_tag) + "\"");
        if (!has_created || !has_expires) return fail(ctx, SigError::Profile, "created and expires are required");
        if (!has_keyid) return fail(ctx, SigError::Profile, "keyid is required");
    }
    if (has_created && has_expires && r.created > r.expires) {
        return fail(ctx, SigError::BadParameters, "created is after expires");
    }
    if (has_created && r.created > policy.now + policy.clock_skew) return fail(ctx, SigError::NotYetValid, "created is in the future");
    if (has_expires && policy.now > r.expires + policy.clock_skew) return fail(ctx, SigError::Expired, "signature expired");

    if (policy.profile == Profile::WebBotAuth) {
        if (!covers_bare(covered, "@authority") && !covers_bare(covered, "@target-uri")) {
            return fail(ctx, SigError::Profile, "signature covers neither @authority nor @target-uri");
        }
        if (const SigError e = check_agent(msg, covered, policy, r, ctx); e != SigError::None) return e;
    } else if (policy.profile == Profile::Directory) {
        bool authority_req = false;
        for (const sfv::Item& c : covered.items) {
            if (c.value.type == sfv::Type::String && c.value.text == "@authority" && c.params.size() == 1 &&
                c.params[0].first == "req" && c.params[0].second.is_true()) {
                authority_req = true;
            }
        }
        if (!authority_req) return fail(ctx, SigError::Profile, "directory signature does not cover \"@authority\";req");
        if (policy.require_content_digest && !covers_bare(covered, "content-digest")) {
            return fail(ctx, SigError::Profile, "directory signature does not cover content-digest");
        }
    }

    if (has_alg && r.alg != "ed25519") return fail(ctx, SigError::UnsupportedAlgorithm, "alg \"" + r.alg + "\" is not ed25519");
    const PublicJwk* key = has_keyid ? find_key(keys, r.keyid) : (keys.size() == 1 ? &keys[0] : nullptr);
    if (key == nullptr) return fail(ctx, SigError::UnknownKey, "no key for keyid \"" + r.keyid + "\"");

    const sfv::Member* sm = sfv::find(sigs, r.label);
    if (sm == nullptr || sm->is_list || sm->item.value.type != sfv::Type::ByteSequence) {
        return fail(ctx, SigError::Malformed, "no Signature byte sequence for label \"" + r.label + "\"");
    }
    const std::string& sig = sm->item.value.text;
    if (sig.size() != kEd25519SignatureSize) return fail(ctx, SigError::BadSignature, "signature is not 64 bytes");

    if (const SigError e = base_impl(msg, covered, r.base, ctx); e != SigError::None) return e;
    if (!ed25519_verify(key->x.data(), r.base.data(), r.base.size(), reinterpret_cast<const uint8_t*>(sig.data()))) {
        return fail(ctx, SigError::BadSignature, "Ed25519 signature does not verify");
    }
    return SigError::None;
}

}  // namespace

const char* to_string(SigError e) {
    switch (e) {
    case SigError::None: return "valid";
    case SigError::NoSignature: return "no signature";
    case SigError::Malformed: return "malformed";
    case SigError::MissingComponent: return "missing component";
    case SigError::UnsupportedComponent: return "unsupported component";
    case SigError::DuplicateComponent: return "duplicate component";
    case SigError::BadParameters: return "bad parameters";
    case SigError::Profile: return "profile violation";
    case SigError::UnsupportedAlgorithm: return "unsupported algorithm";
    case SigError::UnknownKey: return "unknown key";
    case SigError::NotYetValid: return "not yet valid";
    case SigError::Expired: return "expired";
    case SigError::BadSignature: return "bad signature";
    }
    return "unknown";
}

SigError build_signature_base(const Message& msg, const sfv::InnerList& covered, std::string& out) {
    Ctx ctx;
    return base_impl(msg, covered, out, ctx);
}

SigError verify_signatures(const Message& msg, const std::vector<PublicJwk>& keys, const VerifyPolicy& policy,
                           std::vector<SignatureResult>& out) {
    out.clear();
    std::string inputs_text;
    if (!combined_field(msg, "signature-input", inputs_text)) return SigError::NoSignature;
    sfv::Dictionary inputs;
    sfv::Dictionary sigs;
    std::string sigs_text;
    if (!sfv::parse_dictionary(inputs_text, inputs) ||
        (combined_field(msg, "signature", sigs_text) && !sfv::parse_dictionary(sigs_text, sigs))) {
        SignatureResult r;
        r.error = SigError::Malformed;
        r.detail = "Signature-Input or Signature is not a structured dictionary";
        out.push_back(std::move(r));
        return SigError::Malformed;
    }
    if (inputs.empty()) return SigError::NoSignature;
    SigError first = SigError::None;
    Ctx ctx;
    for (const sfv::Member& m : inputs) {
        SignatureResult r;
        r.label = m.key;
        ctx.detail.clear();
        r.error = verify_one(msg, m, sigs, keys, policy, r, ctx);
        r.detail = ctx.detail;
        if (first == SigError::None) first = r.error;
        out.push_back(std::move(r));
    }
    return first;
}

std::string content_digest(std::string_view body) {
    uint8_t digest[kSha256Size];
    if (!sha256(body.data(), body.size(), digest)) return {};
    std::string out = "sha-256=:";
    append_base64(out, digest, sizeof digest);
    out.push_back(':');
    return out;
}

bool verify_directory(const Message& response, std::string_view body, const VerifyPolicy& policy,
                      DirectoryResult& out) {
    out = {};
    auto problem = [&](std::string why) {
        if (out.problem.empty()) out.problem = std::move(why);
        return false;
    };
    if (response.status != 200) return problem("status is not 200");
    std::string text;
    if (!combined_field(response, "content-type", text)) return problem("no Content-Type");
    const std::string_view media = trim_ows(std::string_view(text).substr(0, text.find(';')));
    if (!iequals(media, kDirectoryMediaType)) return problem("Content-Type is not " + std::string(kDirectoryMediaType));
    if (const JwkError e = parse_key_set(body, out.keys); e != JwkError::None) return problem(std::string("body: ") + to_string(e));
    if (out.keys.empty()) return problem("the directory has no Ed25519 keys");
    for (const PublicJwk& k : out.keys) {
        if (k.has_private) return problem("key " + k.thumbprint + " publishes its private part (\"d\")");
        if (!k.kid.empty() && k.kid != k.thumbprint) return problem("kid \"" + k.kid + "\" is not the JWK thumbprint " + k.thumbprint);
    }
    if (combined_field(response, "content-digest", text)) {
        sfv::Dictionary dict;
        const sfv::Member* m = sfv::parse_dictionary(text, dict) ? sfv::find(dict, "sha-256") : nullptr;
        uint8_t digest[kSha256Size];
        if (m == nullptr || m->is_list || m->item.value.type != sfv::Type::ByteSequence) return problem("Content-Digest has no sha-256 byte sequence");
        if (!sha256(body.data(), body.size(), digest) || m->item.value.text != std::string_view(reinterpret_cast<const char*>(digest), sizeof digest)) {
            return problem("Content-Digest does not match the body");
        }
    } else if (policy.require_content_digest) {
        return problem("no Content-Digest");
    }
    VerifyPolicy p = policy;
    p.profile = Profile::Directory;
    verify_signatures(response, out.keys, p, out.signatures);
    out.proven.assign(out.keys.size(), false);
    for (const SignatureResult& r : out.signatures) {
        if (r.error != SigError::None) continue;
        if (const PublicJwk* k = find_key(out.keys, r.keyid)) out.proven[static_cast<size_t>(k - out.keys.data())] = true;
    }
    for (size_t i = 0; i < out.keys.size(); ++i) {
        if (out.proven[i]) continue;
        std::string why = "key " + out.keys[i].thumbprint + " has no valid directory signature";
        for (const SignatureResult& r : out.signatures) {
            if (r.error != SigError::None && (r.keyid == out.keys[i].thumbprint || r.keyid.empty())) {
                why += " (" + r.label + ": " + to_string(r.error) + ": " + r.detail + ")";
                break;
            }
        }
        return problem(std::move(why));
    }
    return true;
}

bool parse_http_message(std::string_view text, Message& msg, std::string_view& body) {
    msg.fields.clear();
    body = {};
    size_t pos = 0;
    bool first = true;
    while (pos < text.size()) {
        const size_t nl = text.find('\n', pos);
        std::string_view line = text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? text.size() : nl + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) {
            body = text.substr(pos);
            return true;
        }
        const size_t colon = line.find(':');
        const size_t sp = line.find(' ');
        if (first) {
            first = false;
            if (line.starts_with("HTTP/")) {
                if (sp == std::string_view::npos || sp + 4 > line.size()) return false;
                int status = 0;
                const auto r = std::from_chars(line.data() + sp + 1, line.data() + sp + 4, status);
                if (r.ec != std::errc() || r.ptr != line.data() + sp + 4 || status < 100) return false;
                msg.status = status;
                continue;
            }
            if (colon == std::string_view::npos || (sp != std::string_view::npos && sp < colon)) {
                if (sp == 0 || sp == std::string_view::npos) return false;
                msg.method = line.substr(0, sp);
                std::string_view target = line.substr(sp + 1);
                target = target.substr(0, target.find(' '));
                const size_t scheme_end = target.find("://");
                if (scheme_end != std::string_view::npos && target[0] != '/') {
                    msg.scheme = target.substr(0, scheme_end);
                    target.remove_prefix(scheme_end + 3);
                    const size_t slash = target.find('/');
                    if (slash == std::string_view::npos) {
                        if (target.find('?') != std::string_view::npos) return false;
                        msg.authority = target;
                        target = "/";
                    } else {
                        msg.authority = target.substr(0, slash);
                        target.remove_prefix(slash);
                    }
                }
                if (target.empty() || target[0] != '/') return false;
                msg.target = target;
                continue;
            }
        }
        if (line.front() == ' ' || line.front() == '\t') return false;  // obs-fold
        if (colon == std::string_view::npos || colon == 0) return false;
        const std::string_view name = line.substr(0, colon);
        if (name.find_first_of(" \t") != std::string_view::npos) return false;
        const std::string_view value = trim_ows(line.substr(colon + 1));
        msg.fields.push_back({name, value});
        if (msg.authority.empty() && iequals(name, "host")) msg.authority = value;
    }
    return true;
}

}  // namespace wc::sig
