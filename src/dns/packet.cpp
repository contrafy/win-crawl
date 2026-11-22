#include "dns/packet.h"

#include <cstring>

namespace wc::dns {
namespace {

constexpr size_t kMaxNameWire = 255;
// Legit names rarely chain more than two or three pointers; the cap only
// exists to bound hostile pointer loops.
constexpr unsigned kMaxPointerJumps = 16;
constexpr size_t kMaxRecords = 64;

uint8_t ascii_lower(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c + ('a' - 'A')) : c;
}

uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

void write_u16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

// Walks the labels of a possibly compressed name, bounds-checking every byte.
class NameReader {
public:
    enum Result { kMalformed = -1, kEnd = 0, kLabel = 1 };

    NameReader(const uint8_t* data, size_t len, size_t offset) : data_(data), len_(len), pos_(offset) {}

    Result next(const uint8_t*& label, uint8_t& label_len) {
        for (;;) {
            if (pos_ >= len_) return kMalformed;
            const uint8_t b = data_[pos_];
            if ((b & 0xC0) == 0xC0) {
                if (pos_ + 1 >= len_) return kMalformed;
                const size_t target = (static_cast<size_t>(b & 0x3F) << 8) | data_[pos_ + 1];
                if (!jumped_) {
                    end_ = pos_ + 2;
                    jumped_ = true;
                }
                if (++jumps_ > kMaxPointerJumps || target >= len_) return kMalformed;
                pos_ = target;
                continue;
            }
            if (b & 0xC0) return kMalformed;  // 0x40/0x80 label types are obsolete/unassigned
            wire_len_ += 1 + static_cast<size_t>(b);
            if (wire_len_ > kMaxNameWire) return kMalformed;
            if (b == 0) {
                if (!jumped_) end_ = pos_ + 1;
                return kEnd;
            }
            if (pos_ + 1 + b > len_) return kMalformed;
            label = data_ + pos_ + 1;
            label_len = b;
            pos_ += 1 + static_cast<size_t>(b);
            return kLabel;
        }
    }

    // Offset just past the name at its original position; valid after kEnd.
    size_t end() const { return end_; }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_;
    size_t end_ = 0;
    size_t wire_len_ = 0;
    unsigned jumps_ = 0;
    bool jumped_ = false;
};

// Validates the name at `offset`; on success stores the offset following it.
bool skip_name(const uint8_t* data, size_t len, size_t offset, size_t& after) {
    NameReader reader(data, len, offset);
    const uint8_t* label = nullptr;
    uint8_t label_len = 0;
    for (;;) {
        const auto r = reader.next(label, label_len);
        if (r == NameReader::kMalformed) return false;
        if (r == NameReader::kEnd) {
            after = reader.end();
            return true;
        }
    }
}

bool wire_name_equal(const uint8_t* data, size_t len, size_t a, size_t b) {
    if (a == b) return true;
    NameReader ra(data, len, a);
    NameReader rb(data, len, b);
    for (;;) {
        const uint8_t* la = nullptr;
        const uint8_t* lb = nullptr;
        uint8_t na = 0;
        uint8_t nb = 0;
        const auto xa = ra.next(la, na);
        const auto xb = rb.next(lb, nb);
        if (xa == NameReader::kMalformed || xb == NameReader::kMalformed || xa != xb) return false;
        if (xa == NameReader::kEnd) return true;
        if (na != nb) return false;
        for (uint8_t i = 0; i < na; ++i) {
            if (ascii_lower(la[i]) != ascii_lower(lb[i])) return false;
        }
    }
}

bool decode_name(const uint8_t* data, size_t len, size_t offset, Response& out, size_t& after) {
    NameReader reader(data, len, offset);
    const uint8_t* label = nullptr;
    uint8_t label_len = 0;
    size_t text = 0;
    for (;;) {
        const auto r = reader.next(label, label_len);
        if (r == NameReader::kMalformed) return false;
        if (r == NameReader::kEnd) break;
        // A '.' inside a label has no dotted-text form and never matches a
        // name we queried for.
        if (std::memchr(label, '.', label_len) != nullptr) return false;
        if (text != 0) out.qname[text++] = '.';
        // wire_len <= 255 bounds text to 253 characters.
        std::memcpy(out.qname + text, label, label_len);
        text += label_len;
    }
    out.qname[text] = '\0';
    out.qname_len = static_cast<uint8_t>(text);
    after = reader.end();
    return true;
}

struct Record {
    size_t owner;
    size_t rdata;
    uint16_t rdlen;
    uint16_t type;
};

bool alpn_is(const uint8_t* id, size_t len, std::string_view want) {
    return len == want.size() && std::memcmp(id, want.data(), len) == 0;
}

// True when the (already validated) SvcParams in [pos, end) contain `key`.
bool has_svc_key(const uint8_t* p, size_t pos, size_t end, uint16_t key) {
    while (pos < end) {
        const uint16_t k = read_u16(p + pos);
        if (k == key) return true;
        if (k > key) return false;  // keys are strictly increasing
        pos += 4 + read_u16(p + pos + 2);
    }
    return false;
}

// Merges one well-formed HTTPS RR into the selected record (see Response).
void select_https(const HttpsRr& rr, Response& out) {
    bool take = out.https_count == 0;
    if (!take && !out.https.alias_mode()) {
        take = rr.alias_mode() || rr.priority < out.https.priority;
    }
    if (take) out.https = rr;
    ++out.https_count;
}

}  // namespace

size_t build_query(uint16_t id, std::string_view name, uint16_t qtype, uint8_t* out, size_t cap,
                   uint16_t edns_udp_size) {
    if (!name.empty() && name.back() == '.') name.remove_suffix(1);
    if (name.empty() || name.size() > kMaxNameText) return 0;

    const bool edns = edns_udp_size != 0;
    const size_t total = kHeaderSize + name.size() + 2 + 4 + (edns ? kOptRecordSize : 0);
    if (out == nullptr || cap < total) return 0;

    write_u16(out, id);
    write_u16(out + 2, 0x0100);  // RD
    write_u16(out + 4, 1);       // QDCOUNT
    write_u16(out + 6, 0);
    write_u16(out + 8, 0);
    write_u16(out + 10, edns ? 1 : 0);  // ARCOUNT: the OPT record

    uint8_t* p = out + kHeaderSize;
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string_view::npos) dot = name.size();
        const size_t label_len = dot - start;
        if (label_len == 0 || label_len > 63) return 0;
        *p++ = static_cast<uint8_t>(label_len);
        std::memcpy(p, name.data() + start, label_len);
        p += label_len;
        start = dot + 1;
    }
    *p++ = 0;
    write_u16(p, qtype);
    write_u16(p + 2, kClassIn);
    p += 4;
    if (edns) {
        // OPT pseudo-RR (RFC 6891 section 6.1.2): root owner, CLASS = payload
        // size, TTL = extended rcode 0, version 0, DO and Z clear; no options.
        *p++ = 0;
        write_u16(p, kTypeOpt);
        write_u16(p + 2, edns_udp_size);
        write_u16(p + 4, 0);
        write_u16(p + 6, 0);
        write_u16(p + 8, 0);
    }
    return total;
}

bool parse_https_rdata(const uint8_t* p, size_t n, HttpsRr& out) {
    out = HttpsRr{};
    if (p == nullptr || n < 3) return false;  // priority + at least the root name
    out.priority = read_u16(p);

    // TargetName is never compressed (RFC 9460 section 2.2), so a pointer is
    // malformed rather than something to follow.
    size_t pos = 2;
    size_t wire = 0;
    size_t text = 0;
    for (;;) {
        if (pos >= n) return false;
        const uint8_t label_len = p[pos];
        if (label_len & 0xC0) return false;
        wire += 1 + static_cast<size_t>(label_len);
        if (wire > kMaxNameWire) return false;
        if (label_len == 0) {
            ++pos;
            break;
        }
        if (pos + 1 + label_len > n) return false;
        const uint8_t* label = p + pos + 1;
        if (std::memchr(label, '.', label_len) != nullptr) return false;
        if (text != 0) out.target[text++] = '.';
        std::memcpy(out.target + text, label, label_len);  // wire <= 255 bounds text to 253
        text += label_len;
        pos += 1 + static_cast<size_t>(label_len);
    }
    if (text == 0) out.target[text++] = '.';
    out.target[text] = '\0';
    out.target_len = static_cast<uint8_t>(text);
    if (out.alias_mode()) return true;  // AliasMode SvcParams MUST be ignored

    const size_t params = pos;
    size_t mandatory = 0;  // offset of the mandatory value, 0 = absent
    size_t mandatory_len = 0;
    bool alpn = false;
    bool first = true;
    uint16_t prev_key = 0;
    while (pos < n) {
        if (pos + 4 > n) return false;
        const uint16_t key = read_u16(p + pos);
        const uint16_t vlen = read_u16(p + pos + 2);
        pos += 4;
        if (pos + vlen > n) return false;
        if (!first && key <= prev_key) return false;
        first = false;
        prev_key = key;
        const uint8_t* v = p + pos;
        switch (key) {
        case kSvcMandatory:
            if (vlen == 0 || vlen % 2 != 0) return false;
            for (size_t i = 0; i < vlen; i += 2) {
                const uint16_t k = read_u16(v + i);
                // Never lists itself; strictly increasing also excludes duplicates.
                if (k == kSvcMandatory || (i != 0 && k <= read_u16(v + i - 2))) return false;
            }
            mandatory = pos;
            mandatory_len = vlen;
            break;
        case kSvcAlpn:
            if (vlen == 0) return false;
            for (size_t i = 0; i < vlen;) {
                const uint8_t id_len = v[i];
                if (id_len == 0 || i + 1 + id_len > vlen) return false;
                const uint8_t* id = v + i + 1;
                out.alpn_h3 = out.alpn_h3 || alpn_is(id, id_len, "h3");
                out.alpn_h2 = out.alpn_h2 || alpn_is(id, id_len, "h2");
                out.alpn_http11 = out.alpn_http11 || alpn_is(id, id_len, "http/1.1");
                i += 1 + static_cast<size_t>(id_len);
            }
            alpn = true;
            break;
        case kSvcNoDefaultAlpn:
            if (vlen != 0) return false;
            out.no_default_alpn = true;
            break;
        case kSvcPort:
            if (vlen != 2) return false;
            out.port = read_u16(v);
            break;
        case kSvcIpv4Hint:
            if (vlen == 0 || vlen % 4 != 0) return false;
            out.ipv4hint = true;
            break;
        case kSvcEch:
            // ECHConfigList: a u16-length-prefixed vector of 4..65535 bytes
            // that exactly fills the value. The configs are not interpreted.
            if (vlen < 2 + 4 || read_u16(v) != vlen - 2) return false;
            out.ech = true;
            break;
        case kSvcIpv6Hint:
            if (vlen == 0 || vlen % 16 != 0) return false;
            out.ipv6hint = true;
            break;
        default:
            break;  // unknown keys are skipped
        }
        pos += vlen;
    }

    // Self-consistency (RFC 9460 sections 7.1.1 and 8).
    if (out.no_default_alpn && !alpn) return false;
    for (size_t i = 0; i < mandatory_len; i += 2) {
        if (!has_svc_key(p, params, n, read_u16(p + mandatory + i))) return false;
    }
    return true;
}

bool parse_response(const uint8_t* data, size_t len, Response& out) {
    out.addr_count = 0;
    out.cname_hops = 0;
    out.https_count = 0;
    out.https_malformed = false;
    out.qname_len = 0;
    out.qname[0] = '\0';
    if (data == nullptr || len < kHeaderSize) return false;

    out.id = read_u16(data);
    const uint16_t flags = read_u16(data + 2);
    out.qr = (flags & 0x8000) != 0;
    out.tc = (flags & 0x0200) != 0;
    out.rd = (flags & 0x0100) != 0;
    out.ra = (flags & 0x0080) != 0;
    out.rcode = static_cast<uint8_t>(flags & 0x000F);
    const uint16_t qdcount = read_u16(data + 4);
    const uint16_t ancount = read_u16(data + 6);
    if (qdcount != 1) return false;

    const size_t qname_off = kHeaderSize;
    size_t pos = 0;
    if (!decode_name(data, len, qname_off, out, pos)) return false;
    if (pos + 4 > len) return false;
    out.qtype = read_u16(data + pos);
    out.qclass = read_u16(data + pos + 2);
    pos += 4;

    Record records[kMaxRecords];
    size_t record_count = 0;
    for (uint16_t i = 0; i < ancount; ++i) {
        const size_t owner = pos;
        size_t after = 0;
        if (!skip_name(data, len, owner, after) || after + 10 > len) {
            if (out.tc) break;  // a truncated answer section is expected with TC
            return false;
        }
        const uint16_t type = read_u16(data + after);
        const uint16_t klass = read_u16(data + after + 2);
        const uint16_t rdlen = read_u16(data + after + 8);
        const size_t rdata = after + 10;
        if (rdata + rdlen > len) {
            if (out.tc) break;
            return false;
        }
        pos = rdata + rdlen;
        if (klass != kClassIn) continue;
        if (type == kTypeA) {
            if (rdlen != 4) return false;
        } else if (type == kTypeCname) {
            size_t target_end = 0;
            if (!skip_name(data, len, rdata, target_end) || target_end > pos) return false;
        } else if (type != kTypeHttps) {
            continue;  // HTTPS rdata is judged per record once its owner is known
        }
        if (record_count < kMaxRecords) records[record_count++] = {owner, rdata, rdlen, type};
    }

    // Follow CNAMEs from the question name until some owner has an RRset of
    // the wanted type.
    const uint16_t want = out.qtype == kTypeHttps ? kTypeHttps : kTypeA;
    size_t current = qname_off;
    for (unsigned hop = 0;; ++hop) {
        bool found_set = false;
        for (size_t r = 0; r < record_count; ++r) {
            const Record& rec = records[r];
            if (rec.type != want || !wire_name_equal(data, len, rec.owner, current)) continue;
            found_set = true;
            if (want == kTypeA) {
                if (out.addr_count < kMaxAddresses) {
                    uint32_t addr;
                    std::memcpy(&addr, data + rec.rdata, 4);  // already network order
                    out.addrs[out.addr_count++] = addr;
                }
            } else {
                HttpsRr rr;
                if (parse_https_rdata(data + rec.rdata, rec.rdlen, rr)) {
                    select_https(rr, out);
                } else {
                    out.https_malformed = true;
                }
            }
        }
        if (found_set || hop == kMaxCnameChain) break;

        size_t next = 0;
        bool found = false;
        for (size_t r = 0; r < record_count && !found; ++r) {
            const Record& rec = records[r];
            if (rec.type == kTypeCname && wire_name_equal(data, len, rec.owner, current)) {
                next = rec.rdata;
                found = true;
            }
        }
        if (!found) break;
        current = next;
        out.cname_hops = static_cast<uint8_t>(hop + 1);
    }
    return true;
}

bool name_equal(std::string_view a, std::string_view b) {
    if (!a.empty() && a.back() == '.') a.remove_suffix(1);
    if (!b.empty() && b.back() == '.') b.remove_suffix(1);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(static_cast<uint8_t>(a[i])) != ascii_lower(static_cast<uint8_t>(b[i]))) return false;
    }
    return true;
}

}  // namespace wc::dns
