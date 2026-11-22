#include "crawl/record.h"

#include "tls/tls.h"

#include <windows.h>

#include <algorithm>
#include <charconv>
#include <limits>

namespace wc::crawl {

namespace {

constexpr size_t kMaxHeaderValue = 64;  // Server and Content-Type are recorded up to this many bytes

bool is_ows(char c) {
    return c == ' ' || c == '\t';
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && is_ows(s.front())) {
        s.remove_prefix(1);
    }
    while (!s.empty() && is_ows(s.back())) {
        s.remove_suffix(1);
    }
    return s;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i];
        char y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x + ('a' - 'A'));
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y + ('a' - 'A'));
        if (x != y) {
            return false;
        }
    }
    return true;
}

// Length of the well-formed UTF-8 sequence starting at s[i] (RFC 3629 §4),
// or 0 if s[i] does not start one.
size_t utf8_length(std::string_view s, size_t i) {
    const auto at = [&](size_t k) { return static_cast<unsigned char>(s[k]); };
    const unsigned char c = at(i);
    size_t len = 0;
    unsigned char lo = 0x80;
    unsigned char hi = 0xBF;  // bounds of the second byte
    if (c >= 0xC2 && c <= 0xDF) {
        len = 2;
    } else if (c >= 0xE0 && c <= 0xEF) {
        len = 3;
        if (c == 0xE0) lo = 0xA0;  // overlong
        if (c == 0xED) hi = 0x9F;  // surrogates
    } else if (c >= 0xF0 && c <= 0xF4) {
        len = 4;
        if (c == 0xF0) lo = 0x90;  // overlong
        if (c == 0xF4) hi = 0x8F;  // beyond U+10FFFF
    } else {
        return 0;
    }
    if (s.size() - i < len) {
        return 0;
    }
    if (at(i + 1) < lo || at(i + 1) > hi) {
        return 0;
    }
    for (size_t k = 2; k < len; ++k) {
        if ((at(i + k) & 0xC0) != 0x80) {
            return 0;
        }
    }
    return len;
}

void append_uint(std::string& out, uint64_t v) {
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof(buf), v);
    out.append(buf, r.ptr);
}

void append_int(std::string& out, int64_t v) {
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof(buf), v);
    out.append(buf, r.ptr);
}

void append_bool(std::string& out, bool v) {
    out.append(v ? "true" : "false");
}

// ,"key":
void key(std::string& out, std::string_view name) {
    out.push_back(',');
    out.push_back('"');
    out.append(name);
    out.append("\":");
}

void opt_bool(std::string& out, std::string_view name, const std::optional<bool>& v) {
    key(out, name);
    if (v) {
        append_bool(out, *v);
    } else {
        out.append("null");
    }
}

void opt_uint(std::string& out, std::string_view name, const std::optional<uint64_t>& v) {
    key(out, name);
    if (v) {
        append_uint(out, *v);
    } else {
        out.append("null");
    }
}

void opt_str(std::string& out, std::string_view name, bool present, std::string_view v) {
    key(out, name);
    if (present) {
        append_json_string(out, v);
    } else {
        out.append("null");
    }
}

// Names are fixed ASCII identifiers (status/error names): no escaping needed.
void opt_name(std::string& out, std::string_view name, const char* v) {
    key(out, name);
    if (v != nullptr) {
        out.push_back('"');
        out.append(v);
        out.push_back('"');
    } else {
        out.append("null");
    }
}

std::string_view unquote(std::string_view v) {
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
        return v.substr(1, v.size() - 2);
    }
    return v;
}

// Index of the next `sep` at or after `i` outside a quoted-string, or s.size().
size_t find_unquoted(std::string_view s, size_t i, char sep) {
    bool quoted = false;
    while (i < s.size()) {
        const char c = s[i];
        if (quoted) {
            if (c == '\\') {
                i += 2;
                continue;
            }
            if (c == '"') quoted = false;
        } else if (c == '"') {
            quoted = true;
        } else if (c == sep) {
            return i;
        }
        ++i;
    }
    return s.size();
}

}  // namespace

void append_json_string(std::string& out, std::string_view text) {
    static constexpr char kHex[] = "0123456789abcdef";
    out.push_back('"');
    size_t i = 0;
    const size_t n = text.size();
    while (i < n) {
        // Copy the run of bytes that need no attention in one append.
        size_t j = i;
        while (j < n) {
            const unsigned char c = static_cast<unsigned char>(text[j]);
            if (c < 0x20 || c == '"' || c == '\\' || c >= 0x80) {
                break;
            }
            ++j;
        }
        out.append(text.data() + i, j - i);
        i = j;
        if (i == n) {
            break;
        }
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c >= 0x80) {
            const size_t len = utf8_length(text, i);
            if (len != 0) {
                out.append(text.data() + i, len);
                i += len;
                continue;
            }
        }
        switch (c) {
        case '"': out.append("\\\""); break;
        case '\\': out.append("\\\\"); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        case '\b': out.append("\\b"); break;
        case '\f': out.append("\\f"); break;
        default:
            out.append("\\u00");
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
            break;
        }
        ++i;
    }
    out.push_back('"');
}

std::string_view truncate_utf8(std::string_view text, size_t max) {
    if (text.size() <= max) {
        return text;
    }
    size_t cut = max;
    // Back off to the start of the sequence text[cut] belongs to.
    while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80) {
        --cut;
    }
    return text.substr(0, cut);
}

bool alt_svc_has_h3(std::string_view value) {
    size_t i = 0;
    while (i < value.size()) {
        while (i < value.size() && (is_ows(value[i]) || value[i] == ',')) {
            ++i;  // OWS and empty list elements
        }
        const size_t start = i;
        while (i < value.size() && value[i] != '=' && value[i] != ',' && value[i] != ';' && !is_ows(value[i])) {
            ++i;
        }
        // alt-value = protocol-id "=" alt-authority; "clear" and junk have no '='.
        const std::string_view id = value.substr(start, i - start);
        if (i < value.size() && value[i] == '=' && (id == "h3" || (id.size() > 3 && id.substr(0, 3) == "h3-"))) {
            return true;
        }
        i = find_unquoted(value, i, ',');
    }
    return false;
}

Hsts parse_hsts(std::string_view value) {
    Hsts h;
    unsigned max_age_seen = 0;
    bool sub_seen = false;
    bool preload_seen = false;
    bool bad = false;
    size_t i = 0;
    while (i < value.size()) {
        const size_t semi = find_unquoted(value, i, ';');
        const std::string_view directive = trim(value.substr(i, semi - i));
        i = semi + 1;
        if (directive.empty()) {
            continue;
        }
        const size_t eq = directive.find('=');
        const std::string_view name = trim(directive.substr(0, eq));
        const bool has_value = eq != std::string_view::npos;
        if (iequals(name, "max-age")) {
            ++max_age_seen;
            const std::string_view v = has_value ? unquote(trim(directive.substr(eq + 1))) : std::string_view{};
            bool digits = !v.empty();
            for (char c : v) {
                digits = digits && c >= '0' && c <= '9';
            }
            if (!digits) {
                bad = true;
                continue;
            }
            uint64_t age = 0;
            const auto r = std::from_chars(v.data(), v.data() + v.size(), age);
            // §6.1.1: delta-seconds that overflow saturate rather than fail.
            h.max_age = r.ec == std::errc::result_out_of_range ? std::numeric_limits<uint64_t>::max() : age;
        } else if (iequals(name, "includeSubDomains")) {
            bad = bad || sub_seen;
            sub_seen = true;
            h.include_subdomains = true;
        } else if (iequals(name, "preload")) {
            bad = bad || preload_seen;
            preload_seen = true;
            h.preload = true;
        }
        // §6.1: unknown directives are ignored.
    }
    h.valid = max_age_seen == 1 && !bad;
    return h;
}

void SiteRecord::clear() {
    url.clear();
    host.clear();
    seed_https = false;
    dns = nullptr;
    has_ip = false;
    ip = 0;
    ip_dup.reset();
    cf_ip.reset();
    https_rr = HttpsRr{};
    robots_status.reset();
    robots_error = nullptr;
    robots_allowed.reset();
    fetch = nullptr;
    status.reset();
    redirects = 0;
    has_final = false;
    final_https = false;
    final_url.clear();
    has_content_type = false;
    content_type.clear();
    bytes.reset();
    links.reset();
    alt_svc_h3.reset();
    hsts.reset();
    hsts_max_age.reset();
    hsts_sub = false;
    hsts_preload = false;
    has_server = false;
    server.clear();
    cf_ray.reset();
    tls.handshake = nullptr;
    tls.protocol = 0;
    tls.cipher.clear();
    tls.group.clear();
    tls.pq.reset();
    tls.resumed.reset();
    ms = 0;
    skip = nullptr;
    wait_ms = 0;
    crawl_delay.reset();
    crawl_delay_ms = 0;
    retry_after.reset();
    retried.reset();
}

void SiteRecord::set_page_reply(const parse::ResponseParser& reply, const parse::Url& reply_url,
                                std::string_view body) {
    const bool https = reply_url.scheme == parse::Scheme::Https;
    status = reply.status();
    has_final = true;
    final_https = https;
    final_url.clear();
    parse::append_to_string(final_url, reply_url);
    has_content_type = reply.has_header("Content-Type");
    const std::string_view type = truncate_utf8(reply.header("Content-Type"), kMaxHeaderValue);
    content_type.assign(type.data(), type.size());
    has_server = reply.has_header("Server");
    const std::string_view srv = truncate_utf8(reply.header("Server"), kMaxHeaderValue);
    server.assign(srv.data(), srv.size());
    bytes = body.size();
    links.reset();

    // Alt-Svc may be split over several header lines.
    bool h3 = false;
    for (size_t i = 0; i < reply.header_count() && !h3; ++i) {
        const parse::HeaderField f = reply.header_at(i);
        h3 = iequals(f.name, "Alt-Svc") && alt_svc_has_h3(f.value);
    }
    alt_svc_h3 = h3;

    // RFC 6797 §8.1: HSTS is ignored over plain http, and only the first
    // header counts.
    hsts.reset();
    hsts_max_age.reset();
    hsts_sub = false;
    hsts_preload = false;
    if (https) {
        hsts = reply.has_header("Strict-Transport-Security");
        if (*hsts) {
            const Hsts h = parse_hsts(reply.header("Strict-Transport-Security"));
            if (h.valid) {
                hsts_max_age = h.max_age;
            }
            hsts_sub = h.include_subdomains;
            hsts_preload = h.preload;
        }
    }
}

void SiteRecord::append_json(std::string& out) const {
    out.append("{\"url\":");
    append_json_string(out, url);
    key(out, "host");
    append_json_string(out, host);
    opt_name(out, "dns", dns);
    key(out, "ip");
    if (has_ip) {
        out.push_back('"');
        const auto* b = reinterpret_cast<const unsigned char*>(&ip);
        for (int i = 0; i < 4; ++i) {
            if (i != 0) out.push_back('.');
            append_uint(out, b[i]);
        }
        out.push_back('"');
    } else {
        out.append("null");
    }
    opt_bool(out, "ip_dup", ip_dup);
    opt_bool(out, "cf_ip", cf_ip);

    key(out, "https_rr");
    if (https_rr.status != nullptr) {
        out.append("{\"status\":\"");
        out.append(https_rr.status);
        out.append("\",\"present\":");
        append_bool(out, https_rr.present);
        out.append(",\"alias\":");
        append_bool(out, https_rr.alias);
        out.append(",\"h3\":");
        append_bool(out, https_rr.h3);
        out.append(",\"h2\":");
        append_bool(out, https_rr.h2);
        out.append(",\"ech\":");
        append_bool(out, https_rr.ech);
        out.push_back('}');
    } else {
        out.append("null");
    }

    key(out, "robots_status");
    if (robots_status) {
        append_int(out, *robots_status);
    } else {
        out.append("null");
    }
    opt_name(out, "robots_error", robots_error);
    opt_bool(out, "robots_allowed", robots_allowed);

    opt_name(out, "fetch", fetch);
    key(out, "status");
    if (status) {
        append_int(out, *status);
    } else {
        out.append("null");
    }
    key(out, "redirects");
    if (fetch != nullptr) {
        append_uint(out, redirects);
    } else {
        out.append("null");
    }
    opt_str(out, "final_url", has_final, final_url);
    opt_bool(out, "https_upgrade", has_final ? std::optional<bool>(!seed_https && final_https) : std::nullopt);

    key(out, "tls");
    if (tls.handshake != nullptr) {
        out.append("{\"handshake\":\"");
        out.append(tls.handshake);
        out.append("\",\"version\":");
        if (tls.protocol != 0) {
            out.push_back('"');
            out.append(tls::protocol_name(tls.protocol));
            out.push_back('"');
        } else {
            out.append("null");
        }
        out.append(",\"cipher\":");
        if (!tls.cipher.empty()) {
            append_json_string(out, tls.cipher);
        } else {
            out.append("null");
        }
        out.append(",\"group\":");
        if (!tls.group.empty()) {
            append_json_string(out, tls.group);
        } else {
            out.append("null");
        }
        opt_bool(out, "pq", tls.pq);
        opt_bool(out, "resumed", tls.resumed);
        out.push_back('}');
    } else {
        out.append("null");
    }

    opt_bool(out, "alt_svc_h3", alt_svc_h3);
    opt_bool(out, "hsts", hsts);
    opt_uint(out, "hsts_max_age", hsts_max_age);
    const bool hsts_on = hsts.value_or(false);
    opt_bool(out, "hsts_sub", hsts_on ? std::optional<bool>(hsts_sub) : std::nullopt);
    opt_bool(out, "hsts_preload", hsts_on ? std::optional<bool>(hsts_preload) : std::nullopt);
    opt_str(out, "server", has_server, server);
    opt_bool(out, "cf_ray", cf_ray);
    opt_str(out, "content_type", has_content_type, content_type);
    opt_uint(out, "bytes", bytes);
    opt_uint(out, "links", links);
    key(out, "ms");
    append_uint(out, ms);
    opt_name(out, "skip", skip);
    key(out, "wait_ms");
    append_uint(out, wait_ms);
    key(out, "crawl_delay");
    if (crawl_delay) {
        char buf[32];
        const auto r = std::to_chars(buf, buf + sizeof(buf), *crawl_delay);  // shortest round-trip form
        out.append(buf, r.ptr);
    } else {
        out.append("null");
    }
    key(out, "crawl_delay_ms");
    append_uint(out, crawl_delay_ms);
    opt_uint(out, "retry_after", retry_after);
    opt_bool(out, "retried", retried);
    out.append("}\n");
}

// ---------------------------------------------------------------- RecordWriter

RecordWriter::~RecordWriter() {
    close();
}

bool RecordWriter::open(const std::string& path, std::string& error) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = "cannot create record file " + path + " (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    file_ = h;
    stop_ = false;
    failed_ = false;
    bytes_ = 0;
    thread_ = std::thread([this] { run(); });
    return true;
}

void RecordWriter::submit(std::string& buffer) {
    if (buffer.empty()) {
        return;
    }
    std::lock_guard lock(mutex_);
    queue_.push_back(std::move(buffer));
    if (!pool_.empty()) {
        buffer = std::move(pool_.back());
        pool_.pop_back();
    } else {
        buffer = std::string();
    }
    cv_.notify_one();
}

void RecordWriter::run() {
    std::vector<std::string> batch;
    for (;;) {
        {
            std::unique_lock lock(mutex_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
            if (queue_.empty()) {
                return;  // stop_ and nothing left
            }
            batch.swap(queue_);
        }
        for (std::string& b : batch) {
            size_t done = 0;
            while (!failed_ && done < b.size()) {
                DWORD wrote = 0;
                const DWORD want = static_cast<DWORD>(std::min<size_t>(b.size() - done, 1u << 30));
                if (!WriteFile(file_, b.data() + done, want, &wrote, nullptr) || wrote == 0) {
                    failed_ = true;
                    break;
                }
                done += wrote;
                bytes_ += wrote;
            }
            b.clear();  // capacity stays for the next loop that needs a buffer
        }
        std::lock_guard lock(mutex_);
        for (std::string& b : batch) {
            pool_.push_back(std::move(b));
        }
        batch.clear();
    }
}

bool RecordWriter::close() {
    if (file_ == nullptr) {
        return !failed_;
    }
    {
        std::lock_guard lock(mutex_);
        stop_ = true;
    }
    cv_.notify_one();
    thread_.join();
    if (!CloseHandle(file_)) {
        failed_ = true;
    }
    file_ = nullptr;
    pool_.clear();
    return !failed_;
}

}  // namespace wc::crawl
