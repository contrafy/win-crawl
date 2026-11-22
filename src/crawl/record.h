#pragma once
// Per-site measurement records (--record FILE): one JSON line per seed URL
// whose host passed host dedupe. docs/study-method.md documents every field.
//
// Assembly is allocation-free in steady state: each task slot owns a
// SiteRecord whose strings keep their capacity across sites, and each loop
// serializes into its own buffer that is handed whole to RecordWriter's
// thread once it fills, so loops never contend per record.

#include "parse/http.h"
#include "parse/url.h"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace wc::crawl {

// Appends `text` as a JSON string literal (quotes included). Escapes '"',
// '\\' and control characters; valid UTF-8 passes through, and each byte of
// an invalid UTF-8 sequence becomes \u00XX (its Latin-1 reading), so the
// output is always valid UTF-8 JSON whatever a server sent.
void append_json_string(std::string& out, std::string_view text);

// `text` cut to at most `max` bytes without splitting a UTF-8 sequence.
std::string_view truncate_utf8(std::string_view text, size_t max);

// True if an Alt-Svc field value advertises HTTP/3: an alternative whose
// protocol id is "h3" or a draft "h3-NN" (RFC 7838 §3).
bool alt_svc_has_h3(std::string_view value);

// Strict-Transport-Security field value (RFC 6797 §6.1).
struct Hsts {
    bool valid = false;  // exactly one max-age with a delta-seconds value, no repeated directives
    uint64_t max_age = 0;
    bool include_subdomains = false;
    bool preload = false;
};
Hsts parse_hsts(std::string_view value);

// Everything recorded about one site. Fields left unset serialize as null.
struct SiteRecord {
    // Seed.
    std::string url;  // the input line, trimmed
    std::string host;
    bool seed_https = false;

    // DNS of the seed host. nullptr: never resolved.
    const char* dns = nullptr;  // dns::status_name, or "cancelled" when the run stopped
    bool has_ip = false;
    uint32_t ip = 0;            // network byte order
    std::optional<bool> ip_dup; // the IP was already taken by an earlier host
    std::optional<bool> cf_ip;  // the IP is in Cloudflare's published ranges

    // HTTPS resource record (--https-rr). status == nullptr: not queried.
    struct HttpsRr {
        const char* status = nullptr;
        bool present = false;
        bool alias = false;
        bool h3 = false;
        bool h2 = false;
        bool ech = false;
    } https_rr;

    // robots.txt of the seed origin (after robots redirects).
    std::optional<int> robots_status;
    const char* robots_error = nullptr;  // fetch_error_name of a failed robots fetch
    std::optional<bool> robots_allowed;  // the page fetch was permitted

    // Page chain. `fetch` says how it ended; the reply fields describe the
    // last page reply received (the final one unless a later hop failed).
    const char* fetch = nullptr;  // "ok", a fetch_error_name, "redirect_dns", "robots_blocked"; nullptr: never attempted
    std::optional<int> status;
    unsigned redirects = 0;
    bool has_final = false;
    bool final_https = false;
    std::string final_url;
    bool has_content_type = false;
    std::string content_type;
    std::optional<uint64_t> bytes;  // decoded body bytes of the last reply
    std::optional<uint64_t> links;  // links extracted (2xx HTML only)
    std::optional<bool> alt_svc_h3;
    std::optional<bool> hsts;       // header present on an https reply; null for http replies
    std::optional<uint64_t> hsts_max_age;
    bool hsts_sub = false;
    bool hsts_preload = false;
    bool has_server = false;
    std::string server;
    std::optional<bool> cf_ray;  // the first reply from the seed origin carried CF-RAY

    // First TLS handshake of the site. handshake == nullptr: no https connection reached TLS.
    struct Tls {
        const char* handshake = nullptr;  // "ok" | "certificate" | "failed" | "incomplete"
        uint32_t protocol = 0;            // SP_PROT_* (0: unknown)
        std::string cipher;
        std::string group;                // key exchange group; empty: unknown
        std::optional<bool> pq;
        std::optional<bool> resumed;
    } tls;

    uint64_t ms = 0;  // task time, start to record

    // Politeness (docs/politeness.md).
    const char* skip = nullptr;          // "ip_budget" | "ip_unreachable" | "crawl_delay"; nullptr: not skipped
    uint64_t wait_ms = 0;                // waited on politeness: IP queue and spacing, Crawl-delay, Retry-After
    std::optional<double> crawl_delay;   // Crawl-delay (s) in the seed origin's robots.txt
    uint64_t crawl_delay_ms = 0;         // of wait_ms: waited for a Crawl-delay
    std::optional<uint64_t> retry_after; // Retry-After (s) of the first 429/503 that carried one
    std::optional<bool> retried;         // that Retry-After was waited out and the request repeated

    // Resets every field; strings keep their capacity.
    void clear();
    // Fills the reply fields from a page reply received for `reply_url`.
    void set_page_reply(const parse::ResponseParser& reply, const parse::Url& reply_url, std::string_view body);
    // Appends one JSON object plus '\n'.
    void append_json(std::string& out) const;
};

// Owns the record file and a writer thread. Loops fill their own buffers and
// hand them over whole; the writer returns emptied buffers (capacity intact)
// for reuse, so steady state allocates nothing.
class RecordWriter {
public:
    RecordWriter() = default;
    ~RecordWriter();
    RecordWriter(const RecordWriter&) = delete;
    RecordWriter& operator=(const RecordWriter&) = delete;

    // Creates/truncates `path` and starts the writer thread.
    bool open(const std::string& path, std::string& error);
    // Any thread. Queues `buffer` (if non-empty) for writing and replaces it
    // with an empty recycled buffer.
    void submit(std::string& buffer);
    // Writes everything queued, stops the thread and closes the file. False
    // if any write failed. Idempotent.
    bool close();
    bool is_open() const { return file_ != nullptr; }
    uint64_t bytes_written() const { return bytes_; }

private:
    void run();

    void* file_ = nullptr;  // HANDLE
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::string> queue_;
    std::vector<std::string> pool_;
    bool stop_ = false;
    bool failed_ = false;
    uint64_t bytes_ = 0;  // writer thread until joined
    std::thread thread_;
};

}  // namespace wc::crawl
