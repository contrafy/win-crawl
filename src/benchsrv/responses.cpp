#include "benchsrv/http_server.h"

#include <algorithm>
#include <cstdio>

namespace wc::benchsrv {

namespace {

// Template sizes as multiples of page_kb / 8; they average exactly page_kb.
constexpr uint32_t kSizeEighths[kPageTemplates] = {2, 4, 6, 8, 8, 10, 12, 14};
constexpr size_t kChunkSize = 4096;

constexpr const char* kFiller[] = {
    "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit", "sed", "do",
    "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore", "magna", "aliqua", "crawler",
};

void append_filler(std::string& out, size_t bytes, uint64_t& state) {
    if (bytes < 16) return;
    const size_t end = out.size() + bytes;
    out += "<p>";
    while (out.size() + 16 < end) {
        state = mix64(state);
        out += kFiller[state % (sizeof(kFiller) / sizeof(kFiller[0]))];
        out += ' ';
    }
    out += "</p>\n";
}

// One link in one of several syntactic shapes, so extractors must handle
// absolute, protocol-relative, root-relative and relative hrefs, quoting
// variants, entities, uppercase markup and <area>.
void append_link(std::string& out, uint32_t i, uint64_t h, const std::string& zone, uint16_t port) {
    const unsigned long long host = (h >> 8) % 1000000;
    const unsigned page = static_cast<unsigned>(h % 100000);
    char buf[256];
    switch (i % 6) {
        case 0:
            std::snprintf(buf, sizeof(buf), "<a href=\"http://h%llu.%s:%u/p/%u\">site %llu</a>\n", host, zone.c_str(),
                          port, page, host);
            break;
        case 1: std::snprintf(buf, sizeof(buf), "<a href=\"/p/%u\">page %u</a>\n", page, page); break;
        case 2: std::snprintf(buf, sizeof(buf), "<a class=\"rel\" href=\"p%u.html\">next</a>\n", page); break;
        case 3: std::snprintf(buf, sizeof(buf), "<a href='../d/%u?q=%u&amp;x=1'>query</a>\n", page, i); break;
        case 4:
            std::snprintf(buf, sizeof(buf), "<area shape=\"rect\" coords=\"0,0,8,8\" href=\"//h%llu.%s:%u/p/%u\">\n",
                          host, zone.c_str(), port, page);
            break;
        default:
            std::snprintf(buf, sizeof(buf), "<A TITLE=\"x\" HREF=\"http://h%llu.%s:%u/p/%u#frag\">UPPER</A>\n", host,
                          zone.c_str(), port, page);
            break;
    }
    out += buf;
}

std::string make_page_body(const Behavior& b, uint32_t tmpl, uint16_t port) {
    const size_t target = static_cast<size_t>(b.page_kb) * 1024 * kSizeEighths[tmpl] / 8;
    std::string body;
    body.reserve(target + b.links * 128 + 512);
    char head[160];
    std::snprintf(head, sizeof(head),
                  "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>bench page %u</title></head>\n"
                  "<body>\n<h1>Benchmark page %u</h1>\n<map name=\"m\">\n",
                  tmpl, tmpl);
    body += head;
    constexpr size_t kTail = 24;  // "</map>\n</body></html>\n"
    const size_t link_bytes = static_cast<size_t>(b.links) * 80;
    const size_t fixed = body.size() + kTail + link_bytes;
    const size_t filler_total = target > fixed ? target - fixed : 0;
    const size_t per_gap = filler_total / (static_cast<size_t>(b.links) + 1);
    uint64_t state = mix64(b.seed ^ (0x7061676500000000ULL + tmpl));
    for (uint32_t i = 0; i < b.links; ++i) {
        append_filler(body, per_gap, state);
        append_link(body, i, mix64(state + i), b.zone, port);
    }
    if (body.size() + kTail < target) append_filler(body, target - body.size() - kTail, state);
    body += "</map>\n</body></html>\n";
    return body;
}

std::string chunk_encode(const std::string& body) {
    std::string out;
    out.reserve(body.size() + body.size() / kChunkSize * 8 + 16);
    char size_line[24];
    for (size_t pos = 0; pos < body.size(); pos += kChunkSize) {
        const size_t n = std::min(kChunkSize, body.size() - pos);
        std::snprintf(size_line, sizeof(size_line), "%zx\r\n", n);
        out += size_line;
        out.append(body, pos, n);
        out += "\r\n";
    }
    out += "0\r\n\r\n";
    return out;
}

const char* reason(uint16_t status) {
    switch (status) {
        case 200: return "OK";
        case 301: return "Moved Permanently";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 429: return "Too Many Requests";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

// extra: additional header lines, each ending in CRLF.
Response make_response(uint16_t status, const char* content_type, const std::string& body, bool chunked, bool close,
                       const char* extra = "") {
    Response r;
    r.status = status;
    char head[512];
    const std::string payload = chunked ? chunk_encode(body) : body;
    char length_line[64];
    if (chunked) {
        std::snprintf(length_line, sizeof(length_line), "Transfer-Encoding: chunked\r\n");
    } else {
        std::snprintf(length_line, sizeof(length_line), "Content-Length: %zu\r\n", body.size());
    }
    const int n = std::snprintf(head, sizeof(head),
                                "HTTP/1.1 %u %s\r\nServer: wincrawl-benchd\r\nContent-Type: %s\r\n%s%sConnection: %s\r\n\r\n",
                                status, reason(status), content_type, length_line, extra, close ? "close" : "keep-alive");
    r.data.reserve(static_cast<size_t>(n) + payload.size());
    r.data.assign(head, static_cast<size_t>(n));
    r.head_len = r.data.size();
    r.data += payload;
    return r;
}

std::string small_html(uint16_t status) {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "<html><head><title>%u</title></head><body>%u %s</body></html>\n", status, status,
                  reason(status));
    return buf;
}

constexpr const char* kHtml = "text/html; charset=utf-8";

}  // namespace

ResponseSet::ResponseSet(const Behavior& behavior, uint16_t link_port) {
    const std::string robots_body =
        "# wincrawl-benchd\nUser-agent: *\nDisallow: /private/\nDisallow: /tmp/\n";
    const std::string robots_delayed_body = "# wincrawl-benchd\nUser-agent: *\nCrawl-delay: " +
                                            std::to_string(behavior.crawl_delay_s) +
                                            "\nDisallow: /private/\nDisallow: /tmp/\n";
    const std::string retry_after = "Retry-After: " + std::to_string(behavior.retry_after_s) + "\r\n";
    for (uint32_t t = 0; t < kPageTemplates; ++t) bodies_[t] = make_page_body(behavior, t, link_port);
    for (int conn = 0; conn < 2; ++conn) {
        const bool close = conn == 1;
        robots_[0][conn] = make_response(200, "text/plain", robots_body, false, close);
        robots_[1][conn] = make_response(404, kHtml, small_html(404), false, close);
        robots_delayed_[conn] = make_response(200, "text/plain", robots_delayed_body, false, close);
        for (uint32_t t = 0; t < kPageTemplates; ++t) {
            pages_[t][0][conn] = make_response(200, kHtml, bodies_[t], false, close);
            pages_[t][1][conn] = make_response(200, kHtml, bodies_[t], true, close);
        }
        redirect_[conn] = make_response(301, kHtml, small_html(301), false, close, "Location: /r/1\r\n");
        not_found_[conn] = make_response(404, kHtml, small_html(404), false, close);
        server_error_[conn] = make_response(503, kHtml, small_html(503), false, close, "Retry-After: 120\r\n");
        throttled_[conn] = make_response(429, kHtml, small_html(429), false, close, retry_after.c_str());
    }
    bad_request_ = make_response(400, kHtml, small_html(400), false, true);
    too_large_ = make_response(431, kHtml, small_html(431), false, true);
    not_implemented_ = make_response(501, kHtml, small_html(501), false, true);
}

}  // namespace wc::benchsrv
