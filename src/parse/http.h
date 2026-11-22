#pragma once
// HTTP/1.1 request writer and incremental response parser.
//
// The parser never owns bytes: the caller accumulates everything received on
// the connection in its own growable buffer and re-presents the whole buffer
// after each recv. Chunked bodies are decoded in place inside that buffer, so
// the finished body is always one contiguous span. The parser stores offsets,
// not pointers, so the buffer may be reallocated between calls, but bytes
// already presented must not be modified or moved by the caller.
//
//   ResponseParser p;
//   p.reset(/*head_request=*/false, /*max_bytes=*/2 << 20);
//   std::string buf;
//   for (;;) {
//       size_t n = recv_into(buf);              // appends to buf
//       ParseStatus st = n == 0 ? p.finish(buf.data(), buf.size())
//                               : p.parse(buf.data(), buf.size());
//       if (st == ParseStatus::NeedMore) continue;
//       if (st == ParseStatus::Error) { /* p.error() */ break; }
//       // Done: p.status(), p.header("Location"), p.body(), p.keep_alive();
//       // a following response on this connection starts at buf[p.consumed()].
//       break;
//   }
//
// Views returned by header()/body() point into the buffer passed to the most
// recent parse()/finish() call and stay valid until that buffer changes.

#include "parse/url.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wc::parse {

// Appends "METHOD target HTTP/1.1" plus Host, User-Agent (omitted when empty),
// Accept: */* and Connection headers, then `extra_headers` verbatim: whole
// header lines, each ending in CRLF (the Web Bot Auth signature fields). No
// Accept-Encoding, so servers reply with identity bodies.
void append_request(std::string& out, std::string_view method, const Url& url,
                    std::string_view user_agent, bool keep_alive, std::string_view extra_headers = {});

enum class ParseStatus : uint8_t { NeedMore, Done, Error };

enum class HttpError : uint8_t {
    None,
    BadStatusLine,     // reply does not start with "HTTP/1.x NNN"
    BadHeader,         // malformed header block
    BadContentLength,  // non-numeric or conflicting Content-Length
    BadChunk,          // malformed chunked framing
    TooLarge,          // message would exceed max_bytes
    Truncated,         // EOF before the message was complete
};

const char* to_string(HttpError error);

struct HeaderField {
    std::string_view name;
    std::string_view value;  // surrounding whitespace trimmed
};

class ResponseParser {
public:
    // Prepares for a new response. `max_bytes` caps the raw message size
    // (status line, headers, framing, and body, including skipped 1xx
    // responses). A response to HEAD never has a body.
    void reset(bool head_request, size_t max_bytes);

    // `buf[0, len)` is every byte received for this response so far; `len`
    // never shrinks between calls. May rewrite bytes past the header block
    // (chunk decoding) but never bytes past consumed().
    ParseStatus parse(char* buf, size_t len);

    // Call on EOF. Completes a close-delimited body; otherwise an unfinished
    // message becomes Error(Truncated).
    ParseStatus finish(char* buf, size_t len);

    ParseStatus state() const { return state_; }
    HttpError error() const { return error_; }

    // Valid once the final status line has been parsed (i.e. after Done).
    int status() const { return status_; }
    int http_minor() const { return minor_; }
    // True if another request may be sent on this connection after this
    // response: HTTP/1.1 unless "Connection: close", HTTP/1.0 only with
    // "Connection: keep-alive", never for close-delimited bodies.
    bool keep_alive() const { return keep_alive_; }
    bool chunked() const { return mode_ == BodyMode::Chunked; }

    // Case-insensitive lookup of the first header with this name; empty if
    // absent (use has_header() to distinguish an empty value).
    std::string_view header(std::string_view name) const;
    bool has_header(std::string_view name) const;
    size_t header_count() const { return headers_.size(); }
    HeaderField header_at(size_t i) const;

    // Status line + headers + blank line of the final response.
    size_t header_bytes() const { return body_begin_ - msg_begin_; }
    // Raw bytes of this exchange from buf[0], including skipped 1xx responses
    // and chunk framing; the next pipelined response would start here.
    size_t consumed() const { return pos_; }
    // Decoded body; valid after Done.
    std::string_view body() const;

private:
    enum class Phase : uint8_t { Headers, Body, ChunkSize, ChunkData, ChunkDataEnd, Trailers, Done };
    enum class BodyMode : uint8_t { None, Length, Chunked, Close };
    struct Span {
        uint32_t name_off, name_len, value_off, value_len;
    };

    ParseStatus fail(HttpError e);
    ParseStatus parse_headers(size_t len);
    ParseStatus parse_body(size_t len);
    bool parse_status_line(size_t begin, size_t end);
    ParseStatus start_body();

    char* buf_ = nullptr;
    size_t max_bytes_ = 0;
    size_t msg_begin_ = 0;   // start of the current (possibly 1xx) response
    size_t scan_ = 0;        // resume point of the header terminator search
    size_t body_begin_ = 0;
    size_t body_end_ = 0;    // decoded body end (write cursor for chunked)
    size_t pos_ = 0;         // read cursor
    uint64_t remaining_ = 0; // bytes left in the current chunk or Content-Length body
    int status_ = 0;
    int minor_ = 0;
    bool head_ = false;
    bool keep_alive_ = false;
    Phase phase_ = Phase::Headers;
    BodyMode mode_ = BodyMode::None;
    ParseStatus state_ = ParseStatus::NeedMore;
    HttpError error_ = HttpError::None;
    std::vector<Span> headers_;
};

}  // namespace wc::parse
