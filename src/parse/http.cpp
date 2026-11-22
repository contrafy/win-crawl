#include "parse/http.h"

#include <algorithm>
#include <cstring>

namespace wc::parse {
namespace {

constexpr char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }
constexpr bool is_digit(char c) { return c >= '0' && c <= '9'; }
constexpr bool is_ows(char c) { return c == ' ' || c == '\t'; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (to_lower(a[i]) != to_lower(b[i])) {
            return false;
        }
    }
    return true;
}

std::string_view trim_ows(std::string_view s) {
    while (!s.empty() && is_ows(s.front())) {
        s.remove_prefix(1);
    }
    while (!s.empty() && is_ows(s.back())) {
        s.remove_suffix(1);
    }
    return s;
}

// Calls fn(token) for each trimmed, non-empty element of a comma list.
template <typename Fn>
void for_each_token(std::string_view list, Fn&& fn) {
    while (!list.empty()) {
        const size_t comma = list.find(',');
        const std::string_view token = trim_ows(list.substr(0, comma));
        if (!token.empty()) {
            fn(token);
        }
        if (comma == std::string_view::npos) {
            break;
        }
        list.remove_prefix(comma + 1);
    }
}

int hex_value(char c) {
    if (is_digit(c)) {
        return c - '0';
    }
    const char l = to_lower(c);
    if (l >= 'a' && l <= 'f') {
        return l - 'a' + 10;
    }
    return -1;
}

}  // namespace

void append_request(std::string& out, std::string_view method, const Url& url,
                    std::string_view user_agent, bool keep_alive, std::string_view extra_headers) {
    out.append(method);
    out.push_back(' ');
    out.append(url.target);
    out.append(" HTTP/1.1\r\nHost: ");
    append_host_header(out, url);
    if (!user_agent.empty()) {
        out.append("\r\nUser-Agent: ");
        out.append(user_agent);
    }
    out.append("\r\nAccept: */*\r\nConnection: ");
    out.append(keep_alive ? "keep-alive" : "close");
    out.append("\r\n");
    out.append(extra_headers);
    out.append("\r\n");
}

const char* to_string(HttpError error) {
    switch (error) {
    case HttpError::None: return "none";
    case HttpError::BadStatusLine: return "bad status line";
    case HttpError::BadHeader: return "bad header";
    case HttpError::BadContentLength: return "bad content-length";
    case HttpError::BadChunk: return "bad chunk";
    case HttpError::TooLarge: return "too large";
    case HttpError::Truncated: return "truncated";
    }
    return "unknown";
}

void ResponseParser::reset(bool head_request, size_t max_bytes) {
    buf_ = nullptr;
    // Header spans are 32-bit offsets.
    max_bytes_ = std::min<size_t>(max_bytes, UINT32_MAX);
    msg_begin_ = 0;
    scan_ = 0;
    body_begin_ = 0;
    body_end_ = 0;
    pos_ = 0;
    remaining_ = 0;
    status_ = 0;
    minor_ = 0;
    head_ = head_request;
    keep_alive_ = false;
    phase_ = Phase::Headers;
    mode_ = BodyMode::None;
    state_ = ParseStatus::NeedMore;
    error_ = HttpError::None;
    headers_.clear();
}

ParseStatus ResponseParser::fail(HttpError e) {
    error_ = e;
    keep_alive_ = false;
    state_ = ParseStatus::Error;
    return state_;
}

ParseStatus ResponseParser::parse(char* buf, size_t len) {
    buf_ = buf;
    if (state_ != ParseStatus::NeedMore) {
        return state_;
    }
    ParseStatus st = ParseStatus::NeedMore;
    if (phase_ == Phase::Headers) {
        st = parse_headers(len);
    }
    if (st == ParseStatus::NeedMore && phase_ != Phase::Headers && phase_ != Phase::Done) {
        st = parse_body(len);
    }
    // Every unparsed byte belongs to this message, so an unfinished message
    // that already exceeds the cap can only grow past it. A bodyless reply
    // completes without the Content-Length pre-check, so check it here too.
    if ((st == ParseStatus::NeedMore && len > max_bytes_) || (st == ParseStatus::Done && pos_ > max_bytes_)) {
        return fail(HttpError::TooLarge);
    }
    return st;
}

ParseStatus ResponseParser::finish(char* buf, size_t len) {
    const ParseStatus st = parse(buf, len);
    if (st != ParseStatus::NeedMore) {
        return st;
    }
    if (phase_ == Phase::Body && mode_ == BodyMode::Close) {
        pos_ = len;
        body_end_ = len;
        phase_ = Phase::Done;
        state_ = ParseStatus::Done;
        return state_;
    }
    return fail(HttpError::Truncated);
}

bool ResponseParser::parse_status_line(size_t begin, size_t end) {
    // "HTTP/1.x SP 3DIGIT [SP reason]"
    const std::string_view line(buf_ + begin, end - begin);
    if (line.size() < 12 || line.substr(0, 7) != "HTTP/1." || !is_digit(line[7]) || line[8] != ' ') {
        return false;
    }
    size_t i = 9;
    while (i < line.size() && line[i] == ' ') {
        ++i;
    }
    if (i + 3 > line.size() || !is_digit(line[i]) || !is_digit(line[i + 1]) || !is_digit(line[i + 2])) {
        return false;
    }
    if (i + 3 < line.size() && line[i + 3] != ' ' && line[i + 3] != '\t') {
        return false;
    }
    const int code = (line[i] - '0') * 100 + (line[i + 1] - '0') * 10 + (line[i + 2] - '0');
    if (code < 100) {
        return false;
    }
    minor_ = line[7] - '0';
    status_ = code;
    return true;
}

ParseStatus ResponseParser::parse_headers(size_t len) {
    for (;;) {
        if (status_ == 0) {
            // Bare line breaks before a status line are tolerated (some
            // servers emit a stray CRLF after a body).
            while (pos_ < len && pos_ == msg_begin_ && (buf_[pos_] == '\r' || buf_[pos_] == '\n')) {
                ++pos_;
                ++msg_begin_;
            }
            // Reject non-HTTP replies as soon as the first bytes disagree.
            static constexpr std::string_view kPrefix = "HTTP/";
            const size_t avail = std::min(len - pos_, kPrefix.size() + 1);
            for (size_t i = 0; i < avail; ++i) {
                const char c = buf_[pos_ + i];
                if (i < kPrefix.size() ? c != kPrefix[i] : !is_digit(c)) {
                    return fail(HttpError::BadStatusLine);
                }
            }
        }

        const size_t from = std::max(scan_, pos_);
        const void* nl = from < len ? std::memchr(buf_ + from, '\n', len - from) : nullptr;
        if (nl == nullptr) {
            scan_ = len;
            return ParseStatus::NeedMore;
        }
        const size_t eol = static_cast<const char*>(nl) - buf_;
        size_t end = eol;
        if (end > pos_ && buf_[end - 1] == '\r') {
            --end;
        }
        const size_t begin = pos_;
        pos_ = eol + 1;
        scan_ = pos_;

        if (status_ == 0) {
            if (!parse_status_line(begin, end)) {
                return fail(HttpError::BadStatusLine);
            }
            continue;
        }
        if (end == begin) {
            if (status_ >= 100 && status_ < 200 && status_ != 101) {
                // Interim response: the real one follows.
                msg_begin_ = pos_;
                status_ = 0;
                headers_.clear();
                continue;
            }
            body_begin_ = pos_;
            return start_body();
        }
        // Folded continuation lines and lines without a colon carry nothing
        // the crawler needs; skip them rather than fail the page.
        if (is_ows(buf_[begin])) {
            continue;
        }
        const void* colon = std::memchr(buf_ + begin, ':', end - begin);
        if (colon == nullptr) {
            continue;
        }
        const size_t c = static_cast<const char*>(colon) - buf_;
        const std::string_view name = trim_ows(std::string_view(buf_ + begin, c - begin));
        const std::string_view value = trim_ows(std::string_view(buf_ + c + 1, end - c - 1));
        if (name.empty()) {
            return fail(HttpError::BadHeader);
        }
        headers_.push_back(Span{static_cast<uint32_t>(name.data() - buf_), static_cast<uint32_t>(name.size()),
                                static_cast<uint32_t>(value.data() - buf_), static_cast<uint32_t>(value.size())});
    }
}

ParseStatus ResponseParser::start_body() {
    pos_ = body_begin_;
    body_end_ = body_begin_;

    // Persistence (RFC 9112 §9.3).
    bool close = false;
    bool keep = false;
    for (size_t i = 0; i < headers_.size(); ++i) {
        const HeaderField f = header_at(i);
        if (iequals(f.name, "Connection")) {
            for_each_token(f.value, [&](std::string_view t) {
                close |= iequals(t, "close");
                keep |= iequals(t, "keep-alive");
            });
        }
    }
    keep_alive_ = !close && (minor_ >= 1 || keep) && status_ != 101;

    // Message body length (RFC 9112 §6.3).
    if (head_ || status_ < 200 || status_ == 204 || status_ == 304) {
        mode_ = BodyMode::None;
        phase_ = Phase::Done;
        state_ = ParseStatus::Done;
        return state_;
    }

    std::string_view te;
    bool has_te = false;
    bool has_cl = false;
    uint64_t cl = 0;
    for (size_t i = 0; i < headers_.size(); ++i) {
        const HeaderField f = header_at(i);
        if (iequals(f.name, "Transfer-Encoding")) {
            has_te = true;
            te = f.value;
        } else if (iequals(f.name, "Content-Length")) {
            // Repeated values (as a list or repeated fields) must agree.
            bool bad = false;
            bool any = false;
            for_each_token(f.value, [&](std::string_view t) {
                uint64_t v = 0;
                for (const char ch : t) {
                    if (!is_digit(ch) || v > (UINT64_MAX - 9) / 10) {
                        bad = true;
                        return;
                    }
                    v = v * 10 + static_cast<uint64_t>(ch - '0');
                }
                if (has_cl && v != cl) {
                    bad = true;
                }
                has_cl = true;
                any = true;
                cl = v;
            });
            if (bad || !any) {
                return fail(HttpError::BadContentLength);
            }
        }
    }

    if (has_te) {
        // Chunked only if it is the final coding; otherwise the body runs to
        // EOF. A Content-Length alongside Transfer-Encoding is ignored, and
        // the connection must not be reused (RFC 9112 §6.3 item 3).
        std::string_view last;
        for_each_token(te, [&](std::string_view t) { last = t; });
        if (has_cl) {
            keep_alive_ = false;
        }
        if (iequals(last, "chunked")) {
            mode_ = BodyMode::Chunked;
            phase_ = Phase::ChunkSize;
        } else {
            mode_ = BodyMode::Close;
            phase_ = Phase::Body;
            keep_alive_ = false;
        }
        return ParseStatus::NeedMore;
    }
    if (has_cl) {
        if (cl > max_bytes_ - std::min<uint64_t>(body_begin_, max_bytes_) || body_begin_ > max_bytes_) {
            return fail(HttpError::TooLarge);
        }
        mode_ = BodyMode::Length;
        remaining_ = cl;
        if (cl == 0) {
            phase_ = Phase::Done;
            state_ = ParseStatus::Done;
            return state_;
        }
        phase_ = Phase::Body;
        return ParseStatus::NeedMore;
    }
    mode_ = BodyMode::Close;
    phase_ = Phase::Body;
    keep_alive_ = false;
    return ParseStatus::NeedMore;
}

ParseStatus ResponseParser::parse_body(size_t len) {
    if (mode_ == BodyMode::Close) {
        pos_ = len;
        body_end_ = len;
        return ParseStatus::NeedMore;
    }
    if (mode_ == BodyMode::Length) {
        const uint64_t take = std::min<uint64_t>(len - pos_, remaining_);
        pos_ += static_cast<size_t>(take);
        body_end_ = pos_;
        remaining_ -= take;
        if (remaining_ != 0) {
            return ParseStatus::NeedMore;
        }
        phase_ = Phase::Done;
        state_ = ParseStatus::Done;
        return state_;
    }

    for (;;) {
        switch (phase_) {
        case Phase::ChunkSize:
        case Phase::Trailers: {
            const size_t from = std::max(scan_, pos_);
            const void* nl = from < len ? std::memchr(buf_ + from, '\n', len - from) : nullptr;
            if (nl == nullptr) {
                scan_ = len;
                return ParseStatus::NeedMore;
            }
            const size_t eol = static_cast<const char*>(nl) - buf_;
            size_t end = eol;
            if (end > pos_ && buf_[end - 1] == '\r') {
                --end;
            }
            const size_t begin = pos_;
            pos_ = eol + 1;
            scan_ = pos_;

            if (phase_ == Phase::Trailers) {
                if (end == begin) {
                    phase_ = Phase::Done;
                    state_ = ParseStatus::Done;
                    return state_;
                }
                continue;  // trailer fields are ignored
            }

            // chunk-size [ws] [; ext]
            size_t i = begin;
            uint64_t size = 0;
            while (i < end) {
                const int h = hex_value(buf_[i]);
                if (h < 0) {
                    break;
                }
                if (size >> 59) {
                    return fail(HttpError::BadChunk);
                }
                size = (size << 4) | static_cast<uint64_t>(h);
                ++i;
            }
            if (i == begin) {
                return fail(HttpError::BadChunk);
            }
            while (i < end && is_ows(buf_[i])) {
                ++i;
            }
            if (i < end && buf_[i] != ';') {
                return fail(HttpError::BadChunk);
            }
            if (size == 0) {
                phase_ = Phase::Trailers;
                continue;
            }
            if (size > max_bytes_ || pos_ + size > max_bytes_) {
                return fail(HttpError::TooLarge);
            }
            remaining_ = size;
            phase_ = Phase::ChunkData;
            continue;
        }
        case Phase::ChunkData: {
            const size_t take = static_cast<size_t>(std::min<uint64_t>(len - pos_, remaining_));
            if (take != 0 && body_end_ != pos_) {
                std::memmove(buf_ + body_end_, buf_ + pos_, take);
            }
            body_end_ += take;
            pos_ += take;
            remaining_ -= take;
            if (remaining_ != 0) {
                return ParseStatus::NeedMore;
            }
            phase_ = Phase::ChunkDataEnd;
            continue;
        }
        case Phase::ChunkDataEnd: {
            if (pos_ >= len) {
                return ParseStatus::NeedMore;
            }
            if (buf_[pos_] == '\n') {
                pos_ += 1;
            } else if (buf_[pos_] == '\r') {
                if (pos_ + 1 >= len) {
                    return ParseStatus::NeedMore;
                }
                if (buf_[pos_ + 1] != '\n') {
                    return fail(HttpError::BadChunk);
                }
                pos_ += 2;
            } else {
                return fail(HttpError::BadChunk);
            }
            phase_ = Phase::ChunkSize;
            continue;
        }
        default:
            return ParseStatus::NeedMore;
        }
    }
}

std::string_view ResponseParser::header(std::string_view name) const {
    for (const Span& s : headers_) {
        if (iequals(std::string_view(buf_ + s.name_off, s.name_len), name)) {
            return std::string_view(buf_ + s.value_off, s.value_len);
        }
    }
    return {};
}

bool ResponseParser::has_header(std::string_view name) const {
    for (const Span& s : headers_) {
        if (iequals(std::string_view(buf_ + s.name_off, s.name_len), name)) {
            return true;
        }
    }
    return false;
}

HeaderField ResponseParser::header_at(size_t i) const {
    const Span& s = headers_[i];
    return HeaderField{std::string_view(buf_ + s.name_off, s.name_len), std::string_view(buf_ + s.value_off, s.value_len)};
}

std::string_view ResponseParser::body() const {
    if (buf_ == nullptr || state_ != ParseStatus::Done) {
        return {};
    }
    return std::string_view(buf_ + body_begin_, body_end_ - body_begin_);
}

}  // namespace wc::parse
