// parse::ResponseParser on arbitrary byte streams, fed in fuzz-chosen pieces.
//
// Input layout: 4 config bytes, then the raw bytes received on a connection.
//   byte 0: bit 0 HEAD request, bit 1 call finish() at EOF, bits 2-4 size cap
//   byte 1: number of extra split points (low 4 bits)
//   bytes 2-3: seed for the split points
//
// The stream is parsed twice: once whole, and once incrementally, where each
// step copies everything received so far into a buffer of exactly that size
// (the parser's in-place chunk decoding included), so ASan flags any read past
// the bytes presented. Up to four pipelined responses are parsed, each from
// consumed() of the previous one, as the crawler does.
//
// Invariants:
// - both runs agree on every observable result (state, error, status,
//   headers, body, consumed, keep-alive, chunked);
// - consumed() <= bytes presented; body and header views lie inside the buffer;
// - Done: status in 100..999 and not an interim 1xx (only 101 is final),
//   consumed() <= cap, Content-Length bodies have exactly that length and
//   identity bodies equal the received bytes, no body for HEAD/204/304;
// - Error: an error code is set and keep_alive() is false.

#include "parse/http.h"

#include "check.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace wc::parse;

namespace {

constexpr size_t kCaps[] = {0, 1, 17, 64, 512, 4096, size_t{1} << 20, SIZE_MAX};
constexpr int kMaxPipelined = 4;

struct Outcome {
    ParseStatus state;
    HttpError error;
    int status;
    int minor;
    bool keep_alive;
    bool chunked;
    size_t consumed;
    size_t header_bytes;
    std::string body;
    std::vector<std::string> headers;  // "name\0value"

    bool operator==(const Outcome&) const = default;
};

bool inside(std::string_view v, const char* buf, size_t len) {
    return v.empty() || (v.data() >= buf && v.data() + v.size() <= buf + len);
}

// Checks one finished parse whose buffer is `buf[0, len)`; `raw` is the
// original (undecoded) input at the same offsets.
Outcome observe(const ResponseParser& p, ParseStatus st, const char* buf, size_t len, const uint8_t* raw,
                bool head, size_t cap) {
    FUZZ_CHECK(st == p.state());
    FUZZ_CHECK(p.consumed() <= len);
    Outcome o{st, p.error(), 0, 0, p.keep_alive(), false, p.consumed(), 0, {}, {}};
    if (st == ParseStatus::Error) {
        FUZZ_CHECK(p.error() != HttpError::None);
        FUZZ_CHECK(!p.keep_alive());
        FUZZ_CHECK(p.body().empty());
        // Where parsing stopped depends on how much had arrived.
        o.consumed = 0;
        return o;
    }
    FUZZ_CHECK(p.error() == HttpError::None);
    if (st != ParseStatus::Done) {
        return o;
    }
    o.status = p.status();
    o.minor = p.http_minor();
    o.chunked = p.chunked();
    o.header_bytes = p.header_bytes();
    FUZZ_CHECK(o.status >= 100 && o.status <= 999);
    FUZZ_CHECK(o.status == 101 || o.status >= 200);
    FUZZ_CHECK(o.minor >= 0 && o.minor <= 9);
    FUZZ_CHECK(p.consumed() <= cap);
    FUZZ_CHECK(o.header_bytes <= p.consumed());

    for (size_t i = 0; i < p.header_count(); ++i) {
        const HeaderField f = p.header_at(i);
        FUZZ_CHECK(!f.name.empty());
        FUZZ_CHECK(inside(f.name, buf, len) && inside(f.value, buf, len));
        FUZZ_CHECK(p.has_header(f.name));
        o.headers.push_back(std::string(f.name) + '\0' + std::string(f.value));
    }

    const std::string_view body = p.body();
    FUZZ_CHECK(inside(body, buf, len));
    FUZZ_CHECK(body.size() <= p.consumed());
    if (head || o.status < 200 || o.status == 204 || o.status == 304) {
        FUZZ_CHECK(body.empty());
    }
    if (!body.empty()) {
        const size_t off = static_cast<size_t>(body.data() - buf);
        FUZZ_CHECK(off + body.size() <= p.consumed());
        if (!o.chunked) {
            // Identity bodies are never rewritten.
            FUZZ_CHECK(std::memcmp(body.data(), raw + off, body.size()) == 0);
        }
    }
    if (!o.chunked && !head && p.has_header("Content-Length") && !p.has_header("Transfer-Encoding") &&
        o.status >= 200 && o.status != 204 && o.status != 304) {
        // First value of a possibly repeated list ("5, 5"); the parser
        // rejects lists whose values disagree.
        const std::string_view v = p.header("Content-Length");
        size_t i = v.find_first_not_of(", \t");
        uint64_t cl = 0;
        for (; i < v.size() && v[i] >= '0' && v[i] <= '9'; ++i) {
            cl = cl * 10 + static_cast<uint64_t>(v[i] - '0');
        }
        FUZZ_CHECK(body.size() == cl);
    }
    o.body.assign(body);
    return o;
}

struct Rng {
    uint32_t s;
    uint32_t next() {
        s = s * 1664525u + 1013904223u;
        return s >> 8;
    }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;
    const bool head = data[0] & 1;
    const bool eof = data[0] & 2;
    const size_t cap = kCaps[(data[0] >> 2) & 7];
    const size_t splits = data[1] & 15;
    Rng rng{static_cast<uint32_t>(data[2] << 8 | data[3])};
    const uint8_t* const stream = data + 4;
    const size_t n = size - 4;

    // Whole-buffer parse of the pipelined responses.
    std::vector<char> whole(stream, stream + n);
    std::vector<Outcome> expected;
    {
        size_t base = 0;
        for (int i = 0; i < kMaxPipelined && base <= n; ++i) {
            ResponseParser p;
            p.reset(head, cap);
            char* buf = whole.data() + base;
            ParseStatus st = p.parse(buf, n - base);
            if (st == ParseStatus::NeedMore && eof) st = p.finish(buf, n - base);
            expected.push_back(observe(p, st, buf, n - base, stream + base, head, cap));
            if (st != ParseStatus::Done || p.consumed() == 0) break;
            base += p.consumed();
        }
    }

    // Incremental parse: the bytes of the first response arrive in pieces.
    std::vector<size_t> cuts;
    for (size_t i = 0; i < splits && n != 0; ++i) cuts.push_back(rng.next() % n);
    cuts.push_back(n);
    std::sort(cuts.begin(), cuts.end());

    std::vector<Outcome> actual;
    {
        ResponseParser p;
        p.reset(head, cap);
        std::vector<char> buf;  // replaced (never grown in place) on every step
        size_t have = 0;
        ParseStatus st = ParseStatus::NeedMore;
        for (const size_t cut : cuts) {
            if (cut < have) continue;
            std::vector<char> next(cut);
            if (have) std::memcpy(next.data(), buf.data(), have);
            std::memcpy(next.data() + have, stream + have, cut - have);
            buf.swap(next);
            have = cut;
            st = p.parse(buf.data(), have);
            if (st != ParseStatus::NeedMore) break;
        }
        // Later calls with the same bytes must not change anything.
        if (st == ParseStatus::NeedMore && eof) st = p.finish(buf.data(), have);
        FUZZ_CHECK(p.parse(buf.data(), have) == st);
        actual.push_back(observe(p, st, buf.data(), have, stream, head, cap));

        // The rest of the pipeline, whole, as above; offsets still index `stream`.
        if (st == ParseStatus::Done && p.consumed() != 0) {
            std::vector<char> rest(stream, stream + n);
            size_t base = p.consumed();
            for (int i = 1; i < kMaxPipelined && base <= n; ++i) {
                ResponseParser q;
                q.reset(head, cap);
                char* b = rest.data() + base;
                ParseStatus s = q.parse(b, n - base);
                if (s == ParseStatus::NeedMore && eof) s = q.finish(b, n - base);
                actual.push_back(observe(q, s, b, n - base, stream + base, head, cap));
                if (s != ParseStatus::Done || q.consumed() == 0) break;
                base += q.consumed();
            }
        }
    }

    // Error codes may differ only through the size cap: a partial message
    // already over the cap fails TooLarge before its later bytes, which the
    // whole parse sees, can fail it for a different reason.
    FUZZ_CHECK(actual.size() == expected.size());
    for (size_t i = 0; i < actual.size(); ++i) {
        Outcome& a = actual[i];
        Outcome& e = expected[i];
        if (a.state == ParseStatus::Error && e.state == ParseStatus::Error &&
            (a.error == HttpError::TooLarge || e.error == HttpError::TooLarge)) {
            a.error = e.error;
        }
        FUZZ_CHECK(a == e);
    }
    return 0;
}
