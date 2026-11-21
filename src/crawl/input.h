#pragma once
// Seed URL input: the file is memory-mapped once, its line boundaries are
// prescanned into a compact offsets array, and event loops then claim lines in
// batches through one atomic cursor. Lines are handed out as string_views into
// the mapping, so no per-URL allocation or copy happens before parsing.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wc::crawl {

class UrlInput {
public:
    UrlInput() = default;
    ~UrlInput();
    UrlInput(const UrlInput&) = delete;
    UrlInput& operator=(const UrlInput&) = delete;

    // Maps `path` read-only and prescans it. Returns false with a message in
    // `error` when the file cannot be opened or mapped. An empty file is valid
    // and yields no lines.
    bool open(const std::string& path, std::string& error);

    // Uses an in-memory buffer instead of a file (tests). `text` must outlive
    // this object.
    void assign(std::string_view text);

    // Thread-safe. Appends up to `max` lines to `out` and returns how many were
    // appended (0 once the input is exhausted). Lines are trimmed of
    // surrounding whitespace and never empty.
    size_t claim(size_t max, std::vector<std::string_view>& out);

    // Number of non-empty lines in the input.
    size_t total() const { return lines_.size(); }
    // Thread-safe. Lines not yet handed out by claim().
    size_t remaining() const;

private:
    // Offsets are 64-bit so inputs beyond 4 GiB still work; a single URL line
    // longer than 4 GiB is not a thing.
    struct Line {
        uint64_t offset;
        uint32_t length;
    };

    void close();
    void scan();

    const char* data_ = nullptr;
    size_t size_ = 0;
    void* file_ = nullptr;     // HANDLE; void* keeps <windows.h> out of the header
    void* mapping_ = nullptr;  // HANDLE
    std::vector<Line> lines_;
    // fetch_add may run past lines_.size() once exhausted; readers clamp.
    std::atomic<uint64_t> cursor_{0};
};

}  // namespace wc::crawl
