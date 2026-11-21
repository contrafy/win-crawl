#include "crawl/input.h"

#include <windows.h>

#include <algorithm>
#include <cstring>

namespace wc::crawl {

namespace {

bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

std::string win32_message(DWORD error) {
    char buf[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, buf,
                             sizeof(buf), nullptr);
    while (n > 0 && is_space(buf[n - 1])) {
        --n;
    }
    return std::string(buf, n) + " (error " + std::to_string(error) + ")";
}

}  // namespace

UrlInput::~UrlInput() {
    close();
}

void UrlInput::close() {
    if (data_ != nullptr && mapping_ != nullptr) {
        UnmapViewOfFile(data_);
    }
    if (mapping_ != nullptr) {
        CloseHandle(mapping_);
    }
    if (file_ != nullptr) {
        CloseHandle(file_);
    }
    data_ = nullptr;
    size_ = 0;
    mapping_ = nullptr;
    file_ = nullptr;
    lines_.clear();
    cursor_.store(0, std::memory_order_relaxed);
}

bool UrlInput::open(const std::string& path, std::string& error) {
    close();
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "cannot open " + path + ": " + win32_message(GetLastError());
        return false;
    }
    file_ = file;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) {
        error = "cannot stat " + path + ": " + win32_message(GetLastError());
        close();
        return false;
    }
    if (size.QuadPart == 0) {
        // CreateFileMapping rejects zero-length files; nothing to map anyway.
        return true;
    }
    HANDLE mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapping == nullptr) {
        error = "cannot map " + path + ": " + win32_message(GetLastError());
        close();
        return false;
    }
    mapping_ = mapping;
    const void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (view == nullptr) {
        error = "cannot map " + path + ": " + win32_message(GetLastError());
        close();
        return false;
    }
    data_ = static_cast<const char*>(view);
    size_ = static_cast<size_t>(size.QuadPart);
    scan();
    return true;
}

void UrlInput::assign(std::string_view text) {
    close();
    data_ = text.data();
    size_ = text.size();
    scan();
}

void UrlInput::scan() {
    // Seed files average ~40 bytes per line; reserving avoids regrowth copies
    // on the 1M-line input without overcommitting for tiny files.
    lines_.reserve(size_ / 32 + 1);
    const char* const begin = data_;
    const char* const end = data_ + size_;
    const char* p = begin;
    while (p < end) {
        const char* nl = static_cast<const char*>(std::memchr(p, '\n', static_cast<size_t>(end - p)));
        const char* line_end = nl != nullptr ? nl : end;
        const char* b = p;
        const char* e = line_end;
        // Trimming whitespace also strips the '\r' of CRLF endings.
        while (b < e && is_space(*b)) {
            ++b;
        }
        while (e > b && is_space(e[-1])) {
            --e;
        }
        if (e > b) {
            lines_.push_back(Line{static_cast<uint64_t>(b - begin), static_cast<uint32_t>(e - b)});
        }
        p = nl != nullptr ? nl + 1 : end;
    }
    lines_.shrink_to_fit();
}

size_t UrlInput::claim(size_t max, std::vector<std::string_view>& out) {
    const uint64_t total = lines_.size();
    if (max == 0 || cursor_.load(std::memory_order_relaxed) >= total) {
        return 0;
    }
    const uint64_t first = cursor_.fetch_add(max, std::memory_order_relaxed);
    if (first >= total) {
        return 0;
    }
    const uint64_t last = std::min<uint64_t>(first + max, total);
    for (uint64_t i = first; i < last; ++i) {
        const Line& line = lines_[static_cast<size_t>(i)];
        out.emplace_back(data_ + line.offset, line.length);
    }
    return static_cast<size_t>(last - first);
}

size_t UrlInput::remaining() const {
    const uint64_t total = lines_.size();
    const uint64_t cursor = cursor_.load(std::memory_order_relaxed);
    return cursor >= total ? 0 : static_cast<size_t>(total - cursor);
}

}  // namespace wc::crawl
