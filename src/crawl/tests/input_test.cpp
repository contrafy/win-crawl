#include "crawl/input.h"

#include "doctest/doctest.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using wc::crawl::UrlInput;

namespace {

std::vector<std::string> drain(UrlInput& in, size_t batch) {
    std::vector<std::string_view> views;
    while (in.claim(batch, views) > 0) {
    }
    return std::vector<std::string>(views.begin(), views.end());
}

std::string temp_file(const std::string& contents) {
    char dir[MAX_PATH];
    GetTempPathA(MAX_PATH, dir);
    char path[MAX_PATH];
    GetTempFileNameA(dir, "wci", 0, path);
    FILE* f = std::fopen(path, "wb");
    REQUIRE(f != nullptr);
    std::fwrite(contents.data(), 1, contents.size(), f);
    std::fclose(f);
    return path;
}

}  // namespace

TEST_CASE("input: CRLF, LF, blank lines, whitespace and no trailing newline") {
    const std::string text = "http://a.com/\r\n\r\n  http://b.com/x \r\n\n\t\nhttp://c.com/\nhttp://d.com/last";
    UrlInput in;
    in.assign(text);
    CHECK(in.total() == 4);
    CHECK(in.remaining() == 4);
    const auto lines = drain(in, 3);
    REQUIRE(lines.size() == 4);
    CHECK(lines[0] == "http://a.com/");
    CHECK(lines[1] == "http://b.com/x");
    CHECK(lines[2] == "http://c.com/");
    CHECK(lines[3] == "http://d.com/last");
    CHECK(in.remaining() == 0);
    std::vector<std::string_view> more;
    CHECK(in.claim(10, more) == 0);
    CHECK(more.empty());
}

TEST_CASE("input: empty and whitespace-only inputs have no lines") {
    UrlInput in;
    in.assign("");
    CHECK(in.total() == 0);
    in.assign(" \r\n\r\n\n  ");
    CHECK(in.total() == 0);
    std::vector<std::string_view> out;
    CHECK(in.claim(4, out) == 0);
}

TEST_CASE("input: claim hands out batches in order and clamps at the end") {
    std::string text;
    for (int i = 0; i < 10; ++i) {
        text += "u" + std::to_string(i) + "\n";
    }
    UrlInput in;
    in.assign(text);
    std::vector<std::string_view> out;
    CHECK(in.claim(4, out) == 4);
    CHECK(in.remaining() == 6);
    CHECK(in.claim(4, out) == 4);
    CHECK(in.claim(4, out) == 2);
    CHECK(in.claim(4, out) == 0);
    CHECK(in.remaining() == 0);
    REQUIRE(out.size() == 10);
    CHECK(out.front() == "u0");
    CHECK(out.back() == "u9");
}

TEST_CASE("input: concurrent claims hand out every line exactly once") {
    std::string text;
    const int n = 100000;
    for (int i = 0; i < n; ++i) {
        text += "http://h" + std::to_string(i) + ".test/\r\n";
    }
    UrlInput in;
    in.assign(text);
    REQUIRE(in.total() == static_cast<size_t>(n));

    const int threads = 8;
    std::vector<std::vector<std::string_view>> got(threads);
    std::vector<std::thread> workers;
    for (int t = 0; t < threads; ++t) {
        workers.emplace_back([&, t] {
            while (in.claim(static_cast<size_t>(1 + t * 7), got[t]) > 0) {
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }
    std::vector<std::string_view> all;
    for (auto& g : got) {
        all.insert(all.end(), g.begin(), g.end());
    }
    REQUIRE(all.size() == static_cast<size_t>(n));
    std::sort(all.begin(), all.end());
    CHECK(std::adjacent_find(all.begin(), all.end()) == all.end());
    CHECK(in.remaining() == 0);
}

TEST_CASE("input: memory-mapped file") {
    const std::string path = temp_file("http://x.org/\r\nhttp://y.org/\r\n");
    {
        UrlInput in;
        std::string err;
        REQUIRE(in.open(path, err));
        CHECK(err.empty());
        const auto lines = drain(in, 64);
        REQUIRE(lines.size() == 2);
        CHECK(lines[0] == "http://x.org/");
        CHECK(lines[1] == "http://y.org/");
    }
    DeleteFileA(path.c_str());

    const std::string empty = temp_file("");
    {
        UrlInput in;
        std::string err;
        CHECK(in.open(empty, err));
        CHECK(in.total() == 0);
    }
    DeleteFileA(empty.c_str());
}

TEST_CASE("input: missing file reports an error") {
    UrlInput in;
    std::string err;
    CHECK_FALSE(in.open("Z:\\definitely\\not\\here\\urls.txt", err));
    CHECK(err.find("cannot open") != std::string::npos);
    CHECK(in.total() == 0);
}
