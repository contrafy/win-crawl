// Link extraction throughput. Built only with -DWINCRAWL_PARSE_BENCH=ON.
// Usage: links_bench [page.html ...]   (synthetic page when no files given)

#include "parse/links.h"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string synthetic_page() {
    std::string html = "<!DOCTYPE html><html><head><title>t</title><script>var a='<a href=x>';</script>"
                       "<style>.c{color:red}</style></head><body>\n";
    for (int i = 0; i < 2000; ++i) {
        html += "<div class=\"item\"><p>Some paragraph text that is typical of a page body, with <b>bold</b> and "
                "<i>italic</i> words.</p><a href=\"/articles/" +
                std::to_string(i) + "?ref=home&amp;x=1\" class=\"link\">Article</a></div>\n";
    }
    html += "</body></html>";
    return html;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> pages;
    for (int i = 1; i < argc; ++i) {
        std::ifstream f(argv[i], std::ios::binary);
        std::ostringstream ss;
        ss << f.rdbuf();
        pages.push_back(ss.str());
    }
    if (pages.empty()) {
        pages.push_back(synthetic_page());
    }
    size_t total_bytes = 0;
    for (const std::string& p : pages) {
        total_bytes += p.size();
    }

    wc::parse::Url base;
    wc::parse::parse_url("http://www.example.com/dir/index.html", base);
    wc::parse::LinkExtractor ex;
    std::vector<wc::parse::Url> out;

    for (const bool collect : {false, true}) {
        size_t links = 0;
        size_t bytes = 0;
        const auto start = std::chrono::steady_clock::now();
        double secs = 0;
        do {
            for (const std::string& p : pages) {
                links += ex.extract(p, base, collect ? &out : nullptr);
                bytes += p.size();
            }
            secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        } while (secs < 2.0);
        std::printf("%-10s %zu pages, %.1f MB corpus, %zu links/pass: %.0f MB/s\n", collect ? "collect" : "count",
                    pages.size(), total_bytes / 1e6, links / (bytes / total_bytes), bytes / secs / 1e6);
    }
    return 0;
}
