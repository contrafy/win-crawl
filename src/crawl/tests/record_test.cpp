#include "crawl/ipranges.h"
#include "crawl/record.h"

#include "doctest/doctest.h"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace wc::crawl;

namespace {

std::string json(std::string_view s) {
    std::string out;
    append_json_string(out, s);
    return out;
}

uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return static_cast<uint32_t>(a) | static_cast<uint32_t>(b) << 8 | static_cast<uint32_t>(c) << 16 |
           static_cast<uint32_t>(d) << 24;
}

// Parses a complete reply into `buf`/`parser`.
void parse_reply(std::string& buf, wc::parse::ResponseParser& parser) {
    parser.reset(false, 1 << 20);
    REQUIRE(parser.parse(buf.data(), buf.size()) == wc::parse::ParseStatus::Done);
}

std::string temp_path(const char* name) {
    char dir[MAX_PATH];
    REQUIRE(GetTempPathA(MAX_PATH, dir) != 0);
    return std::string(dir) + name + std::to_string(GetCurrentProcessId()) + ".jsonl";
}

}  // namespace

TEST_CASE("record: JSON string escaping") {
    CHECK(json("") == R"("")");
    CHECK(json("plain text/1.0") == R"("plain text/1.0")");
    CHECK(json("a\"b\\c") == R"("a\"b\\c")");
    CHECK(json("\n\r\t\b\f") == R"("\n\r\t\b\f")");
    CHECK(json(std::string_view("\x00\x01\x1f", 3)) == R"("\u0000\u0001\u001f")");
    CHECK(json("\x7f") == "\"\x7f\"");  // DEL is legal in JSON strings
    // Well-formed UTF-8 passes through.
    CHECK(json("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80") == "\"caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80\"");
    // Ill-formed bytes become \u00XX one by one.
    CHECK(json("\xff") == R"("\u00ff")");
    CHECK(json("a\xc3") == R"("a\u00c3")");                      // truncated sequence
    CHECK(json("\xc3(") == R"("\u00c3(")");                      // bad continuation
    CHECK(json("\xc0\xaf") == R"("\u00c0\u00af")");              // overlong
    CHECK(json("\xe0\x80\xaf") == R"("\u00e0\u0080\u00af")");    // overlong 3-byte
    CHECK(json("\xed\xa0\x80") == R"("\u00ed\u00a0\u0080")");    // UTF-16 surrogate
    CHECK(json("\xf4\x90\x80\x80") == R"("\u00f4\u0090\u0080\u0080")");  // > U+10FFFF
    CHECK(json("\x80x") == R"("\u0080x")");                      // stray continuation
}

TEST_CASE("record: truncate_utf8 never splits a sequence") {
    CHECK(truncate_utf8("abcdef", 3) == "abc");
    CHECK(truncate_utf8("ab", 3) == "ab");
    CHECK(truncate_utf8("a\xc3\xa9z", 2) == "a");
    CHECK(truncate_utf8("a\xc3\xa9z", 3) == "a\xc3\xa9");
    CHECK(truncate_utf8("\xf0\x9f\x98\x80", 3).empty());
}

TEST_CASE("record: Alt-Svc h3 detection") {
    CHECK(alt_svc_has_h3(R"(h3=":443"; ma=86400)"));
    CHECK(alt_svc_has_h3(R"(h2=":443", h3=":443"; ma=2592000)"));
    CHECK(alt_svc_has_h3(R"(h3-29=":443"; ma=86400, h3-Q050=":443")"));
    CHECK(alt_svc_has_h3(R"(  h2="alt.example:443" ;ma=60 ,  h3="alt.example:443")"));
    CHECK_FALSE(alt_svc_has_h3("clear"));
    CHECK_FALSE(alt_svc_has_h3(R"(h2=":443"; ma=86400)"));
    CHECK_FALSE(alt_svc_has_h3(R"(h3x=":443")"));
    CHECK_FALSE(alt_svc_has_h3(R"(quic=":443"; ma=2592000; v="46,43")"));
    // A comma inside a quoted value does not start a new alternative.
    CHECK_FALSE(alt_svc_has_h3(R"(h2="a,h3=:443")"));
    CHECK_FALSE(alt_svc_has_h3(""));
    CHECK_FALSE(alt_svc_has_h3("h3"));  // no "=alt-authority"
}

TEST_CASE("record: HSTS parsing") {
    Hsts h = parse_hsts("max-age=31536000; includeSubDomains; preload");
    CHECK(h.valid);
    CHECK(h.max_age == 31536000);
    CHECK(h.include_subdomains);
    CHECK(h.preload);

    h = parse_hsts("MAX-AGE=\"600\"");
    CHECK(h.valid);
    CHECK(h.max_age == 600);
    CHECK_FALSE(h.include_subdomains);

    h = parse_hsts(" includesubdomains ; max-age = 0 ;");
    CHECK(h.valid);
    CHECK(h.max_age == 0);
    CHECK(h.include_subdomains);

    CHECK(parse_hsts("max-age=99999999999999999999999").max_age == std::numeric_limits<uint64_t>::max());
    CHECK(parse_hsts("max-age=1; foo=\"a;b\"").valid);  // unknown directives are ignored
    CHECK_FALSE(parse_hsts("").valid);
    CHECK_FALSE(parse_hsts("includeSubDomains").valid);         // max-age is required
    CHECK_FALSE(parse_hsts("max-age=abc").valid);
    CHECK_FALSE(parse_hsts("max-age=-1").valid);
    CHECK_FALSE(parse_hsts("max-age=1; max-age=2").valid);      // repeated directive
    CHECK_FALSE(parse_hsts("max-age=1; preload; preload").valid);
}

TEST_CASE("record: an unreached site serializes with nulls") {
    SiteRecord r;
    r.url = "http://nx.test/";
    r.host = "nx.test";
    r.dns = "nxdomain";
    r.ms = 12;
    std::string out;
    r.append_json(out);
    CHECK(out ==
          R"({"url":"http://nx.test/","host":"nx.test","dns":"nxdomain","ip":null,"ip_dup":null,"cf_ip":null,)"
          R"("https_rr":null,"robots_status":null,"robots_error":null,"robots_allowed":null,"fetch":null,)"
          R"("status":null,"redirects":null,"final_url":null,"https_upgrade":null,"tls":null,"alt_svc_h3":null,)"
          R"("hsts":null,"hsts_max_age":null,"hsts_sub":null,"hsts_preload":null,"server":null,"cf_ray":null,)"
          R"("content_type":null,"bytes":null,"links":null,"ms":12,"skip":null,"wait_ms":0,"crawl_delay":null,)"
          R"("crawl_delay_ms":0,"retry_after":null,"retried":null})"
          "\n");
}

TEST_CASE("record: a fetched https site serializes every field") {
    SiteRecord r;
    r.url = "http://a.test/x?q=\"1\"";
    r.host = "a.test";
    r.dns = "ok";
    r.has_ip = true;
    r.ip = ip(104, 16, 1, 2);
    r.ip_dup = false;
    r.cf_ip = true;
    r.https_rr.status = "ok";
    r.https_rr.present = true;
    r.https_rr.h3 = true;
    r.https_rr.h2 = true;
    r.robots_status = 404;
    r.robots_allowed = true;
    r.fetch = "ok";
    r.redirects = 1;
    r.cf_ray = true;
    r.tls.handshake = "ok";
    r.tls.protocol = 0x00002000;  // SP_PROT_TLS1_3_CLIENT
    r.tls.cipher = "TLS_AES_128_GCM_SHA256";
    r.tls.group = "X25519MLKEM768";
    r.tls.pq = true;
    r.tls.resumed = false;
    r.ms = 345;
    r.skip = "crawl_delay";
    r.wait_ms = 1500;
    r.crawl_delay = 0.5;
    r.crawl_delay_ms = 500;
    r.retry_after = 1;
    r.retried = true;

    std::string reply =
        "HTTP/1.1 200 OK\r\nServer: cloud\"flare\r\nContent-Type: text/html; charset=utf-8\r\n"
        "Alt-Svc: h2=\":443\"\r\nalt-svc: h3=\":443\"; ma=86400\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\nContent-Length: 5\r\n\r\nhello";
    wc::parse::ResponseParser parser;
    parse_reply(reply, parser);
    wc::parse::Url final_url;
    REQUIRE(wc::parse::parse_url("https://www.a.test/x", final_url));
    r.set_page_reply(parser, final_url, parser.body());
    r.links = 7;

    std::string out;
    r.append_json(out);
    CHECK(out ==
          R"({"url":"http://a.test/x?q=\"1\"","host":"a.test","dns":"ok","ip":"104.16.1.2","ip_dup":false,"cf_ip":true,)"
          R"("https_rr":{"status":"ok","present":true,"alias":false,"h3":true,"h2":true,"ech":false},)"
          R"("robots_status":404,"robots_error":null,"robots_allowed":true,"fetch":"ok","status":200,"redirects":1,)"
          R"("final_url":"https://www.a.test/x","https_upgrade":true,)"
          R"("tls":{"handshake":"ok","version":"TLS 1.3","cipher":"TLS_AES_128_GCM_SHA256","group":"X25519MLKEM768",)"
          R"("pq":true,"resumed":false},"alt_svc_h3":true,"hsts":true,"hsts_max_age":31536000,"hsts_sub":true,)"
          R"("hsts_preload":false,"server":"cloud\"flare","cf_ray":true,"content_type":"text/html; charset=utf-8",)"
          R"("bytes":5,"links":7,"ms":345,"skip":"crawl_delay","wait_ms":1500,"crawl_delay":0.5,"crawl_delay_ms":500,)"
          R"("retry_after":1,"retried":true})"
          "\n");
}

TEST_CASE("record: page reply fields follow the last reply; clear() resets") {
    SiteRecord r;
    wc::parse::ResponseParser parser;
    wc::parse::Url u;

    // An https redirect hop with HSTS, then a plain-http final reply: HSTS
    // over http does not count, and the earlier hop's values are replaced.
    std::string hop = "HTTP/1.1 301 Moved\r\nStrict-Transport-Security: max-age=5\r\nLocation: /\r\n"
                      "Content-Length: 0\r\n\r\n";
    parse_reply(hop, parser);
    REQUIRE(wc::parse::parse_url("https://b.test/", u));
    r.set_page_reply(parser, u, parser.body());
    CHECK(r.hsts == true);
    CHECK(r.hsts_max_age == 5u);

    std::string last = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=5\r\n"
                       "Server: " + std::string(100, 's') + "\r\nContent-Length: 0\r\n\r\n";
    parse_reply(last, parser);
    REQUIRE(wc::parse::parse_url("http://b.test/", u));
    r.set_page_reply(parser, u, parser.body());
    CHECK_FALSE(r.hsts.has_value());
    CHECK_FALSE(r.hsts_max_age.has_value());
    CHECK(r.alt_svc_h3 == false);
    CHECK(r.status == 200);
    CHECK(r.server.size() == 64);
    CHECK_FALSE(r.has_content_type);
    CHECK(r.final_url == "http://b.test/");

    r.skip = "ip_budget";
    r.wait_ms = 7;
    r.crawl_delay = 2;
    r.crawl_delay_ms = 3;
    r.retry_after = 4;
    r.retried = false;
    r.clear();
    std::string out;
    r.append_json(out);
    CHECK(out.find("\"status\":null") != std::string::npos);
    CHECK(out.find("\"final_url\":null") != std::string::npos);
    CHECK(out.find("\"server\":null") != std::string::npos);
    CHECK(out.find("\"skip\":null,\"wait_ms\":0,\"crawl_delay\":null,\"crawl_delay_ms\":0,\"retry_after\":null,"
                   "\"retried\":null}") != std::string::npos);
}

TEST_CASE("record: IPv4 range sets") {
    Ipv4Ranges r;
    std::string error;
    REQUIRE(r.parse("# comment\n10.0.0.0/8\r\n\n192.168.1.0/24  # trailing\n10.1.0.0/16\n0.0.0.0/32\n", error));
    CHECK(r.size() == 3);  // 10.1/16 merges into 10/8
    CHECK(r.contains(ip(10, 0, 0, 0)));
    CHECK(r.contains(ip(10, 255, 255, 255)));
    CHECK(r.contains(ip(192, 168, 1, 77)));
    CHECK(r.contains(ip(0, 0, 0, 0)));
    CHECK_FALSE(r.contains(ip(0, 0, 0, 1)));
    CHECK_FALSE(r.contains(ip(11, 0, 0, 0)));
    CHECK_FALSE(r.contains(ip(192, 168, 2, 0)));
    CHECK_FALSE(r.contains(ip(9, 255, 255, 255)));
    CHECK_FALSE(r.parse("10.0.0.0/33\n", error));
    CHECK(error.find("line 1") != std::string::npos);
    CHECK_FALSE(r.parse("ok\n", error));
    CHECK_FALSE(r.parse("1.2.3.4\n", error));

    Ipv4Ranges all;
    REQUIRE(all.parse("0.0.0.0/0", error));
    CHECK(all.contains(ip(255, 255, 255, 255)));
}

TEST_CASE("record: compiled-in Cloudflare ranges") {
    const Ipv4Ranges& cf = cloudflare_ipv4();
    CHECK(cf.size() > 5);
    CHECK(cf.contains(ip(104, 16, 0, 1)));
    CHECK(cf.contains(ip(172, 67, 1, 1)));
    CHECK(cf.contains(ip(1, 1, 1, 1)) == false);  // the resolver, not the proxy ranges
    CHECK_FALSE(cf.contains(ip(8, 8, 8, 8)));
}

TEST_CASE("record: writer collects buffers from many threads into one file") {
    const std::string path = temp_path("wc_record_test_");
    RecordWriter writer;
    std::string error;
    REQUIRE(writer.open(path, error));
    constexpr int kThreads = 8;
    constexpr int kLines = 5000;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&writer, t] {
            std::string buf;
            for (int i = 0; i < kLines; ++i) {
                buf += "{\"t\":" + std::to_string(t) + ",\"i\":" + std::to_string(i) + "}\n";
                if (buf.size() > 4096) {
                    writer.submit(buf);
                    CHECK(buf.empty());
                }
            }
            writer.submit(buf);
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    REQUIRE(writer.close());
    CHECK(writer.close());  // idempotent

    std::ifstream in(path, std::ios::binary);
    std::string line;
    std::vector<int> next(kThreads, 0);
    size_t lines = 0;
    uint64_t bytes = 0;
    while (std::getline(in, line)) {
        ++lines;
        bytes += line.size() + 1;
        int t = -1;
        int i = -1;
        REQUIRE(std::sscanf(line.c_str(), "{\"t\":%d,\"i\":%d}", &t, &i) == 2);
        REQUIRE(t >= 0);
        REQUIRE(t < kThreads);
        CHECK(i == next[t]);  // one thread's buffers stay in submission order
        next[t] = i + 1;
    }
    in.close();
    CHECK(lines == static_cast<size_t>(kThreads * kLines));
    CHECK(bytes == writer.bytes_written());
    DeleteFileA(path.c_str());
}

TEST_CASE("record: writer reports an unopenable path") {
    RecordWriter writer;
    std::string error;
    CHECK_FALSE(writer.open("Z:\\no\\such\\dir\\x.jsonl", error));
    CHECK(error.find("cannot create") != std::string::npos);
    CHECK_FALSE(writer.is_open());
}
