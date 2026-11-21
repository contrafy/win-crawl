#include "net/addr.h"

#include "doctest/doctest.h"

using namespace wc::net;

TEST_CASE("make_addr and to_string round-trip") {
    const sockaddr_in a = make_addr(htonl(0x7f000001), 8080);
    CHECK(a.sin_family == AF_INET);
    CHECK(ntohs(a.sin_port) == 8080);
    CHECK(to_string(a) == "127.0.0.1:8080");
    CHECK(ipv4_to_string(htonl(0xC0A80A01)) == "192.168.10.1");
    CHECK(ipv4_to_string(0) == "0.0.0.0");
    CHECK(ipv4_to_string(0xffffffff) == "255.255.255.255");
}

TEST_CASE("parse_addr accepts dotted quads with optional port") {
    sockaddr_in out{};
    REQUIRE(parse_addr("10.1.2.3", 53, out));
    CHECK(out.sin_addr.s_addr == htonl(0x0A010203));
    CHECK(ntohs(out.sin_port) == 53);

    REQUIRE(parse_addr("8.8.4.4:5353", 53, out));
    CHECK(out.sin_addr.s_addr == htonl(0x08080404));
    CHECK(ntohs(out.sin_port) == 5353);

    REQUIRE(parse_addr("0.0.0.0:0", 1, out));
    CHECK(out.sin_addr.s_addr == 0);
    CHECK(out.sin_port == 0);
}

TEST_CASE("parse_addr rejects malformed input") {
    sockaddr_in out{};
    for (const char* bad : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4:", "1.2.3.4:65536", "a.b.c.d",
                            "1..2.3", " 1.2.3.4", "1.2.3.4 ", "-1.2.3.4", "1.2.3.4:-1", "1.2.3.4:80:1", "01234.1.1.1"}) {
        CAPTURE(bad);
        CHECK_FALSE(parse_addr(bad, 80, out));
    }
}
