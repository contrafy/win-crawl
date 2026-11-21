add_library(wc_dns STATIC packet.cpp servers.cpp)
target_link_libraries(wc_dns PUBLIC wc_options PRIVATE iphlpapi ws2_32)

wc_add_test(dns_tests SOURCES tests/packet_test.cpp tests/servers_test.cpp LIBS wc_dns)
