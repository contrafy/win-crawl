add_library(wc_net STATIC addr.cpp loop.cpp udp.cpp)
target_link_libraries(wc_net PUBLIC wc_options ws2_32 PRIVATE mswsock ntdll)

wc_add_test(net_tests
  SOURCES tests/addr_test.cpp tests/loop_test.cpp tests/udp_test.cpp
  LIBS wc_net)
