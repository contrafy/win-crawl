add_library(wc_net STATIC addr.cpp loop.cpp tcp.cpp udp.cpp)
target_link_libraries(wc_net PUBLIC wc_options ws2_32 PRIVATE mswsock ntdll)

wc_add_test(net_tests
  SOURCES tests/addr_test.cpp tests/loop_test.cpp tests/udp_test.cpp tests/tcp_test.cpp
  LIBS wc_net)
# Separate executable: it is the slowest and keeps the unit suite well under budget.
wc_add_test(net_stress_tests SOURCES tests/tcp_stress_test.cpp LIBS wc_net)
