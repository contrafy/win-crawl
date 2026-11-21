add_library(wc_benchsrv STATIC
  behavior.cpp
  dns_server.cpp
  http_server.cpp
  responses.cpp
  urlgen.cpp)
target_link_libraries(wc_benchsrv PUBLIC wc_options wc_net)

wc_add_test(benchsrv_tests
  SOURCES
    tests/behavior_test.cpp
    tests/dns_server_test.cpp
    tests/http_server_test.cpp
  LIBS wc_benchsrv)
