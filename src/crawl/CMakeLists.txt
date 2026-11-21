add_library(wc_crawl STATIC
  config.cpp
  connection.cpp
  dedupe.cpp
  engine.cpp
  input.cpp
  stats.cpp)
target_link_libraries(wc_crawl PUBLIC wc_options wc_net wc_parse wc_dns wc_tls)

wc_add_test(crawl_tests
  SOURCES
    tests/config_test.cpp
    tests/dedupe_test.cpp
    tests/input_test.cpp
    tests/stats_test.cpp
  LIBS wc_crawl)

# Loopback end-to-end runs of the engine against in-process fake DNS/HTTP servers.
wc_add_test(crawl_e2e_tests
  SOURCES
    tests/fake_servers.cpp
    tests/connection_test.cpp
    tests/engine_test.cpp
  LIBS wc_crawl)
