add_library(wc_crawl STATIC
  config.cpp
  dedupe.cpp
  input.cpp
  stats.cpp)
target_link_libraries(wc_crawl PUBLIC wc_options)

wc_add_test(crawl_tests
  SOURCES
    tests/config_test.cpp
    tests/dedupe_test.cpp
    tests/input_test.cpp
    tests/stats_test.cpp
  LIBS wc_crawl)
