add_library(wc_parse STATIC url.cpp http.cpp links.cpp robots.cpp)
target_link_libraries(wc_parse PUBLIC wc_options)

wc_add_test(parse_tests
  SOURCES tests/url_test.cpp tests/http_test.cpp tests/links_test.cpp tests/robots_test.cpp
  LIBS wc_parse)

# Throwaway link-extraction throughput benchmark; off by default.
option(WINCRAWL_PARSE_BENCH "Build the wc_parse link extraction benchmark" OFF)
if(WINCRAWL_PARSE_BENCH)
  add_executable(links_bench bench/links_bench.cpp)
  target_link_libraries(links_bench PRIVATE wc_parse)
endif()
