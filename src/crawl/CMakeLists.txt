# Cloudflare's IPv4 ranges are compiled in from the data file (the "cf_ip"
# record field); editing the file re-runs the configure step.
set(WC_CLOUDFLARE_IPV4_FILE ${PROJECT_SOURCE_DIR}/data/cloudflare-ips-v4.txt)
file(READ ${WC_CLOUDFLARE_IPV4_FILE} WC_CLOUDFLARE_IPV4)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${WC_CLOUDFLARE_IPV4_FILE})
configure_file(cloudflare_data.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/cloudflare_data.cpp @ONLY)

add_library(wc_crawl STATIC
  config.cpp
  connection.cpp
  dedupe.cpp
  engine.cpp
  input.cpp
  ipranges.cpp
  politeness.cpp
  record.cpp
  stats.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/cloudflare_data.cpp)
target_link_libraries(wc_crawl PUBLIC wc_options wc_net wc_parse wc_dns wc_tls wc_sig)

wc_add_test(crawl_tests
  SOURCES
    tests/config_test.cpp
    tests/dedupe_test.cpp
    tests/input_test.cpp
    tests/politeness_test.cpp
    tests/record_test.cpp
    tests/stats_test.cpp
  LIBS wc_crawl)

# Loopback end-to-end runs of the engine against in-process fake DNS/HTTP servers.
wc_add_test(crawl_e2e_tests
  SOURCES
    tests/fake_servers.cpp
    tests/connection_test.cpp
    tests/engine_test.cpp
  LIBS wc_crawl)

# Politeness end-to-end: the engine against the benchmark rig's servers, which
# record per-IP concurrency and per-host request times (docs/politeness.md).
wc_add_test(crawl_polite_tests
  SOURCES
    tests/polite_test.cpp
  LIBS wc_crawl wc_benchsrv)
