add_library(wc_tls STATIC tls.cpp)
target_link_libraries(wc_tls PUBLIC wc_options PRIVATE secur32 crypt32)

# The loopback tests run a test-only Schannel server whose key lives in CNG (ncrypt).
wc_add_test(tls_tests SOURCES tests/tls_test.cpp tests/test_server.cpp LIBS wc_tls secur32 crypt32 ncrypt)
