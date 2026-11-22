# Ed25519 from the vendored Monocypher 4.0.3 (CNG has no EdDSA). Compiled as
# C++ so every preset, including fuzz (clang-cl + ASan), builds it with the
# project's own flags; MONOCYPHER_CPP_NAMESPACE (an upstream option) puts the
# API in a namespace instead of extern "C". It is /W4-clean as is.
set(WC_MONOCYPHER_DIR ${PROJECT_SOURCE_DIR}/third_party/monocypher)
set(WC_MONOCYPHER_SOURCES ${WC_MONOCYPHER_DIR}/monocypher.c ${WC_MONOCYPHER_DIR}/monocypher-ed25519.c)
set_source_files_properties(${WC_MONOCYPHER_SOURCES} PROPERTIES LANGUAGE CXX)
add_library(wc_monocypher STATIC ${WC_MONOCYPHER_SOURCES})
target_include_directories(wc_monocypher PUBLIC ${WC_MONOCYPHER_DIR})
target_compile_definitions(wc_monocypher PUBLIC MONOCYPHER_CPP_NAMESPACE=wc_monocypher)
target_link_libraries(wc_monocypher PRIVATE wc_options)

add_library(wc_sig STATIC base64.cpp crypto.cpp httpsig.cpp jwk.cpp sfv.cpp signer.cpp)
target_link_libraries(wc_sig PUBLIC wc_options PRIVATE wc_monocypher bcrypt)

wc_add_test(sig_tests
  SOURCES
    tests/crypto_test.cpp
    tests/sfv_test.cpp
    tests/jwk_test.cpp
    tests/httpsig_test.cpp
  LIBS wc_sig)
