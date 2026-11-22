# libFuzzer targets. Added by the root CMakeLists only with WINCRAWL_BUILD_FUZZ
# (the 'fuzz' preset), where wc_options already compiles everything with ASan
# and coverage instrumentation and links the sanitizer runtimes.

# Executables find the ASan runtime DLL next to them: everything lands in
# CMAKE_RUNTIME_OUTPUT_DIRECTORY except wincrawl.exe (build/<preset>/).
# Copying LLVM's own DLL avoids picking up the different MSVC-ASan DLL of the
# same name from a developer prompt's PATH.
foreach(dir IN ITEMS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} ${PROJECT_BINARY_DIR})
  file(COPY ${WC_CLANG_RT_DIR}/clang_rt.asan_dynamic-x86_64.dll DESTINATION ${dir})
endforeach()

add_library(wc_fuzz_main OBJECT main.cpp)
target_link_libraries(wc_fuzz_main PUBLIC wc_options)

# wc_add_fuzzer(<name> LIBS <targets...>) builds fuzz_<name> from <name>.cpp.
# Its corpus lives in corpus/<name>/ and its dictionary, if any, in dict/<name>.dict.
function(wc_add_fuzzer name)
  cmake_parse_arguments(F "" "" "LIBS" ${ARGN})
  add_executable(fuzz_${name} ${name}.cpp)
  target_link_libraries(fuzz_${name} PRIVATE wc_fuzz_main ${F_LIBS})
  set_property(GLOBAL APPEND PROPERTY WC_FUZZERS fuzz_${name})
endfunction()

wc_add_fuzzer(dns_response LIBS wc_dns)
wc_add_fuzzer(dns_https LIBS wc_dns)
wc_add_fuzzer(http_response LIBS wc_parse)
wc_add_fuzzer(url LIBS wc_parse)
wc_add_fuzzer(robots LIBS wc_parse)
wc_add_fuzzer(links LIBS wc_parse)
wc_add_fuzzer(benchsrv_dns LIBS wc_benchsrv wc_dns)

get_property(wc_fuzzers GLOBAL PROPERTY WC_FUZZERS)
add_custom_target(fuzzers DEPENDS ${wc_fuzzers})
