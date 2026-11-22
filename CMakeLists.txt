cmake_minimum_required(VERSION 3.25)
project(wincrawl VERSION 2.0.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "wincrawl targets 64-bit Windows only")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

option(WINCRAWL_BUILD_TESTS "Build unit tests" ON)
option(WINCRAWL_BUILD_FUZZ "Build the libFuzzer targets under fuzz/ (clang-cl only; instruments every target with ASan)" OFF)

if(WINCRAWL_BUILD_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    message(FATAL_ERROR "WINCRAWL_BUILD_FUZZ requires clang-cl (use the 'fuzz' preset)")
  endif()
  # LLVM's Windows libFuzzer runtime is built /MT with MSVC STL container
  # annotations off (it records both via /FAILIFMISMATCH), so every object it
  # links with must match.
  set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
  # One output directory, so the ASan runtime DLL copied there (fuzz/) is
  # found by every instrumented executable, unit tests included.
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
  execute_process(COMMAND ${CMAKE_CXX_COMPILER} /clang:-print-resource-dir
    OUTPUT_VARIABLE WC_CLANG_RESOURCE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
  file(TO_CMAKE_PATH "${WC_CLANG_RESOURCE_DIR}/lib/windows" WC_CLANG_RT_DIR)
  # LLVM >= 20 layout: one ASan DLL, reached through a thunk under /MT.
  foreach(lib IN ITEMS fuzzer_no_main asan_dynamic asan_static_runtime_thunk)
    if(NOT EXISTS "${WC_CLANG_RT_DIR}/clang_rt.${lib}-x86_64.lib")
      message(FATAL_ERROR "clang_rt.${lib}-x86_64.lib not found in ${WC_CLANG_RT_DIR} (needs LLVM >= 20 with compiler-rt)")
    endif()
  endforeach()
endif()

# Shared compile settings; every wincrawl target links this. clang-cl accepts
# the same switches (/W4 maps to -Wall -Wextra).
add_library(wc_options INTERFACE)
target_compile_options(wc_options INTERFACE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
target_compile_definitions(wc_options INTERFACE
  WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
target_include_directories(wc_options INTERFACE ${PROJECT_SOURCE_DIR}/src)
if(WINCRAWL_BUILD_FUZZ)
  # Every target gets ASan plus libFuzzer's coverage instrumentation, so the
  # unit tests and apps of this tree run under ASan too. CMake links clang-cl
  # targets with lld-link directly (not through the clang driver), so the
  # runtimes are named explicitly: ASan for /MT, and libFuzzer without its
  # main(), which defines the coverage callbacks for every executable; the fuzz
  # targets supply main() themselves (fuzz/main.cpp).
  target_compile_options(wc_options INTERFACE -fsanitize=address -fsanitize=fuzzer-no-link)
  target_compile_definitions(wc_options INTERFACE _DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION)
  target_link_directories(wc_options INTERFACE ${WC_CLANG_RT_DIR})
  target_link_libraries(wc_options INTERFACE
    clang_rt.asan_dynamic-x86_64.lib clang_rt.asan_static_runtime_thunk-x86_64.lib
    clang_rt.fuzzer_no_main-x86_64.lib)
endif()

if(WINCRAWL_BUILD_TESTS)
  enable_testing()
  add_library(wc_doctest STATIC ${PROJECT_SOURCE_DIR}/third_party/doctest/doctest_main.cpp)
  target_include_directories(wc_doctest PUBLIC ${PROJECT_SOURCE_DIR}/third_party)
  target_link_libraries(wc_doctest PUBLIC wc_options)
  # Include real std headers instead of doctest's forward declarations (MSVC C5285).
  target_compile_definitions(wc_doctest PUBLIC DOCTEST_CONFIG_USE_STD_HEADERS)
endif()

# wc_add_test(<name> SOURCES <files...> LIBS <targets...>)
# Builds a doctest executable and registers it with CTest. No-op when tests are disabled.
function(wc_add_test name)
  if(NOT WINCRAWL_BUILD_TESTS)
    return()
  endif()
  cmake_parse_arguments(T "" "" "SOURCES;LIBS" ${ARGN})
  add_executable(${name} ${T_SOURCES})
  target_link_libraries(${name} PRIVATE wc_doctest ${T_LIBS})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

# Each module under src/ and each program under apps/ owns its CMakeLists.txt.
file(GLOB WC_MODULE_LISTS CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/src/*/CMakeLists.txt
  ${PROJECT_SOURCE_DIR}/apps/*/CMakeLists.txt)
foreach(list_file IN LISTS WC_MODULE_LISTS)
  get_filename_component(module_dir ${list_file} DIRECTORY)
  add_subdirectory(${module_dir})
endforeach()

if(WINCRAWL_BUILD_FUZZ)
  add_subdirectory(fuzz)
endif()
