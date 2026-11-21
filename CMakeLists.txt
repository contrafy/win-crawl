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

# Shared compile settings; every wincrawl target links this.
add_library(wc_options INTERFACE)
target_compile_options(wc_options INTERFACE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
target_compile_definitions(wc_options INTERFACE
  WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
target_include_directories(wc_options INTERFACE ${PROJECT_SOURCE_DIR}/src)

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

# Original coursework crawler (thread per connection), kept until the new engine replaces it.
add_executable(wincrawl_legacy main.cpp Crawler.cpp Socket.cpp Utility.cpp)
target_compile_options(wincrawl_legacy PRIVATE /W3)
# HTMLParserBase.h selects the course-provided parser library via #pragma comment(lib).
target_link_directories(wincrawl_legacy PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(wincrawl_legacy PRIVATE ws2_32)
