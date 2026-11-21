cmake_minimum_required(VERSION 3.25)
project(wincrawl LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "wincrawl targets 64-bit Windows only")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(wincrawl main.cpp Crawler.cpp Socket.cpp Utility.cpp)
target_compile_options(wincrawl PRIVATE /W4 /permissive-)
# HTMLParserBase.h selects the course-provided parser library via #pragma comment(lib).
target_link_directories(wincrawl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wincrawl PRIVATE ws2_32)
# The parser library was compiled with /GL; link with /LTCG instead of restarting the link.
target_link_options(wincrawl PRIVATE $<$<CONFIG:Release>:/LTCG>)
