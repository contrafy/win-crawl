add_executable(wincrawl main.cpp)
target_link_libraries(wincrawl PRIVATE wc_crawl)
# build/<preset>/wincrawl.exe: a stable path for scripts and docs.
set_target_properties(wincrawl PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
