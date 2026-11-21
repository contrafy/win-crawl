add_executable(wincrawl main.cpp)
target_link_libraries(wincrawl PRIVATE wc_crawl)
# build/<preset>/wincrawl.exe, next to the legacy binary, for scripts and docs.
set_target_properties(wincrawl PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
