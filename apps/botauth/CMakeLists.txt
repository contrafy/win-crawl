add_executable(wincrawl-botauth main.cpp)
target_link_libraries(wincrawl-botauth PRIVATE wc_sig advapi32)
# build/<preset>/wincrawl-botauth.exe, next to wincrawl.exe.
set_target_properties(wincrawl-botauth PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
