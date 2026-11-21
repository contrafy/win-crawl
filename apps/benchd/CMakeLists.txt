add_executable(wincrawl-benchd main.cpp load.cpp)
target_link_libraries(wincrawl-benchd PRIVATE wc_benchsrv)
