// main() for every fuzz target. The whole fuzz tree links libFuzzer without
// its main() (clang_rt.fuzzer_no_main, see the root CMakeLists.txt), so unit
// tests and apps keep their own; fuzz targets start the driver here.

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerRunDriver(int* argc, char*** argv, int (*callback)(const uint8_t* data, size_t size));

int main(int argc, char** argv) {
    return LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
