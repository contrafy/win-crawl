#pragma once
// Invariant checks for fuzz targets: print the failed condition, then trap so
// libFuzzer records the input as a crash ("deadly signal").

#include <cstdio>

#define FUZZ_CHECK(cond)                                                                       \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "%s:%d: invariant failed: %s\n", __FILE__, __LINE__, #cond); \
            std::fflush(stderr);                                                               \
            __builtin_trap();                                                                  \
        }                                                                                      \
    } while (0)
