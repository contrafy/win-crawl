#pragma once
// Process CPU usage between samples, in percent of one logical CPU
// (800% = eight cores busy).

#include <windows.h>

#include <chrono>
#include <cstdint>

namespace wc::benchd {

class CpuMeter {
public:
    CpuMeter() { sample(last_cpu_, last_wall_); }

    double sample_percent() {
        uint64_t cpu;
        std::chrono::steady_clock::time_point wall;
        sample(cpu, wall);
        const double wall_s = std::chrono::duration<double>(wall - last_wall_).count();
        const double cpu_s = static_cast<double>(cpu - last_cpu_) / 1e7;  // 100 ns units
        last_cpu_ = cpu;
        last_wall_ = wall;
        return wall_s > 0 ? 100.0 * cpu_s / wall_s : 0.0;
    }

    // Total process CPU seconds (user + kernel).
    static double total_seconds() {
        uint64_t cpu;
        std::chrono::steady_clock::time_point wall;
        sample(cpu, wall);
        return static_cast<double>(cpu) / 1e7;
    }

private:
    static void sample(uint64_t& cpu, std::chrono::steady_clock::time_point& wall) {
        FILETIME create, exit, kernel, user;
        GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user);
        const auto to64 = [](const FILETIME& f) { return (static_cast<uint64_t>(f.dwHighDateTime) << 32) | f.dwLowDateTime; };
        cpu = to64(kernel) + to64(user);
        wall = std::chrono::steady_clock::now();
    }

    uint64_t last_cpu_ = 0;
    std::chrono::steady_clock::time_point last_wall_;
};

}  // namespace wc::benchd
