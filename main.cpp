// main.cpp
#define _WINSOCK_DEPRECATED_NO_WARNINGS   // silence inet_addr etc.
#define WIN32_LEAN_AND_MEAN

#include "Socket.h"
#include "Crawler.h"
#include <windows.h>
#include <memory>
#include <cstdlib>
#include <cstdio>

#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::printf("Usage: %s <numThreads> <inputFilePath>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const int numThreads = std::atoi(argv[1]);
    if (numThreads < 1) {
        std::puts("Invalid number of threads (>0 required)");
        return EXIT_FAILURE;
    }

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        std::printf("WSAStartup error %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }

    Crawler crawler(numThreads);
    crawler.ReadFile(argv[2]);

    // stats thread
    HANDLE statsThread = CreateThread(nullptr, 0,
        Crawler::StatsThread, &crawler, 0, nullptr);
    if (!statsThread) {
        std::printf("Error creating stats thread: %d\n", GetLastError());
        WSACleanup();
        return EXIT_FAILURE;
    }

    // crawler worker threads – use smart pointer for RAII
    std::unique_ptr<HANDLE[]> threads(new HANDLE[numThreads]);
    for (int i = 0; i < numThreads; ++i) {
        threads[i] = CreateThread(nullptr, 0,
            Crawler::CrawlerThread, &crawler, 0, nullptr);
        if (!threads[i]) {
            std::printf("Error creating crawling thread %d: %d\n", i, GetLastError());
            // close any threads that were created successfully
            for (int j = 0; j < i; ++j) CloseHandle(threads[j]);
            CloseHandle(statsThread);
            WSACleanup();
            return EXIT_FAILURE;
        }
    }

    WaitForMultipleObjects(numThreads, threads.get(), TRUE, INFINITE);
    for (int i = 0; i < numThreads; ++i) CloseHandle(threads[i]);

    crawler.signalShutdown();
    WaitForSingleObject(statsThread, INFINITE);
    CloseHandle(statsThread);

    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    const double totalTime =
        static_cast<double>(end.QuadPart - crawler.getStartTime().QuadPart) /
        crawler.getFrequency().QuadPart;

    std::printf(
        "\n--- FINAL STATS ---------------------------------------------\n"
        "Extracted  %ld URLs     @ %.0f / s\n"
        "Resolved   %ld hosts    @ %.0f / s\n"
        "Checked    %ld robots   @ %.0f / s\n"
        "Crawled    %ld pages    @ %.0f / s (%.2f MB)\n"
        "Parsed     %ld links    @ %.0f / s\n"
        "HTTP 2xx %ld | 3xx %ld | 4xx %ld | 5xx %ld | other %ld\n",
        crawler.getExtractedURLs(), crawler.getExtractedURLs() / totalTime,
        crawler.getUniqueHosts(), crawler.getUniqueHosts() / totalTime,
        crawler.getRobotsChecked(), crawler.getRobotsChecked() / totalTime,
        crawler.getPagesCrawled(), crawler.getPagesCrawled() / totalTime,
        crawler.getTotalBytes() / 1048576.0,
        crawler.getTotalLinks(), crawler.getTotalLinks() / totalTime,
        crawler.getHttp2xx(), crawler.getHttp3xx(),
        crawler.getHttp4xx(), crawler.getHttp5xx(), crawler.getHttpOther());

    WSACleanup();
    return EXIT_SUCCESS;
}
