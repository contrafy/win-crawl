#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include "Socket.h"
#include "pch.h"
#include "Crawler.h"

#include <windows.h>

#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <numThreads> <inputFilePath>\n", argv[0]);
        return 1;
    }

    int numThreads = atoi(argv[1]);
    if (numThreads < 1) {
        printf("Invalid number of threads\n");
        return 1;
    }

    // initialize Winsock once
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup error %d\n", WSAGetLastError());
        return 1;
    }

    Crawler crawler(numThreads);

    crawler.ReadFile(argv[2]);

    // start stats thread
    HANDLE statsThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Crawler::StatsThread, &crawler, 0, NULL);
    if (statsThread == NULL) {
        printf("Error creating stats thread: %d\n", GetLastError());
        WSACleanup();
        return 1;
    }

    // start N crawling threads
    HANDLE* threadHandles = new HANDLE[numThreads];
    for (int i = 0; i < numThreads; i++) {
        threadHandles[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Crawler::CrawlerThread, &crawler, 0, NULL);
        if (threadHandles[i] == NULL) {
            printf("Error creating crawling thread %d: %d\n", i, GetLastError());
            // clean up
            for (int j = 0; j < i; ++j) {
                CloseHandle(threadHandles[j]);
            }
            delete[] threadHandles;
            CloseHandle(statsThread);
            WSACleanup();
            return 1;
        }
    }

    // wait for crawling threads to finish
    for (int i = 0; i < numThreads; i++) {
        WaitForSingleObject(threadHandles[i], INFINITE);
        CloseHandle(threadHandles[i]);
    }

    // signal stats thread to quit and wait for termination
    crawler.signalShutdown();
    WaitForSingleObject(statsThread, INFINITE);
    CloseHandle(statsThread);
        
    // get end time
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    double totalTime = (double)(endTime.QuadPart - crawler.getStartTime().QuadPart) / crawler.getFrequency().QuadPart;

    // print final summary
    printf("Extracted %ld URLs @ %.0f/s\n", crawler.getExtractedURLs(), crawler.getExtractedURLs() / totalTime);
    printf("Looked up %ld DNS names @ %.0f/s\n", crawler.getUniqueHosts(), crawler.getUniqueHosts() / totalTime);
    printf("Attempted %ld site robots @ %.0f/s\n", crawler.getUniqueIPs(), crawler.getUniqueIPs() / totalTime);
    printf("Crawled %ld pages @ %.0f/s (%.2f MB)\n", crawler.getPagesCrawled(), crawler.getPagesCrawled() / totalTime, crawler.getTotalBytes() / (1024.0 * 1024.0));
    printf("Parsed %ld links @ %.0f/s\n", crawler.getTotalLinks(), crawler.getTotalLinks() / totalTime);
    printf("HTTP codes: 2xx = %ld, 3xx = %ld, 4xx = %ld, 5xx = %ld, other = %ld\n", crawler.getHttp2xx(), crawler.getHttp3xx(), crawler.getHttp4xx(), crawler.getHttp5xx(), crawler.getHttpOther());

    // printf("Pages with TAMU.edu links: %ld\n", crawler.getTamuLinkPages());
    // printf(" - Originating from outside TAMU: %ld\n", crawler.getTamuLinkPagesExternal());
    // cleanup
    // delete[] threadHandles;
    WSACleanup();

    return 0;
}