// Crawler.cpp
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include "Crawler.h"
#include "HTMLParserBase.h"
#include "Socket.h"
#include "Utility.h"

#include <windows.h>
#include <fstream>
#include <regex>
#include <vector>
#include <iostream>
#include <cstdlib>

Crawler::Crawler(int numThreads)
{
    InitializeCriticalSection(&queueCS);
    InitializeCriticalSection(&hostCS);
    InitializeCriticalSection(&ipCS);

    eventQuit = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    activeThreads = numThreads;

    if (!eventQuit) {
        std::fprintf(stderr, "CreateEvent failed (%d)\n", GetLastError());
        std::exit(EXIT_FAILURE);
    }
}

Crawler::~Crawler()
{
    DeleteCriticalSection(&queueCS);
    DeleteCriticalSection(&hostCS);
    DeleteCriticalSection(&ipCS);
    CloseHandle(eventQuit);
}

void Crawler::ReadFile(const std::string& path)
{
    std::ifstream in(path);
    if (!in) {
        std::cerr << "Cannot open " << path << '\n';
        std::exit(EXIT_FAILURE);
    }

    in.seekg(0, std::ios::end);
    const auto sz = in.tellg();
    in.seekg(0);
    std::printf("Loaded seed list (%lld bytes)\n", static_cast<long long>(sz));

    std::string line;
    while (std::getline(in, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (!line.empty()) urlQueue.push(line);
    }
}

void Crawler::Run()
{
    HTMLParserBase parser;
    Socket         sock;

    std::string url, scheme, host, request, response;
    int          port{}, status{};
    char         ipBuf[INET_ADDRSTRLEN]{};

    const size_t ROBOTS_LIMIT = 16 * 1024;       // 16 KiB
    const size_t PAGE_LIMIT = 2 * 1024 * 1024; // 2 MiB

    while (true)
    {
        /* ----------- pop URL ------------------------------------------- */
        EnterCriticalSection(&queueCS);
        if (urlQueue.empty()) {
            LeaveCriticalSection(&queueCS);
            break;
        }
        url = urlQueue.front();
        urlQueue.pop();
        LeaveCriticalSection(&queueCS);
        InterlockedIncrement(&extractedURLs);

        /* ----------- parse URL ----------------------------------------- */
        if (!parseURL(url, scheme, host, port, request)) continue;
        if (!checkAndInsertHost(host))                    continue;
        InterlockedIncrement(&uniqueHosts);

        /* ----------- DNS ---------------------------------------------- */
        if (!sock.resolveDNS(host)) continue;
        InterlockedIncrement(&dnsLookups);

        in_addr addr = sock.getResolvedAddress();
        if (!inet_ntop(AF_INET, &addr, ipBuf, sizeof ipBuf)) continue;
        if (!checkAndInsertIP(ipBuf)) continue;
        InterlockedIncrement(&uniqueIPs);

        /* ----------- robots.txt (HEAD) -------------------------------- */
        if (!sock.connect(host, port) ||
            !sock.sendHTTPRequest(host, "/robots.txt", "HEAD") ||
            !sock.receiveResponse(response, status, ROBOTS_LIMIT))
        {
            sock.close(); continue;
        }

        InterlockedIncrement(&robotsChecked);
        if (status < 400 || status >= 500) { sock.close(); continue; } // obey robots

        /* ----------- target page (GET) -------------------------------- */
        sock.close();                              // fresh TCP improves robustness
        if (!sock.connect(host, port) ||
            !sock.sendHTTPRequest(host, request, "GET") ||
            !sock.receiveResponse(response, status, PAGE_LIMIT))
        {
            sock.close(); continue;
        }

        const LONG respBytes = static_cast<LONG>(response.length());
        InterlockedAdd(&totalBytes, respBytes);
        InterlockedIncrement(&pagesCrawled);

        /* ----------- status buckets + link extraction ----------------- */
        incrementHttpStatus(status);

        if (status >= 200 && status < 300) {
            size_t bodyPos = response.find("\r\n\r\n");
            if (bodyPos != std::string::npos) {
                const char* html = response.data() + bodyPos + 4;
                const int   htmlLen = static_cast<int>(response.length() - bodyPos - 4);

                int nLinks = 0;
                char* links = parser.Parse(
                    const_cast<char*>(html), htmlLen,
                    const_cast<char*>(("http://" + host).c_str()),
                    0, &nLinks);

                if (nLinks > 0) InterlockedAdd(&totalLinks, nLinks);
                free(links);                                    // HTMLParser allocs via malloc
            }
        }

        sock.close();
    }

    InterlockedDecrement(&activeThreads);
}

/* --------------------- misc helpers ------------------------------------ */
bool Crawler::checkAndInsertIP(const std::string& ip)
{
    EnterCriticalSection(&ipCS);
    const bool fresh = seenIPs.insert(ip).second;
    LeaveCriticalSection(&ipCS);
    return fresh;
}

bool Crawler::checkAndInsertHost(const std::string& host)
{
    EnterCriticalSection(&hostCS);
    const bool fresh = seenHosts.insert(host).second;
    LeaveCriticalSection(&hostCS);
    return fresh;
}

/* --------------------- stats thread ------------------------------------ */
void Crawler::printStats()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    const double t = (now.QuadPart - startTime.QuadPart) / static_cast<double>(frequency.QuadPart);

    std::printf("[T%5.1f] Q:%6ld  E:%7ld  H:%6ld  D:%5ld  P:%5ld  L:%5ldk  Thr:%2d\n",
        t, getQueueSize(), getExtractedURLs(), getUniqueHosts(), getDNSLookups(),
        getPagesCrawled(), getTotalLinks() / 1000, getActiveThreads());
}

void Crawler::StatsRun()
{
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);

    LONG lastPages = 0, lastBytes = 0;
    LARGE_INTEGER lastTick = startTime;

    while (WaitForSingleObject(eventQuit, 2000) == WAIT_TIMEOUT)
    {
        printStats();

        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        const double dt = (now.QuadPart - lastTick.QuadPart) / static_cast<double>(frequency.QuadPart);

        const LONG pages = getPagesCrawled();
        const LONG bytes = getTotalBytes();
        std::printf("        %.1f pps  %.1f Mbps\n",
            (pages - lastPages) / dt,
            ((bytes - lastBytes) * 8.0) / (dt * 1024 * 1024));

        lastPages = pages;
        lastBytes = bytes;
        lastTick = now;
    }
}

DWORD WINAPI Crawler::CrawlerThread(LPVOID p) { static_cast<Crawler*>(p)->Run();        return 0; }
DWORD WINAPI Crawler::StatsThread(LPVOID p) { static_cast<Crawler*>(p)->StatsRun();    return 0; }

/* --------------------- trivial atomics --------------------------------- */
#define ATOM(name) LONG Crawler::name() { return InterlockedCompareExchange(&name,0,0); }
ATOM(getExtractedURLs)  ATOM(getUniqueHosts)  ATOM(getDNSLookups)
ATOM(getUniqueIPs)      ATOM(getRobotsChecked) ATOM(getPagesCrawled)
ATOM(getTotalLinks)     ATOM(getTotalBytes)    ATOM(getHttp2xx)
ATOM(getHttp3xx)        ATOM(getHttp4xx)       ATOM(getHttp5xx)
ATOM(getHttpOther)

LONG Crawler::getQueueSize()
{
    EnterCriticalSection(&queueCS);
    const LONG sz = static_cast<LONG>(urlQueue.size());
    LeaveCriticalSection(&queueCS);
    return sz;
}

LARGE_INTEGER Crawler::getStartTime() { return startTime; }
LARGE_INTEGER Crawler::getFrequency() { return frequency; }
int  Crawler::getActiveThreads() { return InterlockedCompareExchange(&activeThreads, 0, 0); }

void Crawler::signalShutdown() { SetEvent(eventQuit); }

