// Crawler.h
#ifndef CRAWLER_H
#define CRAWLER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <queue>
#include <string>
#include <unordered_set>

/**
 * @brief Multi-threaded breadth-first web crawler (WinSock + raw HTTP/1.1).
 *        One Crawler instance coordinates a shared URL queue, maintains
 *        de-duplication sets for hosts & IPs, gathers run-time statistics,
 *        and spawns:
 *            • N worker threads  -> Crawler::CrawlerThread
 *            • 1 stats thread    -> Crawler::StatsThread
 */
class Crawler {
public:
    explicit Crawler(int numThreads);
    ~Crawler();

    /* I/O ------------------------------------------------------------------ */
    void ReadFile(const std::string& inputPath);

    /* Worker & stats entry points (passed to CreateThread) ----------------- */
    static DWORD WINAPI CrawlerThread(LPVOID);
    static DWORD WINAPI StatsThread(LPVOID);

    /* Graceful shutdown ---------------------------------------------------- */
    void signalShutdown();

    /* Public getters (atomic via Interlocked) ------------------------------ */
    LONG  getQueueSize();
    LONG  getExtractedURLs();
    LONG  getUniqueHosts();
    LONG  getDNSLookups();
    LONG  getUniqueIPs();
    LONG  getRobotsChecked();
    LONG  getPagesCrawled();
    LONG  getTotalLinks();
    LONG  getTotalBytes();
    LONG  getHttp2xx();
    LONG  getHttp3xx();
    LONG  getHttp4xx();
    LONG  getHttp5xx();
    LONG  getHttpOther();
    LARGE_INTEGER getStartTime();
    LARGE_INTEGER getFrequency();
    int   getActiveThreads();

private:
    /* Internal helpers ----------------------------------------------------- */
    void   Run();          // executed by each crawler thread
    void   StatsRun();     // executed by stats thread
    void   printStats();   // 2-second periodic console line
    bool   checkAndInsertIP(const std::string& ip);
    bool   checkAndInsertHost(const std::string& host);

    /* Counters updated with Interlocked* ----------------------------------- */
    LONG extractedURLs{}, uniqueHosts{}, dnsLookups{}, uniqueIPs{},
        robotsChecked{}, pagesCrawled{}, totalLinks{}, totalBytes{},
        http2xx{}, http3xx{}, http4xx{}, http5xx{}, httpOther{};

    /* Shared structures ---------------------------------------------------- */
    std::queue<std::string>        urlQueue;
    std::unordered_set<std::string> seenHosts, seenIPs;

    /* Synchronisation ------------------------------------------------------ */
    CRITICAL_SECTION queueCS, hostCS, ipCS;
    volatile LONG     activeThreads{};
    HANDLE            eventQuit{};

    /* Timing --------------------------------------------------------------- */
    LARGE_INTEGER startTime{}, frequency{};

    /* Deleted ops ---------------------------------------------------------- */
    Crawler(const Crawler&) = delete;
    Crawler& operator=(const Crawler&) = delete;
};

#endif // CRAWLER_H
