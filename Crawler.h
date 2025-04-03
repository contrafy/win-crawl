#ifndef CRAWLER_H
#define CRAWLER_H
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <string>
#include <queue>
#include <unordered_set>
#include <windows.h>

class Crawler {
    public:
        Crawler(int numThreads);

        ~Crawler();
        
        // read URLs from file and populate queue
        void ReadFile(const std::string& filename);

        // crawling thread function
        void Run();

        // signal all threads to shutdown
        void signalShutdown();

        // help keep track of active threads
        void decrementActiveThreads();
        int getActiveThreads();

        // print statistics per two seconds
        void printStats();
        void StatsRun();

        // get start time
        LARGE_INTEGER getStartTime();
        // check and insert into seenIPs and seenHosts queues (thread safe)
        bool checkAndInsertIP(const std::string& ipAddr);
        bool checkAndInsertHost(const std::string& host);

        // thread workers
        static DWORD WINAPI CrawlerThread(LPVOID param);
        static DWORD WINAPI StatsThread(LPVOID param);

        // update stats
        void incrementExtractedURLs();
        void incrementUniqueHosts();
        void incrementDNSLookups();
        void incrementUniqueIPs();
        void incrementRobotsChecked();
        void incrementRobotsPassed();
        void incrementPagesCrawled();
        void incrementHttpStatus(int statusCode);
        void addTotalLinks(LONG links);
        void addTotalBytes(LONG bytes);

        // get stats
        LONG getExtractedURLs();
        LONG getUniqueHosts();
        LONG getDNSLookups();
        LONG getUniqueIPs();
        LONG getRobotsChecked();
        LONG getRobotsPassed();
        LONG getPagesCrawled();
        LONG getTotalLinks();
        LONG getTotalBytes();
        LONG getQueueSize();
        LONG getHttp2xx();
        LONG getHttp3xx();
        LONG getHttp4xx();
        LONG getHttp5xx();
        LONG getHttpOther();
        LARGE_INTEGER getFrequency();

        LONG getTamuLinkPages();
        LONG getTamuLinkPagesExternal();

        // synchronization
        CRITICAL_SECTION queueCriticalSection;
        // HANDLE queueSemaphore;
        CRITICAL_SECTION hostCriticalSection;
        CRITICAL_SECTION ipCriticalSection;

    private:
        // shared
        std::queue<std::string> urlQueue;
        std::unordered_set<std::string> seenHosts;
        std::unordered_set<std::string> seenIPs;

        // stats
        LONG extractedURLs;
        LONG uniqueHosts;
        LONG dnsLookups;
        LONG uniqueIPs;
        LONG robotsChecked;
        LONG robotsPassed;
        LONG pagesCrawled;
        LONG totalLinks;
        LONG totalBytes;

        LONG tamuLinkPages;
        LONG tamuLinkPagesExternal;

        // HTTP status codes counts
        LONG http2xx;
        LONG http3xx;
        LONG http4xx;
        LONG http5xx;
        LONG httpOther;

        LARGE_INTEGER startTime;
        LARGE_INTEGER frequency;

        // handle to signal shutdown
        HANDLE eventQuit;

        // control
        bool shutdown;

        LONG activeThreads;
};
#endif // CRAWLER_H