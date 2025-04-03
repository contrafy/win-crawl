#include "Crawler.h"
#include "HTMLParserBase.h"
#include "Socket.h"
#include "Utility.h"

#include <cstdio>
#include <regex>
#include <fstream>
#include <algorithm>

Crawler::Crawler(int numThreads) {
    InitializeCriticalSection(&queueCriticalSection);
    InitializeCriticalSection(&hostCriticalSection);
    InitializeCriticalSection(&ipCriticalSection);


    // create a manual reset event for signaling shutdown
    eventQuit = CreateEvent(NULL, TRUE, FALSE, NULL); // manual reset event, initially non signaled
    if (eventQuit == NULL) {
        std::cerr << "CreateEvent failed with error: " << GetLastError() << std::endl;
        exit(EXIT_FAILURE);
    }

    extractedURLs = 0;
    uniqueHosts = 0;
    dnsLookups = 0;
    uniqueIPs = 0;
    robotsChecked = 0;
    robotsPassed = 0;
    pagesCrawled = 0;
    totalLinks = 0;
    totalBytes = 0;
    http2xx = 0;
    http3xx = 0;
    http4xx = 0;
    http5xx = 0;
    httpOther = 0;

    tamuLinkPages = 0;
    tamuLinkPagesExternal = 0;

    activeThreads = numThreads;
    shutdown = false;

    // timer starts in Crawler::StatsThread
}

Crawler::~Crawler() {
    // delete critical sections
    DeleteCriticalSection(&queueCriticalSection);
    DeleteCriticalSection(&hostCriticalSection);
    DeleteCriticalSection(&ipCriticalSection);

    // close event handle
    CloseHandle(eventQuit);
}

// could be a thread but kinda pointless, only takes a few seconds to pre-load 1M
void Crawler::ReadFile(const std::string& filename) {
    // read URLs from the file and populate the queue
    std::ifstream inputFile(filename);
    if (!inputFile.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        exit(EXIT_FAILURE);
    }
    // if opened successfully, get size and set pointer position back to start of file
    inputFile.seekg(0, std::ios::end);
    std::streamsize fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);
    printf("Opened %s with size %lld\n", filename.c_str(), fileSize);

    std::string line;
    while (std::getline(inputFile, line)) {
        // trim the line
        line.erase(line.find_last_not_of(" \n\r\t") + 1);
        line.erase(0, line.find_first_not_of(" \n\r\t"));
        urlQueue.push(line);
    }

    // queueSemaphore = CreateSemaphore(NULL, urlQueue.size(), urlQueue.size(), NULL);
    inputFile.close();
}


// entrypoint for Crawler Threads
void Crawler::Run() {
    HTMLParserBase* parser = new HTMLParserBase;
    Socket socket;
    std::string url, scheme, host, request, response;
    int port, statusCode;
    size_t limit;

    char ipBuffer[INET_ADDRSTRLEN]; // buffer to hold IP address string
    const std::regex tamuRegex(R"(^https?://([a-zA-Z0-9-]+\.)*tamu\.edu(/|$))");
    const std::regex internalTAMURegex(R"(^([a-zA-Z0-9-]+\.)*tamu\.edu$)");
    bool containsTAMULink = false;

    while (true) {
        // check if queue is empty and safely pop a value
        EnterCriticalSection(&queueCriticalSection);
        if (urlQueue.empty()) {
            LeaveCriticalSection(&queueCriticalSection);
            break; // finished crawling
        }
        url = urlQueue.front();
        urlQueue.pop();
        LeaveCriticalSection(&queueCriticalSection);

        InterlockedIncrement(&extractedURLs);

        // process the URL
        if (!parseURL(url, scheme, host, port, request)) {
            // invalid URL, skip
            // std::cout << "Invalid URL: " << url << std::endl;
            continue;
        }

        if (!checkAndInsertHost(host)) {
            // host already seen, skip
            continue;
        }
        InterlockedIncrement(&uniqueHosts);

        if (!socket.resolveDNS(host)) {
            // DNS failed
            continue;
        }
        InterlockedIncrement(&dnsLookups);

        // get IP address as string using inet_ntop
        in_addr resolvedAddr = socket.getResolvedAddress();
        if (inet_ntop(AF_INET, &resolvedAddr, ipBuffer, INET_ADDRSTRLEN) == NULL) {
            std::cerr << "inet_ntop failed with error: " << WSAGetLastError() << std::endl;
            continue;
        }
        std::string ipAddrStr(ipBuffer);

        if (!checkAndInsertIP(ipAddrStr)) {
            // IP already seen, skip
            continue;
        }
        
        InterlockedIncrement(&uniqueIPs);

        // connect for robots
        if (!socket.connect(host, port)) {
            continue;
        }

        // send request to server for robots
        if (!socket.sendHTTPRequest(host, "/robots.txt", "HEAD")) {
            continue;
        }

        // receive and parse robots response
        limit = 16 * 1024; // 16kb download limit for 'HEAD /robots.txt'
        if (!socket.receiveResponse(response, statusCode, limit)) {
            continue;
        }
        InterlockedIncrement(&robotsChecked);

        // robots status code check
        if (statusCode < 400 || statusCode >= 500) {
            continue;
        }
        InterlockedIncrement(&robotsPassed);

        // download the page if robots passed
        if (!socket.connect(host, port)) {
            continue;
        }
        if (!socket.sendHTTPRequest(host, request, "GET")) {
            continue;
        }

        // if we successfully get a response at all it's "crawled"
        limit = 2 * 1024 * 1024; // 2MB limit for actual page
        if (!socket.receiveResponse(response, statusCode, limit)) {
            continue;
        }
        InterlockedAdd(&totalBytes, (static_cast<LONG>(response.length())));

        // increment the appropriate HTTP code, parse if valid response
        if (statusCode >= 200 && statusCode < 300) {
            InterlockedIncrement(&http2xx);

            // parse page and extract links
            size_t headerEnd = response.find("\r\n\r\n");
            int nLinks = 0;

            if (headerEnd != std::string::npos) {
                std::string htmlBody = response.substr(headerEnd + 4);

                // for mem safety
                std::vector<char> modifiableHtmlBody(htmlBody.begin(), htmlBody.end());
                modifiableHtmlBody.push_back('\0'); // null terminate

                std::string baseUrlStr = "http://" + host;
                std::vector<char> baseUrl(baseUrlStr.begin(), baseUrlStr.end());
                baseUrl.push_back('\0'); // null terminate

                char* linkBuffer = parser->Parse((char*)htmlBody.c_str(), (int)htmlBody.length(), (char*)baseUrlStr.c_str(), (int)(baseUrl.size()), &nLinks);
                if (nLinks < 0) {
                    nLinks = 0;
                }
                InterlockedAdd(&totalLinks, nLinks);

                /* this is expensive for some reason
                // scan for tamu links
                containsTAMULink = false;

                for (int i = 0; i < nLinks; i++) {
                    std::string extractedLink = std::string(linkBuffer + i);

                    // use regex to match TAMU URLs
                    if (std::regex_match(extractedLink, tamuRegex)) {
                        containsTAMULink = true;
                        break; // all we want to know is how many pages have a link, not how many links
                    }
                }

                // increment counters
                if (containsTAMULink) {
                    InterlockedIncrement(&tamuLinkPages);

                    // determine if the originating page is external to TAMU
                    if (!std::regex_match(host, internalTAMURegex)) {
                        InterlockedIncrement(&tamuLinkPagesExternal);
                    }
                }
                */
            }
        }
        else if (statusCode >= 300 && statusCode < 400) {
            InterlockedIncrement(&http3xx);
        }
        else if (statusCode >= 400 && statusCode < 500) {
            InterlockedIncrement(&http4xx);
        }
        else if (statusCode >= 500 && statusCode < 600) {
            InterlockedIncrement(&http5xx);
        }
        else {
            InterlockedIncrement(&httpOther);
        }

        InterlockedAdd(&totalBytes, (static_cast<LONG>(response.length())));
        InterlockedIncrement(&pagesCrawled);
    }

    delete parser;
    socket.close();
    InterlockedDecrement(&activeThreads);
}

void Crawler::signalShutdown() {
    shutdown = true;
    // signal the event to notify the stats thread
    SetEvent(eventQuit);
}

LARGE_INTEGER Crawler::getStartTime() {
    return startTime;
}

void Crawler::decrementActiveThreads() {
    InterlockedDecrement(&activeThreads);
}

int Crawler::getActiveThreads() {
    return InterlockedCompareExchange(&activeThreads, 0, 0);
}

// update stats methods using interlocked functions
void Crawler::incrementExtractedURLs() {
    InterlockedIncrement(&extractedURLs);
}

void Crawler::incrementUniqueHosts() {
    InterlockedIncrement(&uniqueHosts);
}

void Crawler::incrementDNSLookups() {
    InterlockedIncrement(&dnsLookups);
}

void Crawler::incrementUniqueIPs() {
    InterlockedIncrement(&uniqueIPs);
}

void Crawler::incrementRobotsChecked() {
    InterlockedIncrement(&robotsChecked);
}

void Crawler::incrementRobotsPassed() {
    InterlockedIncrement(&robotsPassed);
}

void Crawler::incrementPagesCrawled() {
    InterlockedIncrement(&pagesCrawled);
}

void Crawler::incrementHttpStatus(int statusCode) {
    if (statusCode >= 200 && statusCode < 300) {
        InterlockedIncrement(&http2xx);
    }
    else if (statusCode >= 300 && statusCode < 400) {
        InterlockedIncrement(&http3xx);
    }
    else if (statusCode >= 400 && statusCode < 500) {
        InterlockedIncrement(&http4xx);
    }
    else if (statusCode >= 500 && statusCode < 600) {
        InterlockedIncrement(&http5xx);
    }
    else {
        InterlockedIncrement(&httpOther);
    }
}

void Crawler::addTotalLinks(LONG links) {
    InterlockedAdd(&totalLinks, links);
}

void Crawler::addTotalBytes(LONG bytes) {
    InterlockedAdd(&totalBytes, bytes);
}

// get stats methods
LONG Crawler::getExtractedURLs() {
    return InterlockedCompareExchange(&extractedURLs, 0, 0);
}

LONG Crawler::getUniqueHosts() {
    return InterlockedCompareExchange(&uniqueHosts, 0, 0);
}

LONG Crawler::getDNSLookups() {
    return InterlockedCompareExchange(&dnsLookups, 0, 0);
}

LONG Crawler::getUniqueIPs() {
    return InterlockedCompareExchange(&uniqueIPs, 0, 0);
}

LONG Crawler::getRobotsChecked() {
    return InterlockedCompareExchange(&robotsChecked, 0, 0);
}

LONG Crawler::getRobotsPassed() {
    return InterlockedCompareExchange(&robotsPassed, 0, 0);
}

LONG Crawler::getPagesCrawled() {
    return InterlockedCompareExchange(&pagesCrawled, 0, 0);
}

LONG Crawler::getTotalLinks() {
    return InterlockedCompareExchange(&totalLinks, 0, 0);
}

LONG Crawler::getTotalBytes() {
    return InterlockedCompareExchange(&totalBytes, 0, 0);
}

LONG Crawler::getQueueSize() {
    EnterCriticalSection(&queueCriticalSection);
    LONG size = static_cast<LONG>(urlQueue.size());
    LeaveCriticalSection(&queueCriticalSection);
    return size;
}

LONG Crawler::getHttp2xx() {
    return InterlockedCompareExchange(&http2xx, 0, 0);
}

LONG Crawler::getHttp3xx() {
    return InterlockedCompareExchange(&http3xx, 0, 0);
}

LONG Crawler::getHttp4xx() {
    return InterlockedCompareExchange(&http4xx, 0, 0);
}

LONG Crawler::getHttp5xx() {
    return InterlockedCompareExchange(&http5xx, 0, 0);
}

LONG Crawler::getHttpOther() {
    return InterlockedCompareExchange(&httpOther, 0, 0);
}

LARGE_INTEGER Crawler::getFrequency() {
    return frequency;
}

LONG Crawler::getTamuLinkPages() {
    return InterlockedCompareExchange(&tamuLinkPages, 0, 0);
}

LONG Crawler::getTamuLinkPagesExternal() {
    return InterlockedCompareExchange(&tamuLinkPagesExternal, 0, 0);
}

bool Crawler::checkAndInsertIP(const std::string& ipAddr) {
    EnterCriticalSection(&ipCriticalSection);
    bool isNewIP = seenIPs.insert(ipAddr).second;
    LeaveCriticalSection(&ipCriticalSection);
    return isNewIP;
}

bool Crawler::checkAndInsertHost(const std::string& host) {
    EnterCriticalSection(&hostCriticalSection);
    bool isNewHost = seenHosts.insert(host).second;
    LeaveCriticalSection(&hostCriticalSection);
    return isNewHost;
}

void Crawler::printStats() {
    // calculate elapsed time in seconds
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsedTime = static_cast<double>(now.QuadPart - startTime.QuadPart) / frequency.QuadPart;

    // pretty print stats
    printf("[%3d] %3d Q %7ld E %7ld H %6ld D %5ld I %5ld R %5ld C %5ld L %4ldK\n",
        static_cast<int>(elapsedTime), getActiveThreads(), getQueueSize(), getExtractedURLs(), getUniqueHosts(), getDNSLookups(), getUniqueIPs(), getRobotsPassed(), getPagesCrawled(), getTotalLinks() / 1000);
}

void Crawler::StatsRun()
{
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);

    LARGE_INTEGER lastTime = startTime;

    LONG lastCrawled = 0;
    LONG lastBytes = 0;

    while (WaitForSingleObject(eventQuit, 2000) == WAIT_TIMEOUT)
    {
        printStats();

        // compute pps and Mbps
        LARGE_INTEGER currentTime;
        QueryPerformanceCounter(&currentTime);
        double elapsedSeconds = static_cast<double>(currentTime.QuadPart - lastTime.QuadPart) / frequency.QuadPart;

        LONG currentCrawled = getPagesCrawled();
        LONG currentBytes = getTotalBytes();

        double pps = (currentCrawled - lastCrawled) / elapsedSeconds;
        double Mbps = ((currentBytes - lastBytes) * 8.0) / (elapsedSeconds * 1024.0 * 1024.0);

        printf("     *** crawling %.1f pps @ %.1f Mbps\n", pps, Mbps);

        lastCrawled = currentCrawled;
        lastBytes = currentBytes;
        lastTime = currentTime;
    }
}

// thread workers
DWORD WINAPI Crawler::StatsThread(LPVOID param)
{
    Crawler* crawler = ((Crawler*)param);
    crawler->StatsRun();
    return 0;
}

DWORD WINAPI Crawler::CrawlerThread(LPVOID param)
{
    Crawler* crawler = ((Crawler*)param);
    crawler->Run();
    return 0;
}
