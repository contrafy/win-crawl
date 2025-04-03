# win-crawl

win-crawl is a multi-threaded web crawler built using WinSock and the Windows API for concurrent network operations. It leverages C++ along with a pre-compiled HTML parsing library to extract links from web pages, and it tracks various performance metrics during execution.

## Features

- **Multi-threading:** Spawns a user-defined number of crawling threads.
- **Dynamic Buffering:** Uses a dynamically resizing buffer for HTTP response handling.
- **DNS Resolution & HTTP Handling:** Resolves hostnames, sends HTTP requests, and processes responses.
- **Performance Statistics:** Continuously tracks metrics such as URLs extracted, DNS lookups, HTTP status codes, and data throughput.

## Architecture

The project is organized into several key components:

- **main.cpp:**  
  Acts as the entry point. It initializes WinSock, reads URLs from an input file, and spawns both the crawling threads and a dedicated statistics thread. The main function remains lean by delegating most of the work to the Crawler class.

- **Crawler Class (Crawler.h):**  
  Handles the core crawling logic. It maintains a queue of URLs to process, as well as thread-safe sets for unique hosts and IPs. It also tracks various performance statistics using Critical Sections and Interlocked operations. The class includes worker functions (`CrawlerThread` and `StatsThread`) that spawn individual threads, with each thread creating its own instances of the HTML parser and Socket classes.

- **Socket Class (Socket.h):**  
  Provides a wrapper around the WinSock SOCKET for sending HTTP requests and receiving responses. It implements a dynamic buffer that resizes as needed, ensuring efficient network I/O. Each crawling thread maintains its own Socket instance, so thread safety within this class is inherently managed.

- **HTMLParserBase:**  
  A pre-compiled library (provided as a .lib file) that parses HTML content to extract URLs from web pages.

## Building with Visual Studio 2019

### Prerequisites

- Windows operating system
- Visual Studio 2019 (or later)
- Windows SDK
