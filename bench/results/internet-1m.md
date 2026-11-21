# 1M-URL crawls over the real internet

Machine: Ryzen 7 9700X (8C/16T), 32 GB, Windows 11 (build 26200), home
connection. Input: `sample_urls/URL-input-1M.txt` (1,000,000 `http://` URLs,
824,985 unique hosts). All runs on 2026-11-21, release builds.

Internet runs are not repeatable to the last digit. Sites change, and
Cloudflare's resolver cache was warm for runs after the first. Treat
differences of a few percent as noise. For controlled comparisons use the
loopback rig (`bench/README.md`).

## Classic mode (the assignment pipeline)

| | legacy (5000 threads) | wincrawl `-c 4000` | wincrawl `-c 12000 --dns-inflight 4096` |
|---|---:|---:|---:|
| Build | `legacy-threaded` | `22a9007` | `a5acfcc` |
| Wall time | 1,632 s | 204.5 s | 152.2 s |
| URLs extracted | 1,000,000 @ 612/s | 1,000,000 @ 4,890/s | 1,000,000 @ 6,572/s |
| Unique hosts (DNS lookups) | 824,985 | 824,981 | 824,981 |
| DNS OK | 115,766 (14.0%) | 418,331 (50.7%) | 405,832 (49.2%) |
| Unique IPs (robots attempted) | 40,490 | 114,074 | 112,341 |
| Robots passed | 12,727 | 35,702 | 34,596 |
| Pages crawled | 12,467 | 34,968 | 33,485 |
| Data received | 212.67 MB | 654.37 MB | 617.18 MB |
| Links | 400,186 | 1,170,823 | 1,057,197 |
| HTTP 2xx / 3xx / 4xx / 5xx | 5,953 / 337 / 6,053 / 124 | 17,257 / 1,147 / 16,205 / 359 | 16,237 / 1,102 / 15,793 / 353 |
| DNS queries / retries / timeouts | n/a (`getaddrinfo`) | 874,931 / 51,847 / 2,135 | 959,212 / 136,128 / 9,180 |
| Connect failures / fetch timeouts | n/a | 17,592 / 1,216 | 18,308 / 1,729 |

Notes:
- The legacy crawler used the OS resolver (the home router); wincrawl used
  1.1.1.1 + 1.0.0.1. With 5000 concurrent `getaddrinfo` calls the router
  timed out most queries. The machine could not resolve github.com during
  that run.
- The 4 fewer unique hosts are seed URLs the new URL parser rejects.
- Links are counted by different parsers. The legacy course parser counts
  only `http://` links. wincrawl counts http and https `<a>`/`<area>` links
  (see `src/parse/links.h`).
- Both wincrawl runs held their concurrency limit for the entire run, so the
  limit, not CPU, is what set throughput. At `-c 12000` the extra DNS load
  shows up as more retries and timeouts (49.2% vs 50.7% OK).

## Real mode

`wincrawl --mode real -c 8000` (build `a5acfcc`): http + https, `GET
/robots.txt` per RFC 9309, redirects followed, certificate verification on
(offline, local root store only).

| | |
|---|---:|
| Wall time | 309.4 s |
| URLs extracted | 1,000,000 @ 3,231/s |
| DNS OK | 413,254 (50.1%) |
| Robots attempted / allowed | 112,635 / 76,678 |
| Pages crawled | 73,891 @ 238/s |
| HTTP 2xx / 3xx / 4xx / 5xx | 46,777 / 2,851 / 23,558 / 705 |
| Data received | 4,106 MB |
| Links | 3,838,208 |
| Redirects followed | 36,358 |
| TLS failures (of which certificate) | 1,838 (1,454) |
| Connect failures / fetch timeouts | 23,577 / 5,567 |

Certificate failures mix genuinely bad certificates (expired, wrong host)
with roots this machine's store had not downloaded yet. Verification never
fetches over the network; see the README.
