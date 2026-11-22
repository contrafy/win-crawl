# 1M seeds (2015 list), all hosts up to 2000 per IP, crawled 2026-11-22

Shares are `numerator / denominator = percent [Wilson 95% interval]`. One record per unique host attempted (seed URLs that passed host dedupe).


## Funnel

| stage | count | of previous stage |
|---|---|---|
| seed URLs | 1,000,000 |  |
| unique hosts | 820,097 | 820,097 / 1,000,000 = 82.01% [81.93–82.08] |
| DNS ok | 411,458 | 411,458 / 820,097 = 50.17% [50.06–50.28] |
| fetched (within the per-IP host budget) | 345,351 | 345,351 / 411,458 = 83.93% [83.82–84.05] |
| robots.txt attempted | 345,351 | 345,351 / 345,351 = 100.00% [100.00–100.00] |
| robots.txt allowed the page | 242,664 | 242,664 / 345,351 = 70.27% [70.11–70.42] |
| page fetch attempted | 242,476 | 242,476 / 242,664 = 99.92% [99.91–99.93] |
| page reply received | 233,093 | 233,093 / 242,476 = 96.13% [96.05–96.21] |
| final reply 2xx | 141,553 | 141,553 / 233,093 = 60.73% [60.53–60.93] |

Distinct IPs among fetched hosts: 113,744.


## Coverage and per-IP sampling

| population | fetched / resolving hosts |
|---|---|
| all resolving hosts | 345,351 / 411,458 = 83.93% [83.82–84.05] |
| on Cloudflare IPs (published ranges) | 63,735 / 63,735 = 100.00% [99.99–100.00] |
| on other IPs | 281,616 / 347,723 = 80.99% [80.86–81.12] |
| on IPs with 2+ resolving hosts | 259,195 / 325,302 = 79.68% [79.54–79.82] |

113,744 IPs resolved, 113,744 with at least one host fetched; the largest carries 28,419 resolving hosts (1,982 fetched). Resolving hosts on IPs with no host fetched (no weight possible): 0.

| not attempted or skipped by politeness (`skip`) | share |
|---|---|
| `ip_budget` | 37,898 / 411,458 = 9.21% [9.12–9.30] |
| `ip_unreachable` | 27,545 / 411,458 = 6.69% [6.62–6.77] |
| `ip_throttled` | 664 / 411,458 = 0.16% [0.15–0.17] |
| `crawl_delay` | 205 / 411,458 = 0.05% [0.04–0.06] |


## HTTP and TLS facts, IP-weighted

A per-IP host budget samples hosts on shared IPs. Each fetched host is weighted by its IP's resolving hosts / fetched hosts, so every resolving host counts once (inverse-probability weighting). Within an IP the fetched hosts are the first ones in input order, not a random draw, so the weighting assumes they are representative of the IP (model-based). With one host per IP (the assignment's IP dedupe) the unweighted column describes the first host on each IP.

Hosts on one IP share a server, so intervals treat the IP as the sampling unit: cluster-robust variance of the ratio estimator, Wilson on n_eff = p(1-p)/var.

| fact | unweighted | IP-weighted |
|---|---|---|
| any HTTP reply (robots or page), of fetched hosts | 292,927 / 345,351 = 84.82% [83.86–85.73], n_eff 5,649 | 80.14% [76.37–83.44], n_eff 487 |
| robots.txt allowed the page, of fetched hosts | 242,664 / 345,351 = 70.27% [68.17–72.28], n_eff 1,902 | 67.82% [62.56–72.67], n_eff 325 |
| final reply 2xx, of page replies | 141,553 / 233,093 = 60.73% [57.93–63.46], n_eff 1,197 | 64.58% [56.21–72.15], n_eff 135 |
| http seed ends on https, of http seeds with a page reply | 54,280 / 233,093 = 23.29% [21.76–24.89], n_eff 2,806 | 20.64% [16.47–25.55], n_eff 304 |
| TLS 1.3, of completed handshakes | 73,538 / 90,373 = 81.37% [78.91–83.61], n_eff 1,054 | 82.01% [79.03–84.65], n_eff 716 |
| PQ hybrid, of TLS 1.3 handshakes | 47,876 / 73,538 = 65.10% [61.12–68.89], n_eff 575 | 66.69% [61.23–71.74], n_eff 305 |
| PQ hybrid, of completed handshakes | 47,876 / 90,373 = 52.98% [49.21–56.71], n_eff 677 | 54.69% [49.13–60.14], n_eff 310 |
| Alt-Svc h3, of last replies over https | 10,437 / 54,280 = 19.23% [17.33–21.28], n_eff 1,534 | 18.77% [16.68–21.07], n_eff 1,216 |
| HSTS, of last replies over https | 16,190 / 54,280 = 29.83% [27.07–32.73], n_eff 1,000 | 29.12% [26.01–32.45], n_eff 762 |
| CF-RAY on the first reply, of hosts with a reply | 60,198 / 292,927 = 20.55% [18.84–22.37], n_eff 2,010 | 18.26% [15.00–22.04], n_eff 462 |


## Politeness

Fetched hosts that waited on politeness (IP queue and spacing, Crawl-delay, Retry-After): 110,511 / 345,351 = 32.00% [31.84–32.16].

| wait per fetched host | p50 | p90 | p99 | max |
|---|---|---|---|---|
|  | 0 ms | 142,593 ms | 792,812 ms | 2,407,906 ms |

robots.txt with a Crawl-delay, of fetched hosts whose robots.txt answered 2xx: 2,135 / 119,110 = 1.79% [1.72–1.87].

| Crawl-delay (s) | share of robots.txt with one |
|---|---|
| 0 | 1 / 2,135 = 0.05% [0.01–0.26] |
| (0, 1] | 101 / 2,135 = 4.73% [3.91–5.72] |
| (1, 5] | 323 / 2,135 = 15.13% [13.67–16.71] |
| (5, 10] | 1,162 / 2,135 = 54.43% [52.31–56.53] |
| (10, 30] | 251 / 2,135 = 11.76% [10.46–13.19] |
| (30, 60] | 95 / 2,135 = 4.45% [3.65–5.41] |
| > 60 | 202 / 2,135 = 9.46% [8.29–10.78] |

429/503 replies with a Retry-After: 3,419; retried after waiting it out: 1,373 / 3,419 = 40.16% [38.53–41.81].


## Link rot

| outcome | share of unique hosts |
|---|---|
| NXDOMAIN (name gone) | 311,039 / 820,097 = 37.93% [37.82–38.03] |
| no A record (NOERROR/NODATA) | 86,585 / 820,097 = 10.56% [10.49–10.62] |
| SERVFAIL / REFUSED | 6,189 / 820,097 = 0.75% [0.74–0.77] |
| DNS timeout | 4,826 / 820,097 = 0.59% [0.57–0.61] |
| resolves, but TCP connect fails (first request) | 38,245 / 820,097 = 4.66% [4.62–4.71] |
| resolves, but first request times out | 15,475 / 820,097 = 1.89% [1.86–1.92] |
| resolves, IP never answered (skipped after repeated failures) | 27,545 / 820,097 = 3.36% [3.32–3.40] |
| **dead: NXDOMAIN + no A + connect failure + IP never answered** | 463,414 / 820,097 = 56.51% [56.40–56.61] |
| alive: any HTTP reply (robots or page) | 292,927 / 820,097 = 35.72% [35.61–35.82] |
| not attempted: IP kept answering 429/503 | 664 / 820,097 = 0.08% [0.08–0.09] |
| not attempted: run stopped | 0 / 820,097 = 0.00% [0.00–0.00] |

Hosts over their IP's host budget are not fetched, so 'alive' is bounded by fetched hosts; 292,927 / 345,351 = 84.82% [84.70–84.94] of fetched hosts answered HTTP. Hosts on an IP that never answered count as dead (by the one-host-per-IP method its first host would have failed the same way); hosts not attempted for other reasons count in neither.

| DNS status | share |
|---|---|
| `ok` | 411,458 / 820,097 = 50.17% [50.06–50.28] |
| `nxdomain` | 311,039 / 820,097 = 37.93% [37.82–38.03] |
| `noanswer` | 86,585 / 820,097 = 10.56% [10.49–10.62] |
| `servfail` | 6,189 / 820,097 = 0.75% [0.74–0.77] |
| `timeout` | 4,826 / 820,097 = 0.59% [0.57–0.61] |


## Redirects and HTTPS upgrade

http:// seeds whose last page reply came over https (redirected to https): 54,280 / 233,093 = 23.29% [23.12–23.46] of http seeds with a page reply.

| redirects followed | share of page fetches |
|---|---|
| 0 | 167,703 / 242,476 = 69.16% [68.98–69.35] |
| 1 | 67,344 / 242,476 = 27.77% [27.60–27.95] |
| 2 | 5,876 / 242,476 = 2.42% [2.36–2.49] |
| 3 | 1,202 / 242,476 = 0.50% [0.47–0.52] |
| 4 | 141 / 242,476 = 0.06% [0.05–0.07] |
| 5 | 210 / 242,476 = 0.09% [0.08–0.10] |

| page fetch outcome | share |
|---|---|
| `ok` | 219,863 / 242,476 = 90.67% [90.56–90.79] |
| `robots_blocked` | 11,665 / 242,476 = 4.81% [4.73–4.90] |
| `timeout` | 9,156 / 242,476 = 3.78% [3.70–3.85] |
| `connect_fail` | 775 / 242,476 = 0.32% [0.30–0.34] |
| `closed` | 563 / 242,476 = 0.23% [0.21–0.25] |
| `ip_unreachable` | 169 / 242,476 = 0.07% [0.06–0.08] |
| `too_large` | 137 / 242,476 = 0.06% [0.05–0.07] |
| `redirect_dns` | 67 / 242,476 = 0.03% [0.02–0.04] |
| `ip_busy` | 47 / 242,476 = 0.02% [0.01–0.03] |
| `crawl_delay` | 17 / 242,476 = 0.01% [0.00–0.01] |
| `tls_fail` | 12 / 242,476 = 0.00% [0.00–0.01] |
| `bad_reply` | 3 / 242,476 = 0.00% [0.00–0.00] |
| `ip_throttled` | 2 / 242,476 = 0.00% [0.00–0.00] |


## Status codes

| final status class | share |
|---|---|
| `2xx` | 141,553 / 233,093 = 60.73% [60.53–60.93] |
| `4xx` | 75,008 / 233,093 = 32.18% [31.99–32.37] |
| `3xx` | 13,452 / 233,093 = 5.77% [5.68–5.87] |
| `5xx` | 3,080 / 233,093 = 1.32% [1.28–1.37] |

| final status | share |
|---|---|
| `200` | 141,471 / 233,093 = 60.69% [60.49–60.89] |
| `403` | 49,116 / 233,093 = 21.07% [20.91–21.24] |
| `404` | 21,228 / 233,093 = 9.11% [8.99–9.22] |
| `301` | 8,649 / 233,093 = 3.71% [3.63–3.79] |
| `302` | 4,462 / 233,093 = 1.91% [1.86–1.97] |
| `500` | 2,099 / 233,093 = 0.90% [0.86–0.94] |
| `444` | 1,565 / 233,093 = 0.67% [0.64–0.71] |
| `418` | 555 / 233,093 = 0.24% [0.22–0.26] |
| `412` | 548 / 233,093 = 0.24% [0.22–0.26] |
| `520` | 495 / 233,093 = 0.21% [0.19–0.23] |
| `409` | 374 / 233,093 = 0.16% [0.15–0.18] |
| `405` | 320 / 233,093 = 0.14% [0.12–0.15] |
| `400` | 196 / 233,093 = 0.08% [0.07–0.10] |
| `501` | 183 / 233,093 = 0.08% [0.07–0.09] |
| `308` | 171 / 233,093 = 0.07% [0.06–0.09] |
| (53 others) | 1,661 / 233,093 = 0.71% [0.68–0.75] |

| robots.txt status class | share |
|---|---|
| `4xx` | 130,052 / 292,927 = 44.40% [44.22–44.58] |
| `2xx` | 119,110 / 292,927 = 40.66% [40.48–40.84] |
| `5xx` | 22,337 / 292,927 = 7.63% [7.53–7.72] |
| `3xx` | 21,328 / 292,927 = 7.28% [7.19–7.38] |
| `other` | 100 / 292,927 = 0.03% [0.03–0.04] |

| robots.txt fetch error | share |
|---|---|
| `connect_fail` | 38,245 / 345,351 = 11.07% [10.97–11.18] |
| `timeout` | 15,475 / 345,351 = 4.48% [4.41–4.55] |
| `closed` | 13,782 / 345,351 = 3.99% [3.93–4.06] |
| `ip_unreachable` | 1,835 / 345,351 = 0.53% [0.51–0.56] |
| `tls_certificate` | 1,798 / 345,351 = 0.52% [0.50–0.55] |
| `ip_busy` | 1,126 / 345,351 = 0.33% [0.31–0.35] |
| `tls_fail` | 589 / 345,351 = 0.17% [0.16–0.18] |
| `too_large` | 335 / 345,351 = 0.10% [0.09–0.11] |
| `redirect_dns` | 247 / 345,351 = 0.07% [0.06–0.08] |
| `bad_reply` | 17 / 345,351 = 0.00% [0.00–0.01] |
| `ip_throttled` | 13 / 345,351 = 0.00% [0.00–0.01] |


## TLS

First TLS handshake of each site (the first https connection, robots.txt or page). Sites that reached a TLS handshake: 100,690.

| handshake outcome | share |
|---|---|
| `ok` | 88,517 / 100,690 = 87.91% [87.71–88.11] |
| `incomplete` | 10,206 / 100,690 = 10.14% [9.95–10.32] |
| `certificate` | 1,856 / 100,690 = 1.84% [1.76–1.93] |
| `failed` | 111 / 100,690 = 0.11% [0.09–0.13] |

| version | share |
|---|---|
| `TLS 1.3` | 73,538 / 90,373 = 81.37% [81.12–81.62] |
| `TLS 1.2` | 16,835 / 90,373 = 18.63% [18.38–18.88] |

| key exchange group | share |
|---|---|
| `X25519MLKEM768` | 47,876 / 90,373 = 52.98% [52.65–53.30] |
| `x25519` | 35,658 / 90,373 = 39.46% [39.14–39.78] |
| `secp256r1` | 5,405 / 90,373 = 5.98% [5.83–6.14] |
| `secp384r1` | 1,112 / 90,373 = 1.23% [1.16–1.30] |
| `(unknown)` | 322 / 90,373 = 0.36% [0.32–0.40] |

| cipher suite | share |
|---|---|
| `TLS_AES_256_GCM_SHA384` | 64,411 / 90,373 = 71.27% [70.98–71.57] |
| `TLS_AES_128_GCM_SHA256` | 9,127 / 90,373 = 10.10% [9.90–10.30] |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 8,573 / 90,373 = 9.49% [9.30–9.68] |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 5,562 / 90,373 = 6.15% [6.00–6.31] |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | 1,371 / 90,373 = 1.52% [1.44–1.60] |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` | 503 / 90,373 = 0.56% [0.51–0.61] |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 443 / 90,373 = 0.49% [0.45–0.54] |
| `TLS_RSA_WITH_AES_128_GCM_SHA256` | 101 / 90,373 = 0.11% [0.09–0.14] |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | 97 / 90,373 = 0.11% [0.09–0.13] |
| `TLS_RSA_WITH_AES_256_GCM_SHA384` | 67 / 90,373 = 0.07% [0.06–0.09] |
| `TLS_RSA_WITH_AES_128_CBC_SHA256` | 34 / 90,373 = 0.04% [0.03–0.05] |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | 27 / 90,373 = 0.03% [0.02–0.04] |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` | 26 / 90,373 = 0.03% [0.02–0.04] |
| `TLS_RSA_WITH_AES_256_CBC_SHA` | 16 / 90,373 = 0.02% [0.01–0.03] |
| `TLS_RSA_WITH_AES_256_CBC_SHA256` | 7 / 90,373 = 0.01% [0.00–0.02] |
| (2 others) | 8 / 90,373 = 0.01% [0.00–0.02] |

| post-quantum hybrid key exchange | share |
|---|---|
| of TLS 1.3 handshakes | 47,876 / 73,538 = 65.10% [64.76–65.45] |
| of all https sites (handshake completed) | 47,876 / 90,373 = 52.98% [52.65–53.30] |

Resumed handshakes: 14,409 / 90,373 = 15.94% [15.71–16.18].


## HTTP/3 (Alt-Svc) and HSTS

| fact | share |
|---|---|
| Alt-Svc advertises h3, of last replies over https | 10,437 / 54,280 = 19.23% [18.90–19.56] |
| Alt-Svc advertises h3, of all last replies | 39,047 / 233,093 = 16.75% [16.60–16.90] |
| HSTS header, of last replies over https | 16,190 / 54,280 = 29.83% [29.44–30.21] |
| HSTS valid (parsable max-age), of HSTS headers | 15,999 / 16,190 = 98.82% [98.64–98.98] |
| max-age=0 (asks to forget HSTS), of valid | 398 / 15,999 = 2.49% [2.26–2.74] |
| includeSubDomains, of valid with max-age > 0 | 6,094 / 15,601 = 39.06% [38.30–39.83] |
| preload, of valid with max-age > 0 | 3,483 / 15,601 = 22.33% [21.68–22.99] |

| HSTS max-age | share of valid HSTS |
|---|---|
| 0 (delete) | 398 / 15,999 = 2.49% [2.26–2.74] |
| < 1 day | 282 / 15,999 = 1.76% [1.57–1.98] |
| 1 day – < 30 days | 158 / 15,999 = 0.99% [0.85–1.15] |
| 30 days – < 180 days | 817 / 15,999 = 5.11% [4.78–5.46] |
| 180 days – < 1 year | 1,717 / 15,999 = 10.73% [10.26–11.22] |
| 1 year – < 2 years | 10,822 / 15,999 = 67.64% [66.91–68.36] |
| ≥ 2 years | 1,805 / 15,999 = 11.28% [10.80–11.78] |


## HTTPS DNS records (RFC 9460)

Queried for every host whose A lookup succeeded; cancelled queries excluded (411,458 answered).

| HTTPS query status | share |
|---|---|
| `noanswer` | 284,027 / 411,458 = 69.03% [68.89–69.17] |
| `servfail` | 61,056 / 411,458 = 14.84% [14.73–14.95] |
| `ok` | 60,406 / 411,458 = 14.68% [14.57–14.79] |
| `timeout` | 5,741 / 411,458 = 1.40% [1.36–1.43] |
| `nxdomain` | 228 / 411,458 = 0.06% [0.05–0.06] |

| fact | share |
|---|---|
| HTTPS RR present, of queried | 60,406 / 411,458 = 14.68% [14.57–14.79] |
| AliasMode, of present | 4 / 60,406 = 0.01% [0.00–0.02] |
| alpn includes h3, of present | 56,586 / 60,406 = 93.68% [93.48–93.87] |
| alpn includes h2, of present | 60,307 / 60,406 = 99.84% [99.80–99.87] |
| ECH config, of present | 55,340 / 60,406 = 91.61% [91.39–91.83] |
| ECH config, of queried | 55,340 / 411,458 = 13.45% [13.35–13.55] |


## Cloudflare

| signal | share |
|---|---|
| IP in Cloudflare's published ranges, of resolved hosts | 63,735 / 411,458 = 15.49% [15.38–15.60] |
| CF-RAY header on the first reply, of hosts with a reply | 60,198 / 292,927 = 20.55% [20.40–20.70] |
| either signal ("behind Cloudflare"), of resolved hosts | 65,325 / 411,458 = 15.88% [15.77–15.99] |
| signals agree, of hosts with both known | 287,355 / 292,927 = 98.10% [98.05–98.15] |

|  | CF-RAY yes | CF-RAY no |
|---|---|---|
| IP in CF ranges | 58,608 | 3,982 |
| IP not in CF ranges | 1,590 | 228,747 |

| fact | behind Cloudflare | not behind Cloudflare |
|---|---|---|
| TLS 1.3, of completed handshakes | 26,116 / 26,251 = 99.49% [99.39–99.57] | 47,422 / 64,122 = 73.96% [73.61–74.29] |
| PQ hybrid, of TLS 1.3 handshakes | 25,957 / 26,116 = 99.39% [99.29–99.48] | 21,919 / 47,422 = 46.22% [45.77–46.67] |
| PQ hybrid, of completed handshakes | 25,957 / 26,251 = 98.88% [98.75–99.00] | 21,919 / 64,122 = 34.18% [33.82–34.55] |
| Alt-Svc h3, of last replies over https | 8,481 / 9,691 = 87.51% [86.84–88.16] | 1,956 / 44,589 = 4.39% [4.20–4.58] |
| HSTS, of last replies over https | 2,826 / 9,691 = 29.16% [28.26–30.07] | 13,364 / 44,589 = 29.97% [29.55–30.40] |
| HTTPS RR present, of queried | 57,789 / 65,325 = 88.46% [88.22–88.71] | 2,617 / 346,133 = 0.76% [0.73–0.79] |
| HTTPS RR with ECH, of queried | 55,333 / 65,325 = 84.70% [84.43–84.98] | 7 / 346,133 = 0.00% [0.00–0.00] |


## Servers and content

| Server header (product token) | share |
|---|---|
| `nginx` | 71,629 / 198,268 = 36.13% [35.92–36.34] |
| `cloudflare` | 43,504 / 198,268 = 21.94% [21.76–22.12] |
| `apache` | 21,881 / 198,268 = 11.04% [10.90–11.17] |
| `openresty` | 13,129 / 198,268 = 6.62% [6.51–6.73] |
| `microsoft-iis` | 11,197 / 198,268 = 5.65% [5.55–5.75] |
| `home` | 5,437 / 198,268 = 2.74% [2.67–2.82] |
| `wts` | 2,705 / 198,268 = 1.36% [1.31–1.42] |
| `kestrel` | 2,685 / 198,268 = 1.35% [1.30–1.41] |
| `tengine` | 2,447 / 198,268 = 1.23% [1.19–1.28] |
| `litespeed` | 1,920 / 198,268 = 0.97% [0.93–1.01] |
| `caddy` | 1,420 / 198,268 = 0.72% [0.68–0.75] |
| `microsoft-httpapi` | 1,205 / 198,268 = 0.61% [0.57–0.64] |
| `beaver` | 982 / 198,268 = 0.50% [0.47–0.53] |
| `none` | 939 / 198,268 = 0.47% [0.44–0.50] |
| `f-web` | 880 / 198,268 = 0.44% [0.42–0.47] |
| (692 others) | 16,308 / 198,268 = 8.23% [8.11–8.35] |

| Server header (verbatim) | share |
|---|---|
| `nginx` | 57,802 / 198,268 = 29.15% [28.95–29.35] |
| `cloudflare` | 43,504 / 198,268 = 21.94% [21.76–22.12] |
| `Apache` | 16,831 / 198,268 = 8.49% [8.37–8.61] |
| `openresty` | 12,541 / 198,268 = 6.33% [6.22–6.43] |
| `Microsoft-IIS/10.0` | 6,099 / 198,268 = 3.08% [3.00–3.15] |
| `home` | 5,437 / 198,268 = 2.74% [2.67–2.82] |
| `nginx/1.10.2` | 4,652 / 198,268 = 2.35% [2.28–2.41] |
| `Kestrel` | 2,685 / 198,268 = 1.35% [1.30–1.41] |
| `Microsoft-IIS/7.5` | 2,539 / 198,268 = 1.28% [1.23–1.33] |
| `Tengine` | 2,289 / 198,268 = 1.15% [1.11–1.20] |
| `nginx/1.16.1` | 2,085 / 198,268 = 1.05% [1.01–1.10] |
| `wts` | 1,924 / 198,268 = 0.97% [0.93–1.01] |
| `LiteSpeed` | 1,920 / 198,268 = 0.97% [0.93–1.01] |
| `Microsoft-IIS/8.5` | 1,900 / 198,268 = 0.96% [0.92–1.00] |
| `nginx/1.30.7` | 1,896 / 198,268 = 0.96% [0.91–1.00] |
| (1797 others) | 34,164 / 198,268 = 17.23% [17.07–17.40] |

| Content-Type of 2xx replies | share |
|---|---|
| `text/html` | 140,724 / 141,409 = 99.52% [99.48–99.55] |
| `*/*` | 275 / 141,409 = 0.19% [0.17–0.22] |
| `image/jpeg` | 112 / 141,409 = 0.08% [0.07–0.10] |
| `application/pdf` | 80 / 141,409 = 0.06% [0.05–0.07] |
| `text/plain` | 40 / 141,409 = 0.03% [0.02–0.04] |
| `application/octet-stream` | 33 / 141,409 = 0.02% [0.02–0.03] |
| `application/json` | 16 / 141,409 = 0.01% [0.01–0.02] |
| `application/javascript` | 13 / 141,409 = 0.01% [0.01–0.02] |
| `text/xml` | 11 / 141,409 = 0.01% [0.00–0.01] |
| `image/gif` | 10 / 141,409 = 0.01% [0.00–0.01] |
| `text/html,text/html` | 10 / 141,409 = 0.01% [0.00–0.01] |
| `application/xml` | 9 / 141,409 = 0.01% [0.00–0.01] |
| `application/rss+xml` | 9 / 141,409 = 0.01% [0.00–0.01] |
| `image/png` | 9 / 141,409 = 0.01% [0.00–0.01] |
| `application/vnd.openxmlformats-officedocument.wordprocessingml.d` | 6 / 141,409 = 0.00% [0.00–0.01] |
| (29 others) | 52 / 141,409 = 0.04% [0.03–0.05] |


## Time per site

| p50 | p90 | p99 | max |
|---|---|---|---|
| 2,156 ms | 21,109 ms | 621,562 ms | 2,415,390 ms |
