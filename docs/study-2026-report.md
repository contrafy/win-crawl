# 1M seeds (2015 list), crawled 2026-11-21

Shares are `numerator / denominator = percent [Wilson 95% interval]`. One record per unique host attempted (seed URLs that passed host dedupe).


## Funnel

| stage | count | of previous stage |
|---|---|---|
| seed URLs | 1,000,000 |  |
| unique hosts | 824,981 | 824,981 / 1,000,000 = 82.50% [82.42–82.57] |
| DNS ok | 416,928 | 416,928 / 824,981 = 50.54% [50.43–50.65] |
| unique IPs (passed IP dedupe) | 113,963 | 113,963 / 416,928 = 27.33% [27.20–27.47] |
| robots.txt attempted | 113,963 | 113,963 / 113,963 = 100.00% [100.00–100.00] |
| robots.txt allowed the page | 74,743 | 74,743 / 113,963 = 65.59% [65.31–65.86] |
| page fetch attempted | 74,743 | 74,743 / 74,743 = 100.00% [99.99–100.00] |
| page reply received | 72,752 | 72,752 / 74,743 = 97.34% [97.22–97.45] |
| final reply 2xx | 45,409 | 45,409 / 72,752 = 62.42% [62.06–62.77] |


## Link rot

| outcome | share of unique hosts |
|---|---|
| NXDOMAIN (name gone) | 309,935 / 824,981 = 37.57% [37.46–37.67] |
| no A record (NOERROR/NODATA) | 86,088 / 824,981 = 10.44% [10.37–10.50] |
| SERVFAIL / REFUSED | 8,966 / 824,981 = 1.09% [1.06–1.11] |
| DNS timeout | 3,064 / 824,981 = 0.37% [0.36–0.38] |
| resolves, but TCP connect fails (first request) | 23,818 / 824,981 = 2.89% [2.85–2.92] |
| resolves, but first request times out | 6,049 / 824,981 = 0.73% [0.72–0.75] |
| **dead: NXDOMAIN + no A + connect failure** | 419,841 / 824,981 = 50.89% [50.78–51.00] |
| alive: any HTTP reply (robots or page) | 87,318 / 824,981 = 10.58% [10.52–10.65] |

IP-duplicate hosts are not fetched, so 'alive' is bounded by unique IPs; 87,318 / 113,963 = 76.62% [76.37–76.86] of hosts that passed IP dedupe answered HTTP.

| DNS status | share |
|---|---|
| `ok` | 416,928 / 824,981 = 50.54% [50.43–50.65] |
| `nxdomain` | 309,935 / 824,981 = 37.57% [37.46–37.67] |
| `noanswer` | 86,088 / 824,981 = 10.44% [10.37–10.50] |
| `servfail` | 8,966 / 824,981 = 1.09% [1.06–1.11] |
| `timeout` | 3,064 / 824,981 = 0.37% [0.36–0.38] |


## Redirects and HTTPS upgrade

http:// seeds whose last page reply came over https (redirected to https): 22,044 / 72,752 = 30.30% [29.97–30.64] of http seeds with a page reply.

| redirects followed | share of page fetches |
|---|---|
| 0 | 45,830 / 74,743 = 61.32% [60.97–61.67] |
| 1 | 25,101 / 74,743 = 33.58% [33.25–33.92] |
| 2 | 3,184 / 74,743 = 4.26% [4.12–4.41] |
| 3 | 472 / 74,743 = 0.63% [0.58–0.69] |
| 4 | 72 / 74,743 = 0.10% [0.08–0.12] |
| 5 | 84 / 74,743 = 0.11% [0.09–0.14] |

| page fetch outcome | share |
|---|---|
| `ok` | 67,729 / 74,743 = 90.62% [90.40–90.82] |
| `robots_blocked` | 4,495 / 74,743 = 6.01% [5.85–6.19] |
| `timeout` | 1,288 / 74,743 = 1.72% [1.63–1.82] |
| `connect_fail` | 851 / 74,743 = 1.14% [1.06–1.22] |
| `closed` | 315 / 74,743 = 0.42% [0.38–0.47] |
| `too_large` | 38 / 74,743 = 0.05% [0.04–0.07] |
| `redirect_dns` | 20 / 74,743 = 0.03% [0.02–0.04] |
| `bad_reply` | 6 / 74,743 = 0.01% [0.00–0.02] |
| `tls_fail` | 1 / 74,743 = 0.00% [0.00–0.01] |


## Status codes

| final status class | share |
|---|---|
| `2xx` | 45,409 / 72,752 = 62.42% [62.06–62.77] |
| `4xx` | 21,540 / 72,752 = 29.61% [29.28–29.94] |
| `3xx` | 5,112 / 72,752 = 7.03% [6.84–7.21] |
| `5xx` | 691 / 72,752 = 0.95% [0.88–1.02] |

| final status | share |
|---|---|
| `200` | 45,387 / 72,752 = 62.39% [62.03–62.74] |
| `403` | 13,383 / 72,752 = 18.40% [18.12–18.68] |
| `404` | 6,257 / 72,752 = 8.60% [8.40–8.81] |
| `301` | 4,287 / 72,752 = 5.89% [5.72–6.07] |
| `444` | 764 / 72,752 = 1.05% [0.98–1.13] |
| `302` | 703 / 72,752 = 0.97% [0.90–1.04] |
| `429` | 367 / 72,752 = 0.50% [0.46–0.56] |
| `500` | 282 / 72,752 = 0.39% [0.35–0.44] |
| `520` | 118 / 72,752 = 0.16% [0.14–0.19] |
| `400` | 112 / 72,752 = 0.15% [0.13–0.19] |
| `412` | 101 / 72,752 = 0.14% [0.11–0.17] |
| `409` | 99 / 72,752 = 0.14% [0.11–0.17] |
| `416` | 93 / 72,752 = 0.13% [0.10–0.16] |
| `405` | 91 / 72,752 = 0.13% [0.10–0.15] |
| `501` | 89 / 72,752 = 0.12% [0.10–0.15] |
| (50 others) | 619 / 72,752 = 0.85% [0.79–0.92] |

| robots.txt status class | share |
|---|---|
| `4xx` | 43,337 / 87,318 = 49.63% [49.30–49.96] |
| `2xx` | 32,659 / 87,318 = 37.40% [37.08–37.72] |
| `3xx` | 8,334 / 87,318 = 9.54% [9.35–9.74] |
| `5xx` | 2,969 / 87,318 = 3.40% [3.28–3.52] |
| `other` | 19 / 87,318 = 0.02% [0.01–0.03] |

| robots.txt fetch error | share |
|---|---|
| `connect_fail` | 23,818 / 113,963 = 20.90% [20.66–21.14] |
| `timeout` | 6,049 / 113,963 = 5.31% [5.18–5.44] |
| `closed` | 3,514 / 113,963 = 3.08% [2.98–3.19] |
| `tls_certificate` | 903 / 113,963 = 0.79% [0.74–0.85] |
| `tls_fail` | 226 / 113,963 = 0.20% [0.17–0.23] |
| `too_large` | 190 / 113,963 = 0.17% [0.14–0.19] |
| `redirect_dns` | 132 / 113,963 = 0.12% [0.10–0.14] |
| `bad_reply` | 6 / 113,963 = 0.01% [0.00–0.01] |


## TLS

First TLS handshake of each site (the first https connection, robots.txt or page). Sites that reached a TLS handshake: 36,375.

| handshake outcome | share |
|---|---|
| `ok` | 31,712 / 36,375 = 87.18% [86.83–87.52] |
| `incomplete` | 3,651 / 36,375 = 10.04% [9.73–10.35] |
| `certificate` | 937 / 36,375 = 2.58% [2.42–2.74] |
| `failed` | 75 / 36,375 = 0.21% [0.16–0.26] |

| version | share |
|---|---|
| `TLS 1.3` | 27,372 / 32,649 = 83.84% [83.43–84.23] |
| `TLS 1.2` | 5,277 / 32,649 = 16.16% [15.77–16.57] |

| key exchange group | share |
|---|---|
| `X25519MLKEM768` | 15,467 / 32,649 = 47.37% [46.83–47.92] |
| `x25519` | 13,683 / 32,649 = 41.91% [41.38–42.45] |
| `secp256r1` | 2,602 / 32,649 = 7.97% [7.68–8.27] |
| `secp384r1` | 759 / 32,649 = 2.32% [2.17–2.49] |
| `(unknown)` | 138 / 32,649 = 0.42% [0.36–0.50] |

| cipher suite | share |
|---|---|
| `TLS_AES_256_GCM_SHA384` | 24,040 / 32,649 = 73.63% [73.15–74.11] |
| `TLS_AES_128_GCM_SHA256` | 3,332 / 32,649 = 10.21% [9.88–10.54] |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 2,414 / 32,649 = 7.39% [7.11–7.68] |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 1,978 / 32,649 = 6.06% [5.80–6.32] |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` | 293 / 32,649 = 0.90% [0.80–1.01] |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | 251 / 32,649 = 0.77% [0.68–0.87] |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 160 / 32,649 = 0.49% [0.42–0.57] |
| `TLS_RSA_WITH_AES_256_GCM_SHA384` | 47 / 32,649 = 0.14% [0.11–0.19] |
| `TLS_RSA_WITH_AES_128_CBC_SHA256` | 25 / 32,649 = 0.08% [0.05–0.11] |
| `TLS_RSA_WITH_AES_256_CBC_SHA` | 21 / 32,649 = 0.06% [0.04–0.10] |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` | 21 / 32,649 = 0.06% [0.04–0.10] |
| `TLS_RSA_WITH_AES_128_GCM_SHA256` | 20 / 32,649 = 0.06% [0.04–0.09] |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | 18 / 32,649 = 0.06% [0.03–0.09] |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | 14 / 32,649 = 0.04% [0.03–0.07] |
| `TLS_RSA_WITH_AES_256_CBC_SHA256` | 7 / 32,649 = 0.02% [0.01–0.04] |
| (2 others) | 8 / 32,649 = 0.02% [0.01–0.05] |

| post-quantum hybrid key exchange | share |
|---|---|
| of TLS 1.3 handshakes | 15,467 / 27,372 = 56.51% [55.92–57.09] |
| of all https sites (handshake completed) | 15,467 / 32,649 = 47.37% [46.83–47.92] |

Resumed handshakes: 535 / 32,649 = 1.64% [1.51–1.78].


## HTTP/3 (Alt-Svc) and HSTS

| fact | share |
|---|---|
| Alt-Svc advertises h3, of last replies over https | 5,328 / 22,044 = 24.17% [23.61–24.74] |
| Alt-Svc advertises h3, of all last replies | 15,235 / 72,752 = 20.94% [20.65–21.24] |
| HSTS header, of last replies over https | 6,461 / 22,044 = 29.31% [28.71–29.91] |
| HSTS valid (parsable max-age), of HSTS headers | 6,362 / 6,461 = 98.47% [98.14–98.74] |
| max-age=0 (asks to forget HSTS), of valid | 106 / 6,362 = 1.67% [1.38–2.01] |
| includeSubDomains, of valid with max-age > 0 | 2,397 / 6,256 = 38.32% [37.12–39.53] |
| preload, of valid with max-age > 0 | 1,296 / 6,256 = 20.72% [19.73–21.74] |

| HSTS max-age | share of valid HSTS |
|---|---|
| 0 (delete) | 106 / 6,362 = 1.67% [1.38–2.01] |
| < 1 day | 115 / 6,362 = 1.81% [1.51–2.17] |
| 1 day – < 30 days | 98 / 6,362 = 1.54% [1.27–1.87] |
| 30 days – < 180 days | 192 / 6,362 = 3.02% [2.63–3.47] |
| 180 days – < 1 year | 558 / 6,362 = 8.77% [8.10–9.49] |
| 1 year – < 2 years | 4,608 / 6,362 = 72.43% [71.32–73.51] |
| ≥ 2 years | 685 / 6,362 = 10.77% [10.03–11.55] |


## HTTPS DNS records (RFC 9460)

Queried for every host whose A lookup succeeded; cancelled queries excluded (416,928 answered).

| HTTPS query status | share |
|---|---|
| `noanswer` | 288,973 / 416,928 = 69.31% [69.17–69.45] |
| `servfail` | 66,538 / 416,928 = 15.96% [15.85–16.07] |
| `ok` | 60,266 / 416,928 = 14.45% [14.35–14.56] |
| `timeout` | 920 / 416,928 = 0.22% [0.21–0.24] |
| `nxdomain` | 231 / 416,928 = 0.06% [0.05–0.06] |

| fact | share |
|---|---|
| HTTPS RR present, of queried | 60,266 / 416,928 = 14.45% [14.35–14.56] |
| AliasMode, of present | 4 / 60,266 = 0.01% [0.00–0.02] |
| alpn includes h3, of present | 56,448 / 60,266 = 93.66% [93.47–93.86] |
| alpn includes h2, of present | 60,167 / 60,266 = 99.84% [99.80–99.87] |
| ECH config, of present | 55,200 / 60,266 = 91.59% [91.37–91.81] |
| ECH config, of queried | 55,200 / 416,928 = 13.24% [13.14–13.34] |


## Cloudflare

| signal | share |
|---|---|
| IP in Cloudflare's published ranges, of resolved hosts | 63,498 / 416,928 = 15.23% [15.12–15.34] |
| CF-RAY header on the first reply, of hosts with a reply | 19,402 / 87,318 = 22.22% [21.95–22.50] |
| either signal ("behind Cloudflare"), of resolved hosts | 63,757 / 416,928 = 15.29% [15.18–15.40] |
| signals agree, of hosts with both known | 87,051 / 87,318 = 99.69% [99.66–99.73] |

|  | CF-RAY yes | CF-RAY no |
|---|---|---|
| IP in CF ranges | 19,143 | 8 |
| IP not in CF ranges | 259 | 67,908 |

| fact | behind Cloudflare | not behind Cloudflare |
|---|---|---|
| TLS 1.3, of completed handshakes | 8,181 / 8,289 = 98.70% [98.43–98.92] | 19,191 / 24,360 = 78.78% [78.26–79.29] |
| PQ hybrid, of TLS 1.3 handshakes | 8,111 / 8,181 = 99.14% [98.92–99.32] | 7,356 / 19,191 = 38.33% [37.64–39.02] |
| PQ hybrid, of completed handshakes | 8,111 / 8,289 = 97.85% [97.52–98.14] | 7,356 / 24,360 = 30.20% [29.62–30.78] |
| Alt-Svc h3, of last replies over https | 4,364 / 5,195 = 84.00% [82.98–84.98] | 964 / 16,849 = 5.72% [5.38–6.08] |
| HSTS, of last replies over https | 1,255 / 5,195 = 24.16% [23.01–25.34] | 5,206 / 16,849 = 30.90% [30.20–31.60] |
| HTTPS RR present, of queried | 57,376 / 63,757 = 89.99% [89.76–90.22] | 2,890 / 353,171 = 0.82% [0.79–0.85] |
| HTTPS RR with ECH, of queried | 55,192 / 63,757 = 86.57% [86.30–86.83] | 8 / 353,171 = 0.00% [0.00–0.00] |


## Servers and content

| Server header (product token) | share |
|---|---|
| `nginx` | 23,487 / 68,080 = 34.50% [34.14–34.86] |
| `cloudflare` | 15,686 / 68,080 = 23.04% [22.73–23.36] |
| `apache` | 11,189 / 68,080 = 16.44% [16.16–16.72] |
| `microsoft-iis` | 5,307 / 68,080 = 7.80% [7.60–8.00] |
| `openresty` | 2,650 / 68,080 = 3.89% [3.75–4.04] |
| `litespeed` | 1,282 / 68,080 = 1.88% [1.78–1.99] |
| `tengine` | 932 / 68,080 = 1.37% [1.28–1.46] |
| `wts` | 659 / 68,080 = 0.97% [0.90–1.04] |
| `f-web` | 515 / 68,080 = 0.76% [0.69–0.82] |
| `microsoft-httpapi` | 349 / 68,080 = 0.51% [0.46–0.57] |
| `amazons3` | 339 / 68,080 = 0.50% [0.45–0.55] |
| `cloudfront` | 307 / 68,080 = 0.45% [0.40–0.50] |
| `(empty)` | 250 / 68,080 = 0.37% [0.32–0.42] |
| `beaver` | 247 / 68,080 = 0.36% [0.32–0.41] |
| `hcdn` | 244 / 68,080 = 0.36% [0.32–0.41] |
| (591 others) | 4,637 / 68,080 = 6.81% [6.62–7.00] |

| Server header (verbatim) | share |
|---|---|
| `nginx` | 20,178 / 68,080 = 29.64% [29.30–29.98] |
| `cloudflare` | 15,686 / 68,080 = 23.04% [22.73–23.36] |
| `Apache` | 8,750 / 68,080 = 12.85% [12.60–13.11] |
| `Microsoft-IIS/10.0` | 2,809 / 68,080 = 4.13% [3.98–4.28] |
| `openresty` | 2,393 / 68,080 = 3.51% [3.38–3.66] |
| `Microsoft-IIS/7.5` | 1,310 / 68,080 = 1.92% [1.82–2.03] |
| `LiteSpeed` | 1,282 / 68,080 = 1.88% [1.78–1.99] |
| `Microsoft-IIS/8.5` | 881 / 68,080 = 1.29% [1.21–1.38] |
| `Tengine` | 858 / 68,080 = 1.26% [1.18–1.35] |
| `F-WEB` | 515 / 68,080 = 0.76% [0.69–0.82] |
| `wts` | 432 / 68,080 = 0.63% [0.58–0.70] |
| `nginx/1.30.7` | 376 / 68,080 = 0.55% [0.50–0.61] |
| `Microsoft-HTTPAPI/2.0` | 348 / 68,080 = 0.51% [0.46–0.57] |
| `AmazonS3` | 339 / 68,080 = 0.50% [0.45–0.55] |
| `Nginx Microsoft-HTTPAPI/2.0` | 307 / 68,080 = 0.45% [0.40–0.50] |
| (1640 others) | 11,616 / 68,080 = 17.06% [16.78–17.35] |

| Content-Type of 2xx replies | share |
|---|---|
| `text/html` | 44,970 / 45,368 = 99.12% [99.03–99.20] |
| `*/*` | 210 / 45,368 = 0.46% [0.40–0.53] |
| `application/pdf` | 40 / 45,368 = 0.09% [0.06–0.12] |
| `image/jpeg` | 36 / 45,368 = 0.08% [0.06–0.11] |
| `text/plain` | 22 / 45,368 = 0.05% [0.03–0.07] |
| `application/json` | 15 / 45,368 = 0.03% [0.02–0.05] |
| `application/octet-stream` | 14 / 45,368 = 0.03% [0.02–0.05] |
| `text/xml` | 6 / 45,368 = 0.01% [0.01–0.03] |
| `application/xml` | 5 / 45,368 = 0.01% [0.00–0.03] |
| `image/gif` | 5 / 45,368 = 0.01% [0.00–0.03] |
| `application/vnd.openxmlformats-officedocument.wordprocessingml.d` | 4 / 45,368 = 0.01% [0.00–0.02] |
| `image/png` | 4 / 45,368 = 0.01% [0.00–0.02] |
| `application/rss+xml` | 4 / 45,368 = 0.01% [0.00–0.02] |
| `audio/x-scpls` | 3 / 45,368 = 0.01% [0.00–0.02] |
| `application/x-httpd-php` | 3 / 45,368 = 0.01% [0.00–0.02] |
| (21 others) | 27 / 45,368 = 0.06% [0.04–0.09] |


## Time per site

| p50 | p90 | p99 | max |
|---|---|---|---|
| 969 ms | 4,234 ms | 16,766 ms | 122,469 ms |
