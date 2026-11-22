# Measurement study: method

wincrawl's real mode doubles as a measurement instrument. With `--record FILE`
it writes one JSON line per site it attempts, describing what the crawl
observed: DNS, liveness, robots.txt, redirects, TLS version and key exchange
(including post-quantum hybrids), HTTP/3 advertisement, HSTS, HTTPS DNS
records and ECH, and whether the site sits behind Cloudflare.
`tools/study/analyze.py` turns a record file into a markdown report with
denominators and 95% confidence intervals.

The target dataset is the 2015-era 1M seed list (`sample_urls/URL-input-1M.txt`)
as the web answers in 2026.

## Reproducing

```powershell
cmake --preset release; cmake --build --preset release

# The study run (real mode, post-quantum offered, HTTPS RRs queried)
build\release\wincrawl.exe --mode real --record study.jsonl --https-rr --json study.json sample_urls\URL-input-1M.txt

# Control run without post-quantum groups in the ClientHello
build\release\wincrawl.exe --mode real --record study-nopq.jsonl --no-pq sample_urls\URL-input-1M.txt

# Report
python tools\study\analyze.py study.jsonl --seeds 1000000 --title "1M seeds, 2026" > study.md

# Analyzer tests
python -m unittest discover -s tools/study/tests
```

`--record` works in both modes; classic mode records only the fields it can
observe (http only, `HEAD /robots.txt`, no redirects, no TLS). `--https-rr`
needs `--record`. `--no-pq` affects real mode only.

The run header, the final summary and `--json` (`pq_requested`, `pq_offered`)
say whether post-quantum key exchange was requested and whether this
process's ClientHello actually offers a post-quantum group. Schannel enables
the ML-KEM groups machine-wide (see `docs/tls-notes.md`); `--no-pq` removes
them for the process, so a control run needs no machine change.

## What one record means

A record is written for every input line that parsed (and, in classic mode,
is `http://`) **and passed host dedupe**: the first URL seen for each host.
Every other URL is skipped before any network activity and has no record.
Records appear in completion order, not input order.

The pipeline for a site is: resolve the seed host (A record, IPv4) → IP
dedupe → `robots.txt` of the seed origin → the seed page, following up to
`--max-redirects` (5) redirects; each new origin on the way gets its own DNS
lookup (no dedupe) and robots.txt check. With `--https-rr` the host's HTTPS
RR (type 65) is queried in parallel with the fetches as soon as the A lookup
succeeds, and the record is written once both are done.

Fields that do not apply to a site are `null`, never omitted; every line has
the same keys in the same order.

### Fields

| key | type | meaning |
|---|---|---|
| `url` | string | the input line (trimmed), as given |
| `host` | string | the seed host, lowercased |
| `dns` | string | A lookup of the seed host: `ok`, `nxdomain`, `noanswer` (NOERROR without an A record, or truncated), `servfail` (SERVFAIL/REFUSED/other rcode on every attempt), `timeout` (no reply after every attempt), `invalid` (not a DNS name), `cancelled` (run stopped); null only if the run stopped before the lookup started |
| `ip` | string | first A record, dotted quad; null unless `dns` is `ok` |
| `ip_dup` | bool | the host was over its IP's host budget (`--hosts-per-ip`, default 1: the IP was already claimed by an earlier host, the assignment's IP dedupe); such sites are not fetched |
| `cf_ip` | bool | the IP lies in Cloudflare's published IPv4 ranges (`data/cloudflare-ips-v4.txt`, compiled in) |
| `https_rr` | object | null unless `--https-rr` and `dns` is `ok`; see below |
| `robots_status` | int | status of the seed origin's robots.txt reply, after robots redirects (the last reply in that chain) |
| `robots_error` | string | why the seed origin's robots.txt fetch failed: a fetch error (below) or `redirect_dns` (a robots redirect to a host that did not resolve) |
| `robots_allowed` | bool | the page fetch was permitted. Classic: robots answered 4xx. Real: RFC 9309 (2xx rules for the `wincrawl` token, 4xx = allow all, 5xx/unreachable = disallow all, robots redirects followed up to 5 hops) |
| `fetch` | string | how the page chain ended: `ok` (the last request got a reply), a fetch error, `redirect_dns` (a redirect target did not resolve), `robots_blocked` (a redirect led to an origin whose robots.txt disallows the page); null if the page was never requested |
| `status` | int | status of the last page reply received |
| `redirects` | int | page redirects followed; null if the page was never requested |
| `final_url` | string | URL of the last page reply received |
| `https_upgrade` | bool | the seed was `http://` and the last page reply came over https |
| `tls` | object | first TLS handshake of the site; null if no https connection got as far as TLS; see below |
| `alt_svc_h3` | bool | the last page reply has an `Alt-Svc` alternative with protocol id `h3` or `h3-NN` (all `Alt-Svc` header lines are read) |
| `hsts` | bool | the last page reply was over https and carried `Strict-Transport-Security`; null for replies over http (browsers ignore HSTS there, RFC 6797 §8.1) |
| `hsts_max_age` | int | `max-age` of that header; null when the header is invalid (no or repeated max-age, non-numeric) |
| `hsts_sub`, `hsts_preload` | bool | `includeSubDomains` / `preload` directives; null unless `hsts` is true |
| `server` | string | `Server` header of the last page reply, first 64 bytes |
| `cf_ray` | bool | the first HTTP reply of the site carried `CF-RAY`; null if nothing replied |
| `content_type` | string | `Content-Type` of the last page reply, first 64 bytes |
| `bytes` | int | decoded body bytes of the last page reply |
| `links` | int | links extracted from it (2xx `text/html` / `application/xhtml+xml` only in real mode, any 2xx in classic) |
| `ms` | int | milliseconds from the task start (input line claimed) to the record, DNS queueing included |
| `skip` | string | why politeness skipped the host or its page: `ip_budget`, `ip_unreachable`, `crawl_delay`; null otherwise ([`politeness.md`](politeness.md)) |
| `wait_ms` | int | time the site waited on politeness (IP queue and spacing, Crawl-delay, Retry-After) |
| `crawl_delay` | number | Crawl-delay (seconds) in the seed origin's robots.txt |
| `crawl_delay_ms` | int | the part of `wait_ms` spent on Crawl-delay |
| `retry_after` | int | Retry-After (seconds) of the first 429/503 that carried one |
| `retried` | bool | that Retry-After was waited out and the request repeated once |

Fetch errors: `connect_fail` (refused, unreachable, or `--connect-timeout`),
`timeout` (the whole fetch exceeded `--timeout`), `tls_fail`,
`tls_certificate` (rejected by offline chain verification), `too_large`,
`bad_reply` (not HTTP/1.x), `closed` (reset or EOF before a complete reply),
`no_ports` (ephemeral ports exhausted after ~15 s of retries), `aborted`
(Ctrl+C).

`tls` object:

| key | meaning |
|---|---|
| `handshake` | `ok`; `certificate` (Schannel completed the handshake, our offline chain check rejected the certificate; the negotiated parameters are still recorded); `failed` (Schannel rejected the handshake: alert, no common parameters, not TLS); `incomplete` (the fetch ended mid-handshake: timeout, reset) |
| `version` | `"TLS 1.3"` / `"TLS 1.2"`; null without a completed handshake |
| `cipher` | cipher suite, e.g. `TLS_AES_256_GCM_SHA384` |
| `group` | negotiated key-exchange group by IANA name (`X25519MLKEM768`, `x25519`, `secp256r1`, ...), `0xNNNN` for a code point the TLS module cannot name, null for none (TLS 1.2 RSA key transport) |
| `pq` | the group is a post-quantum hybrid |
| `resumed` | abbreviated (resumed) handshake |

`https_rr` object: `status` (the HTTPS query's outcome, same names as `dns`;
NODATA is `noanswer`; ~12% of resolving hosts answer SERVFAIL for this type
through 1.1.1.1), `present` (a usable HTTPS RRset), `alias` (AliasMode),
`h3` / `h2` (alpn contains them), `ech` (an `ech` SvcParam). The booleans are
false unless `present`.

### Which reply a field comes from

- **First reply** (`cf_ray`): the first fetch of every site is the seed
  origin's robots.txt at the seed IP, so `cf_ray` and `cf_ip` describe the
  same server.
- **Seed origin's robots chain** (`robots_*`).
- **Last page reply** (`status`, `final_url`, `server`, `content_type`,
  `bytes`, `links`, `alt_svc_h3`, `hsts*`): the reply that ended the
  redirect chain, or the last reply before a later hop failed (then `fetch`
  says why).
- **First TLS handshake** (`tls`): the first https connection of the site,
  robots.txt or page, at whatever hop it happened. Resumption is therefore
  rare: there is no earlier session for that name.

## Cloudflare detection

Two independent signals, both recorded, so the analyzer can report each and
their agreement:

- `cf_ip`: the seed IP is in `https://www.cloudflare.com/ips-v4` (fetched
  2026-11-22, `data/cloudflare-ips-v4.txt`). Editing the file and rebuilding
  updates the binary (CMake embeds it).
- `cf_ray`: the first reply carried a `CF-RAY` header. This also catches
  Cloudflare customers on dedicated or BYOIP address space, and misses
  nothing that Cloudflare proxies.

"Behind Cloudflare" in the report means either signal. In the validation
sample the two agree on 98.6% of sites where both are known.

## Writer design and overhead

Each event loop serializes finished records into its own buffer (reserved at
320 KiB). When a buffer reaches 256 KiB (~500 records) the loop hands it to
the writer thread under one mutex and takes back an emptied buffer from a
free pool; the writer issues one `WriteFile` per buffer. Per-site strings live
in the task slot's `SiteRecord` and keep their capacity, so steady state
allocates nothing per record (the TLS cipher/group names come from
`ClientSession::info()`, which returns strings). Loops never contend per
record; output order is completion order.

Measured (Ryzen 9700X, release build, shared machine):

| measurement | result |
|---|---|
| serializing one full record (`append_json`, every field set, 784 bytes) | 510 ns (3 runs: 508, 517, 510), 1.5 GB/s |
| loopback rig, classic, 200K URLs, `-c 2000`, 179,960 records (91 MB), 3 runs each | without `--record` 21.3 / 21.6 / 21.6 s; with 19.7 / 21.6 / 21.2 s |
| same, real mode (http only), 2 runs each | without 19.9 / 20.8 s; with 21.1 / 20.9 s |
| process CPU, classic runs above | without 126 / 124 / 122 s; with 115 / 122 / 122 s |

At ~8,500 records/s the difference is inside run-to-run noise. At the
study's rate (~6K records/s) serialization costs ~3 ms of CPU per second
across all loops. Rig: `wincrawl-benchd serve --dns 127.0.0.1:35300 --http
0.0.0.0:38080 -t 4` (lan profile), URLs from `wincrawl-benchd gen --count
200000 --port 38080`.

## Analyzer

`tools/study/analyze.py RECORDS [--seeds N] [--title T] [--top N]` (Python
3.10+, standard library only) prints:

- funnel: seeds → unique hosts → DNS ok → unique IPs → robots attempted →
  robots allowed → page attempted → page reply → final 2xx, each as a share of
  the previous stage;
- link rot: NXDOMAIN, no A record, SERVFAIL, DNS timeout, connect failure and
  timeout on the first request, as shares of unique hosts;
- http→https upgrade share, redirect count distribution, fetch outcomes;
- final and robots.txt status distributions;
- TLS handshake outcomes, versions, groups, ciphers; post-quantum hybrid share
  of TLS 1.3 handshakes and of all completed handshakes;
- Alt-Svc h3 share; HSTS share, validity, max-age distribution,
  includeSubDomains, preload;
- HTTPS RR status, presence, AliasMode, alpn h3/h2, ECH;
- Cloudflare by IP range, by CF-RAY, their 2×2 agreement table, and the
  TLS 1.3 / PQ / h3 / HSTS / HTTPS RR / ECH shares split by behind-Cloudflare
  vs not;
- top Server products and verbatim values, Content-Types, time per site.

Every share is `k / n = p% [lo–hi]` with the Wilson score 95% interval. Each
denominator is the population the fact can be observed on (e.g. HSTS: last
replies over https; PQ: completed TLS handshakes), named in the row.

## Validation sample

2,000 URLs drawn uniformly from the 1M list (`random.Random(463).sample`),
real mode, `-c 2000 --record --https-rr`, Verify::Chain, 2026-11-22, home
connection, 1.1.1.1/1.0.0.1, while another crawl was using the same uplink
and resolvers. 1,921 records in 23.0 s. Selected results:

| fact | share |
|---|---|
| DNS ok, of unique hosts | 991 / 1,921 = 51.59% [49.35–53.82] |
| dead (NXDOMAIN + no A + connect failure), of unique hosts | 849 / 1,921 = 44.20% [41.99–46.43] |
| http seeds ending on https, of seeds with a page reply | 235 / 537 = 43.76% [39.62–47.99] |
| TLS 1.3, of completed handshakes | 254 / 291 = 87.29% [82.97–90.63] |
| X25519MLKEM768, of TLS 1.3 handshakes | 186 / 254 = 73.23% [67.47–78.30] |
| Alt-Svc h3, of last replies over https | 67 / 235 = 28.51% [23.12–34.59] |
| HSTS, of last replies over https | 95 / 235 = 40.43% [34.35–46.81] |
| HTTPS RR present, of resolved hosts | 158 / 991 = 15.94% [13.80–18.35] |
| ECH in the HTTPS RR, of resolved hosts | 115 / 991 = 11.60% [9.76–13.75] |
| behind Cloudflare (either signal), of resolved hosts | 170 / 991 = 17.15% |
| PQ hybrid, of TLS 1.3 handshakes: Cloudflare vs not | 85 / 86 = 98.84% vs 101 / 168 = 60.12% |
| HTTPS RR present: Cloudflare vs not | 145 / 170 = 85.29% vs 13 / 821 = 1.58% |

A `--no-pq` control on the first 300 of those URLs negotiated only `x25519`
(64) and `secp256r1` (2), with `pq_requested`/`pq_offered` false.

## Limitations

- **IP dedupe biases the HTTP-level population.** Sites whose IP an earlier
  host already claimed (20.9% of resolving hosts in the sample) are never
  fetched, and shared IPs are typical of CDNs and shared hosting. HTTP, TLS,
  Alt-Svc and HSTS shares therefore describe "the first site on each IP";
  DNS-level facts (`cf_ip`, `https_rr`) cover every resolving host.
- **robots.txt gates the page.** A disallowing robots.txt means no page reply,
  so no Alt-Svc/HSTS/Server facts for that site (the TLS handshake of an https
  robots.txt is still recorded).
- **IPv4 and A records only.** AAAA-only hosts count as `noanswer`.
- **HTTP/1.1 over TCP only.** HTTP/3 is inferred from the Alt-Svc
  advertisement and the HTTPS RR alpn, not from a QUIC connection.
- **DNS timeouts depend on load.** The validation run saw 10.4% A-lookup
  timeouts with `--https-rr` and 7.5% without it on a rerun of the same URLs
  (warm resolver caches), against 0.3% in the design notes' unloaded
  measurement: HTTPS queries share the per-loop in-flight cap
  (`--dns-inflight`) and the retry budget with A lookups. The resolver's
  `dns_queries_sent`/`dns_retries`/`dns_timeouts` counters in `--json` include
  HTTPS queries; the funnel's `dns_ok`/`dns_fail` (D) count A lookups only.
- **Certificate verification is offline.** `tls_certificate` includes sites
  whose root Windows has not downloaded yet (see the design notes);
  their TLS parameters are recorded regardless.
- **Single vantage point, single moment.** One home connection and one public
  resolver; CDN-specific answers (e.g. ECH configs, Alt-Svc) may differ by
  location.
