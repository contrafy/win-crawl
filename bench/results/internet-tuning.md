# Tuning the 1M classic crawl on a home connection

Question: which settings crawl `sample_urls/URL-input-1M.txt` fastest on this
machine and connection without losing hosts or pages, and does a local
Unbound resolver help?

Short answer: **keep the current defaults** (`-c 4000 --dns-inflight 2048
--connect-timeout 5000 --timeout 10000`, DNS 1.1.1.1 + 1.0.0.1). They crawl
the 1M list in 160–169 s. No setting tried beat them by more than noise
without losing completeness. The limit is the home router's packet rate.
At ~25K packets/s in and out, a classic crawl needs ≈3.85 packets per URL,
which puts the floor near 150 s. The crawler runs at about 95% of that.
A local Unbound is 2–6× slower than 1.1.1.1 on this setup.

## Setup

- Ryzen 7 9700X (8C/16T), 32 GB, Windows 11 26200, wired 1 GbE to a
  consumer router. Measured line: 263 Mbit/s down (single flow); uplink
  sustained ≥ 28 Mbit/s during real-mode crawls. Idle RTT: gateway 1 ms,
  1.1.1.1 12 ms.
- TCP dynamic port range 10000–65535 (55,535 ports; set machine-wide for this
  round before these runs).
- wincrawl release build of `42e2b5f`, run from a scratch copy. Runs were on
  2026-11-21 between 20:15 and 22:10 local time (evening). Other agents
  were building and running loopback benchmarks and small (≤ 2,000 URL)
  live crawls on the same machine during these runs.
- TlsPq enabled hybrid post-quantum key exchange (X25519MLKEM768) in Schannel
  machine-wide before the real-mode runs below. The ClientHello is now
  ≈1.55 KB (was ≈437 B), which is more than one TCP segment. Classic mode
  is http only and is not affected.

### Method

- **Slices.** `URL-input-1M.txt` shuffled with `random.Random(463)` and cut
  into 20 disjoint 50K-URL slices (`s00`–`s19`, ≈43K unique hosts each). The
  "200K" runs concatenate four slices (groups A = s00–03, B = s04–07,
  C = s12–15, D = s16–19, E = s08–11). Full runs use the unshuffled file.
- **Cache warmth.** 1.1.1.1 had already resolved every name in the list
  earlier that day (the runs in `internet-1m.md`). Fresh slices therefore
  cannot give a cold 1.1.1.1 cache. Control: re-running a slice through
  1.1.1.1 about an hour later changed nothing beyond noise.

  | slice | first run | re-run |
  |---|---|---|
  | s00, `-c 4000` | DNS ok 52.57% | DNS ok 52.58%, 5,078 URLs/s steady |
  | s02, `-c 12000` | 51.92%, 6,318/s | 52.28%, 5,963/s |

  So slices were reused across 1.1.1.1 runs. Each Unbound run started fresh
  processes (cold cache), and each Unbound run used a slice Unbound had not
  seen. Google and mixed-resolver runs used slices never sent to Google before.
- **Per run:** `wincrawl --json`, status lines every 500 ms, process CPU
  time (GetProcessTimes), peak working set, NIC bytes/packets per second
  (`typeperf` on the Realtek adapter, whole machine), and the network as other
  devices see it. That last part is three HTTPS fetches through the router's
  resolver every 2 s (google.com/generate_204, cloudflare.com/cdn-cgi/trace,
  github.com), plus pings to the gateway and to 1.1.1.1 every second.
  `TIME_WAIT` was counted before and after each run.
- **Metrics.** *wall* is process lifetime. *steady URLs/s* is the extraction
  rate between 10% and 90% of the input. *tail* is the time from the last
  URL started to exit, roughly the fetch timeout. A 1M run's wall time is
  about 1M / steady + tail. On 50K slices the tail (11–13 s) is half the run.
  At `-c` ≥ 30000 every URL starts in the first second. So 50K runs only
  compare steady rates at `-c` ≤ 12000. Concurrency, timeouts and DNS
  in-flight were compared on 200K inputs, and the final answer comes from
  full 1M runs in ABBA order.
- **DNS-only instrument.** A throwaway program linked against `wc_dns` and
  `wc_net` (not committed) resolves a file's unique hosts with
  `wc::dns::Resolver` exactly as the crawler does: 16 loops, in-flight split
  per loop, 1500 ms × 3 attempts. It has no HTTP, so DNS can be measured
  alone or next to a crawl.

`port_exhaustion` was 0 in every run. Peak in-flight always reached `-c`
(at `-c 50000` on a 50K slice it was 42,978, which is every unique host).
`TIME_WAIT` stayed under 400 machine-wide.

## Where the ceiling is

| test | result |
|---|---|
| DNS only, 1.1.1.1, 2048 in flight, 43K names | 90% resolved in 4.2–4.5 s → **8.6–9.3K names/s**, 51.6–52.0% ok |
| DNS only, same, 4096 in flight, 85K names | **11.4–11.5K names/s**, peaks 14.3K packets/s out |
| DNS only, 2048 in flight, *while* a `-c 50000` crawl runs | **2.9K names/s** (t90 6.9 s vs 2.2 s alone), 2.3K attempt timeouts vs 1.2K |
| Crawl DNS stage (any resolver, `-c` 4000–50000, in-flight 2048) | ≈4.3K names/s; the stage was never faster than this |
| Open-loop A queries for cached names (Python) | 10K q/s: 100% answered, p50 15 ms. 15K q/s: 97.3%, p50 211 ms |
| Gateway ping during DNS-only load at ≈13–14K packets/s out | 1 ms → 110–170 ms |
| Classic crawl, defaults, 200K | 3.85 packets/URL (in + out); total median 21.3K packets/s, max 25.3K |
| Real mode, defaults, 1M | 8.44 packets/URL; total median 24.9K packets/s, p90 28.4K |

The crawl does not saturate the uplink in bits: classic averages
6.4 Mbit/s, while real mode sustains 20–28 Mbit/s. What it does saturate is
the router's packet rate. Once total traffic passes ~20–25K packets/s, the
router answers its own pings 100–170 ms late, whatever the traffic is (pure
DNS or a crawl). DNS answers queue behind the crawl's TCP packets
(handshakes, requests, ACKs). That is why the crawl's DNS stage sits at
≈4.3K names/s, half of what DNS alone achieves. [INFERENCE: router CPU/NAT
packet rate; whether the limit is the router or the cable modem behind it
cannot be separated without access to either.]

Packet budget: 1M classic URLs × ≈3.8 packets (the full list has slightly
more duplicate hosts than the slices) ÷ ~25K packets/s ≈ **150 s**.
Measured: 160–169 s. Real mode: 1M × 8.44 ÷ 25K ≈ 338 s. Measured:
336–350 s. **A 1-minute 1M classic crawl would need ≈63K packets/s
through the router.** No crawler setting gets there on this connection.

Approximate split of a classic URL's 3.85 packets: DNS is 0.88 queries +
0.88 answers ≈ 46%. TCP is the rest, ≈12 packets per robots/page task
(0.17 tasks per URL): handshake, HEAD, sometimes GET, data and ACKs, and
the RST.

## Concurrency, DNS in-flight, timeouts (1.1.1.1, 200K URLs, ≈167.5K hosts)

| config | wall s (each run) | DNS ok % | DNS retries | DNS timeouts | robots att / passed | pages | connect fail | fetch timeouts | CPU s | peak WS MB | other devices: HTTPS probe median s |
|---|---|---|---:|---:|---|---|---:|---:|---:|---:|---|
| `-c 4000` (defaults) | 80.3, 57.9, 45.6 | 51.0–51.4 | 9.2–12.4K | 345–617 | 34.3–34.9K / 10.5–10.6K | 10,291–10,431 | 5.1–5.6K | 286–308 | 11–13 | 182 | 0.53–1.23 |
| `-c 12000` | 53.4, 48.0, 52.9, 46.1 | 51.0–51.4 | 8.8–10.3K | 344–391 | 34.4–35.0K / 10.5–10.7K | 10,325–10,495 | 5.2–5.3K | 295–313 | 11–14 | 320 | 0.60–0.73 |
| `-c 30000` | 62.7, 47.6 | 51.2–51.4 | 8.8–9.5K | 369–460 | 34.4–34.6K / 10.5–10.7K | 10,353–10,502 | 5.2–5.3K | 288–334 | 14–16 | 500 | 0.69–1.01 |
| `-c 50000` | 50.4, 52.9 | 50.9–51.3 | 9.4–9.9K | 417–418 | 34.3–34.9K / 10.6K | 10,394–10,444 | 5.1–5.2K | 297–309 | 13–17 | 600 | 0.60–0.67 |
| `-c 12000 --dns-inflight 512` | 79.2 | 51.38 | 7,565 | 298 | 34,580 / 10,650 | 10,484 | 5,400 | 298 | 10.7 | | 0.08 |
| `-c 12000 --dns-inflight 1024` | 51.2, 49.0, 48.4 | 51.0–51.2 | 7.9–8.1K | 312–349 | 34.3–34.6K / 10.6K | 10,376–10,406 | 5.1–5.4K | 286–310 | 11–13 | 320 | **0.12–0.18** |
| `-c 12000 --dns-inflight 4096` | 57.5 | **50.70** | **48,156** | **1,614** | 34,185 / 10,328 | **9,965** | 5,179 | 935 | 13.6 | | **4.20** (max 99 = failed) |
| `-c 12000 --connect-timeout 2000` | 61.1 | 51.40 | 12,264 | 485 | 34,922 / 10,578 | 10,406 | 5,349 | 303 | 12.2 | | 0.69 |
| `-c 12000 --connect-timeout 1000` | 57.5 | 51.20 | 10,058 | 369 | 34,582 / 10,404 | **10,230** | **5,817** | 284 | 11.8 | | 0.54 |
| `-c 12000 --timeout 5000` | 51.4 (tail 8.4) | 51.15 | 9,995 | 385 | 34,557 / 10,643 | 10,417 | 330 * | 5,366 * | 13.6 | | 0.73 |
| `-c 12000 --dns-inflight 1024 --timeout 5000` | 46.2 (tail 9.1) | 50.94 | 8,228 | 323 | 34,336 / 10,557 | 10,376 | 331 * | 5,202 * | 11.7 | | 0.11 |
| `-c 30000 --dns-inflight 1024` | 48.1 | 51.42 | 8,151 | 316 | 34,916 / 10,605 | 10,431 | 5,259 | 297 | 12.3 | 500 | 0.12 |

\* With `--timeout` equal to `--connect-timeout` (5000), an unanswered SYN
hits the fetch timeout first, so connect failures move into timeouts.

Idle baseline for the probe: median 0.077 s, max 0.63 s; gateway 1 ms;
1.1.1.1 12 ms, no loss.

Readings:
- **Run-to-run noise is ±15%** in the evening, which is more than most
  differences between configurations. The same defaults on 200K took 45.6
  to 80.3 s. Configurations were therefore checked on full 1M runs (next
  section).
- **Concurrency above 4000 buys nothing that survives 1M runs.** It costs
  memory: peak working set 182 MB at 4000, 320 at 12000, 500 at 30000,
  600 at 50000. CPU stays 11–17 s per 200K URLs at any setting, so CPU is
  not the limit.
- **More DNS in flight hurts.** At 4096 the in-flight queries queue
  behind the crawl's packets at the router. Retries go up 5× and lookups
  that exhaust all attempts go up 4×. DNS ok drops 0.5 points and pages
  drop 4%. At 8192 (50K slice) DNS ok fell from 52% to 45.7%. Other
  devices' HTTPS latency on the network rises to seconds.
- **Less DNS in flight (1024) is the polite setting.** Speed on 200K looked
  the same, the other devices' probe stayed near idle (0.12–0.18 s vs
  0.6–0.7 s), and retries were 15% fewer. The 1M runs show it is ~25%
  slower over a full run, though (below). At 512 the DNS window is the
  bottleneck (2.9K URLs/s).
- **Shorter connect timeouts lose sites and gain nothing.** 1000 ms: +10%
  connect failures and −2% pages. 2000 ms: +2% failures and no speed-up.
  Connect time is not what limits the crawl.
- **`--timeout 5000`** shortens the tail from ≈13 s to ≈9 s, about 4 s
  (2.5%) of a 1M run. Pages were within noise (10,417 vs 10,325–10,495 on
  other runs), but fetches slower than 5 s are dropped by construction.
  Not recommended as a default.

## Resolvers

50K slices, `-c 12000`:

| resolver | slice | wall s | steady URLs/s | DNS ok % | queries | retries | DNS timeouts | robots att | pages |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1.1.1.1 + 1.0.0.1 | s02 / s11 / s02 again | 20.9 / 19.0 / 19.9 | 6,318 / 6,524 / 5,963 | 51.9–52.3 | 45.4–46.0K | 2.7–3.0K | 135–136 | 12.3–12.4K | 3,374–3,548 |
| 8.8.8.8 + 8.8.4.4 | s14 | 21.2 | 6,155 | 51.91 | 46,477 | 3,601 | 98 | 12,494 | 3,491 |
| mixed 4 (1.1.1.1, 8.8.8.8, 1.0.0.1, 8.8.4.4) | s16 | 21.6 | 6,060 | 51.77 | 44,881 | 2,011 | 114 | 12,368 | 3,395 |
| mixed 4, `--dns-inflight 4096` | s17 | 20.7 | 6,247 | 51.37 | 53,771 | 10,962 | 835 | 12,256 | 3,484 |
| 1.1.1.1 pair, `--dns-inflight 4096` | s03 | 22.3 | 6,468 | 51.46 | 52,959 | 10,000 | 796 | 12,343 | 3,454 |
| 1.1.1.1 pair, `--dns-inflight 8192` | s05 | 23.8 | 7,328 | **45.74** | 66,599 | 23,674 | 4,959 | **11,082** | **3,101** |
| Unbound recursive, 16 processes | s08 | 72.7 | 943 | **16.94** | 95,779 | 52,969 | 21,892 | 2,849 | 722 |
| Unbound recursive, 16 processes, `--dns-inflight 512` | s09 | 70.9 | 992 | 49.75 | 50,684 | 7,775 | 1,511 | 11,836 | 3,355 |
| Unbound forwarding (to the 4 above), 64 processes | s10 / s11 | 45.4 / 47.9 | 1,817 / 1,691 | 45.0 / 42.6 | 62.8 / 67.3K | 20.0 / 24.6K | 5.1 / 6.6K | 10.9 / 10.2K | 2,935 / 2,693 |

200K, `-c 12000 --dns-inflight 1024`: 1.1.1.1 pair 51.2 / 49.0 / 48.4 s;
Google 51.9 s (DNS ok 50.84%, retries 5,370); mixed 4 61.9 s (DNS ok 51.11%).

The two public resolver pairs and the mix perform the same within noise,
because the bottleneck is on this side of the line. Google needed fewer
retries, and in DNS-only runs at 2048 in flight it was faster (8.3K vs
5.6K names/s, Python closed-loop probe), but that never showed up in
crawls. Keep 1.1.1.1 + 1.0.0.1.

### Unbound

Official NLnet Labs Windows x64 build `unbound-1.26.2.zip`: SHA-256
`1274c4798ee418601b422e2c8112503844b4644f4bad73e6a691da8c9d1bc0d6`,
matching the published `.sha256`. The `.asc` verified against the NLnet
Labs releases signing key G2 (fingerprint `2310 1869 0C4D 903E F419 146A
A144 323D EAAC DF45`, from nlnetlabs.nl/downloads/keys/). It ran from a
scratch directory as a plain user process: no installer, no service, no
admin. Configs and launcher: [`bench/unbound/`](../unbound/)
(`recursive.conf`, `forward.conf`, `farm.py`).

The Windows build does not scale like the Unix one:

- It has no libevent. Each thread waits on its sockets with
  `WSAWaitForMultipleEvents`, which caps a thread at 64 sockets. With
  `outgoing-range: 1024` the log fills with `error: event_add failed. in
  cpsl.` The Windows defaults are `outgoing-range: 48`,
  `num-queries-per-thread: 24`.
- All queries arriving on one listening socket are served by one thread:
  with `num-threads: 16`, `unbound-control stats` showed `thread13.num.queries=50999`
  and 0 on the other 15.
- The workaround is a farm: `farm.py` starts N single-threaded processes on
  ports 5400+i, and `wincrawl --dns 127.0.0.1:5400,127.0.0.1:5401,…`
  rotates across them. Per process: 48 upstream ports, up to 256 queued
  queries, a 64 MB message cache and a 128 MB rrset cache, iterator only
  (no DNSSEC validation, so no DS/DNSKEY lookups),
  `qname-minimisation: no`, IPv4 only.

DNS-only measurements (the `wc_dns` instrument; names/s is 90% of names
divided by the time to resolve them; DNS ok is NOERROR with an A record):

| setup | wincrawl in-flight | names | names/s | DNS ok | timeouts after 3 attempts |
|---|---:|---:|---:|---:|---:|
| 1.1.1.1 + 1.0.0.1 | 2048 | 43,059 | 9,312 | 51.8% | 86 |
| 1.1.1.1 + 1.0.0.1 | 32 | 2,860 | 143 | 55.3% | 9 |
| one Unbound, `num-threads: 16`, `outgoing-range: 1024` | 2048 | 22,001 | 631 | 21.8% | 11,802 |
| one Unbound process (`recursive.conf` as committed) | 32 | 2,860 | 144 | 55.5% | 19 |
| recursive farm × 16 | 256 | 2,827 | 361 | 52.2% | 152 |
| recursive farm × 16 | 512 | 21,959 | **1,016** | 51.2% | 351 |
| recursive farm × 16 | 2048 | 22,001 | 892 | 36.1% | 5,167 |
| recursive farm × 32 | 1024 | 21,950 | 313 | 19.2% | 11,067 |
| recursive farm × 64 | 512 | 21,889 | 211 | 33.0% | 6,448 |
| forwarding farm × 16 | 2048 | 22,001 | 1,942 | 49.7% | 795 |
| forwarding farm × 64 | 2048 | 21,804 | **2,736** | 52.0% | 311 |

At 32 in flight Unbound and 1.1.1.1 are equally fast (≈0.22 s per name)
and find the same names (1,588 vs 1,582 of 2,860). There are no hidden
hosts that a validating public resolver drops. Under load, recursion
collapses as processes are added. Every crawl name is a different
second-level domain, so each one costs a TLD referral plus an
authoritative query from one home IP, and each upstream query uses a fresh
random source port, which is a new NAT entry. During the recursive crawls
the gateway ping went from 1 ms to 17–18 ms median and 1.1.1.1 from 12 ms
to 66–156 ms. [INFERENCE: TLD-server rate limiting and router NAT churn;
neither could be observed directly.]

**Conclusion: no local resolver.** A cache cannot help when nearly every
name is unique, and recursion multiplies the packets that are already the
bottleneck. Best Unbound recursive crawl: 992 URLs/s and 49.75% DNS ok,
vs 6.0–6.5K URLs/s and ≈52% via 1.1.1.1. Best forwarding crawl: 1.7–1.8K
URLs/s and 42.6–45.0% DNS ok.

## Full 1M runs

Classic mode, unshuffled list (1,000,000 URLs, 824,981 unique hosts),
1.1.1.1 + 1.0.0.1, ABBA order (default, candidate, candidate, default),
then the remaining two configurations, then default again:

| | defaults #1 | `-c 12000 --dns-inflight 1024` #1 | same #2 | defaults #2 | `-c 12000` | `-c 12000 --dns-inflight 4096` | defaults #3 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Wall time | **159.8 s** | 200.3 s | 211.7 s | 169.1 s | 159.7 s | 159.2 s | 163.9 s |
| URLs/s (overall / steady) | 6,256 / 7,081 | 4,994 / 5,422 | 4,724 / 5,009 | 5,912 / 6,762 | 6,262 / 7,026 | 6,282 / 7,072 | 6,101 / 6,975 |
| Tail | 10.7 s | 12.7 s | 13.1 s | 12.1 s | 13.1 s | 13.1 s | 11.8 s |
| DNS ok | 50.42% | 50.48% | 50.58% | 50.25% | 50.46% | **49.80%** | 50.97% |
| DNS queries / retries / timeouts | 876,486 / 53,402 / 2,351 | 866,403 / 43,319 / 1,807 | 870,368 / 47,284 / 1,778 | 882,858 / 59,774 / 2,601 | 876,880 / 53,796 / 1,955 | 957,003 / **133,919 / 7,163** | 880,456 / 57,372 / 2,025 |
| Robots attempted / passed | 114,086 / 35,528 | 114,069 / 35,482 | 114,072 / 35,545 | 114,085 / 35,423 | 114,028 / 35,408 | **112,603 / 34,788** | 114,046 / 35,327 |
| Pages crawled | 34,906 | 34,885 | 34,939 | 34,776 | 34,792 | **33,751** | 34,677 |
| Connect failures / fetch timeouts | 18,942 / 1,023 | 18,853 / 1,023 | 18,858 / 1,025 | 18,940 / 1,065 | 18,962 / 1,027 | 19,169 / 1,483 | 19,263 / 1,038 |
| Port exhaustion | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Peak in-flight | 4,000 | 12,000 | 12,000 | 4,000 | 12,000 | 12,000 | 4,000 |
| Crawler CPU (user + kernel) | 39.8 s | 43.4 s | 38.5 s | 39.0 s | 40.7 s | 42.4 s | 39.0 s |
| Peak working set | 323 MB | 548 MB | 549 MB | 324 MB | 547 MB | 555 MB | 323 MB |
| Upload: total / median | 129 MB / 7.1 Mbit/s | 129 MB / 5.3 | 129 MB / 5.0 | 135 MB / 6.8 | 128 MB / 7.1 | 139 MB / 7.4 | 130 MB / 6.8 |
| Other devices: HTTPS probe median / max | 0.44 / 2.4 s | 0.10 / 1.4 s | 0.16 / 1.8 s | 0.50 / 2.4 s | 0.50 / 2.6 s | **1.21 / 7.8 s** | 0.46 / 2.9 s |
| Gateway ping median | 77 ms | 1 ms | 1 ms | 90 ms | 99 ms | 361 ms | 92 ms |

- Defaults: 159.8 / 169.1 / 163.9 s (mean 164.3 s). `-c 12000` gives the
  same time (159.7 s) and uses 70% more memory. `-c 12000
  --dns-inflight 4096` gives the same time again (159.2 s) but finds 1,483
  fewer sites (−1.3%) and 1,155 fewer pages (−3.3%), and it loads the
  router hardest (gateway ping 361 ms, other devices' HTTPS median 1.2 s).
- `--dns-inflight 1024` is 25% slower over a full run (200–212 s) while
  leaving the network usable for everyone else: probe median 0.10–0.16 s,
  gateway ping 1 ms.
- These are the same build as one another. The 204.5 s (`-c 4000`, build
  `22a9007`) vs 152.2 s (`-c 12000 --dns-inflight 4096`, build `a5acfcc`)
  comparison in `internet-1m.md` mixed two builds, with engine review fixes
  in between, and two times of day. On one build at one time,
  concurrency makes no difference.
- DNS cache warmth: every name had passed through 1.1.1.1 earlier the same
  day and in the preceding runs. These numbers are for a warm 1.1.1.1. The
  slice re-run control above suggests warmth is worth little here, because
  failures and SERVFAILs dominate DNS time and negative answers expire
  quickly. [INFERENCE: a truly cold run was not possible to stage.]

### Real mode

Real mode on the same list (http + https, RFC 9309 robots.txt, redirects,
offline certificate verification), with PQ hybrid key exchange on:

| | `--mode real -c 8000` | `--mode real` (`-c 4000`) |
|---|---:|---:|
| Wall time | **335.7 s** | 350.1 s |
| URLs/s (overall / steady) | 2,979 / 3,882 | 2,856 / 3,959 |
| DNS ok | 50.44% | 50.66% |
| DNS queries / retries / timeouts | 958,633 / 113,506 / 4,281 | 926,739 / 81,011 / 3,041 |
| Robots attempted / allowed | 113,593 / 74,428 | 113,912 / 76,211 |
| Pages crawled | 73,080 | **74,849** |
| HTTP 2xx / 3xx / 4xx / 5xx | 45,006 / 4,880 / 22,507 / 687 | 46,800 / 5,001 / 22,384 / 664 |
| Data received | 3,835 MB | 4,183 MB |
| Links | 3,688,184 | 3,915,758 |
| Redirects followed | 32,193 | 34,841 |
| TLS failures (certificate) | 1,280 (912) | 1,338 (996) |
| Connect failures / fetch timeouts | 20,564 / 14,010 | 23,022 / 10,517 |
| Crawler CPU / peak working set | 130.7 s / 775 MB | 126.9 s / 467 MB |
| Packets out / s (median / max) | — | 10.2K / 13.3K |
| Other devices: HTTPS probe median / failures | 1.07 s / 8 | 1.30 s / 4 |
| 1.1.1.1 ping median (lost) | 303 ms (124/187) | 611 ms (140/185) |

The documented real-mode run (`-c 8000`, 309.4 s, before PQ) now takes
335.7 s. One cause is that the 1.55 KB ClientHello needs two TCP segments
where it used to need one. The evening network is another; the two cannot
be separated from these runs. `-c 4000` was 4% slower but crawled 1,769
more pages, with 3,493 fewer fetch timeouts. Real mode is also packet-bound
(≈25K packets/s), and at `-c 8000` more fetches time out waiting in the
router's queue. Real mode makes the home network nearly unusable for
everyone else for the duration: HTTPS probes take over a second and some
time out at 10 s.

## Recommendation

**Defaults: unchanged.**

| option | default | verdict |
|---|---|---|
| `-c` | 4000 | keep: 12000–50000 is not faster on 1M and costs 1.7–1.9× memory |
| `--dns-inflight` | 2048 | keep: 4096 loses 1.3% of sites and 3.3% of pages at equal speed; 1024 is 25% slower |
| `--connect-timeout` | 5000 | keep: 1000 loses 2% of pages, 2000 gains nothing |
| `--timeout` | 10000 | keep: 5000 saves ≈4 s of tail and drops fetches slower than 5 s |
| `--dns` | 1.1.1.1,1.0.0.1 | keep: Google and the mix are equal within noise; local Unbound is 2–6× slower |

For the README:

- In the results table, use the defaults row (`wincrawl
  sample_urls\URL-input-1M.txt`: 159.8 s, 50.4% DNS ok, 114,086 sites
  checked, 34,906 pages). Drop the `-c 12000` column as a speed claim:
  `-c 12000` measured 159.7 s on the same build.
- Suggested sentences: "On a home connection the 1M crawl takes about
  160 seconds at the default settings. Raising `-c` or `--dns-inflight`
  doesn't make it faster. The home router tops out around 25,000 packets/s,
  and the crawl needs about 3.8 packets per URL, which puts the floor near
  150 s." And: "`--dns-inflight 1024` keeps the rest of the household's
  network responsive (web latency stays near idle instead of rising to
  ~0.5 s) at the cost of a ~25% slower crawl."
- "Running it on your machine": a local Unbound does not help. Its Windows
  build serves one listening socket from one thread with at most 64
  sockets, and recursing for ~800K unique domains from one IP is slower
  than a public resolver.

## Code changes worth considering (not made here)

Throughput on this connection is packets per URL divided by the router's
packet rate, so only changes that remove packets help. Expected gains are
small:

1. **Send the first request with `ConnectEx`.** `wc::net` calls `ConnectEx`
   with no send buffer (`src/net/tcp.cpp`). Passing the HEAD/GET as
   `lpSendBuffer` may let the request ride with the handshake's final ACK.
   That saves up to 1 packet per connection: ≈114K of ≈3.8M packets per 1M
   classic run, ≤ 3% (≈5 s). [INFERENCE: whether Windows merges the ACK
   with the data was not checked.]
2. **Adaptive DNS window.** No fixed `--dns-inflight` was both fast and
   polite. An AIMD window per loop (grow while DNS RTT is near its floor,
   halve on rising RTT or timeouts) would track the router's queue. That
   would remove most of the ≈55K retries per run (1.4% of packets). Its
   real value is keeping the 2048-speed with the 1024 network impact.
   [INFERENCE: not prototyped.]
3. **Don't add DNS work to the classic run.** `--https-rr` (HTTPS RR per
   host) adds ≈1.76 packets per URL, ≈46% more packets, so expect classic
   runs with it to take ~45% longer on this connection. The EDNS0 OPT
   record DnsHttps adds to every query costs 11 bytes per query but no
   extra packets, so it should not matter here.
4. **PQ ClientHello.** X25519MLKEM768 makes the ClientHello two segments
   (plus the server's extra ACK), roughly +2 packets per TLS handshake,
   about 2–3% of a real-mode run's packets. Worth stating when real-mode
   times are compared across the PQ change. [INFERENCE: packet count
   derived from the ClientHello size, not captured.]

## Machine changes

None by this work. The TCP dynamic port range (10000–65535) was set for
this round before it started; it was not changed here. Unbound ran as
ordinary user processes from a scratch directory: no installer, service,
firewall rule or registry change. Every Unbound process was stopped after
each experiment (none left running). Scratch files were deleted.
