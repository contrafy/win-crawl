# Politeness: crawling every host, not one per IP

The assignment's pipeline skips any host whose IP an earlier host already
claimed. In the 1M study that skipped 72.6% of resolving hosts, so the HTTP and
TLS findings describe "the first host on each IP". Dropping the dedupe is only
acceptable with per-target politeness: the same data shows how concentrated
the hosts are.

| hosts per IP (1M study, 416,928 resolving hosts on 113,963 IPs) | IPs | hosts |
|---|---:|---:|
| ≥ 2 | 27,692 | 330,657 |
| ≥ 50 | 508 | 150,264 |
| ≥ 1,000 | 20 | 75,360 |
| largest (221.122.123.81, not Cloudflare) | 1 | 27,391 |
| Cloudflare's published ranges | 20,275 | 63,498 (largest IP 3,184) |

Without limits the crawler would open thousands of connections per second to
221.122.123.81.

## Policy and defaults

Every new TCP connection takes a slot at its IP's gate first. Keep-alive
requests on an open connection (robots.txt, then the page) are not new
connections.

| knob | default | option |
|---|---|---|
| hosts fetched per IP | 1 (the assignment's IP dedupe), both modes | `--hosts-per-ip N`, `0` or `--no-ip-dedupe` = unlimited |
| connections open at once per IP | 2 | `--ip-concurrency N` (0 = no cap) |
| time between connection starts to one IP | 250 ms | `--ip-interval MS` |
| 429/503 back-off | the IP's spacing gains a penalty: max(interval, 1 s), doubling per throttle up to 60 s, halved by every normal reply; the next start waits it out | always on (off for CDN IPs) |
| `Retry-After` on 429/503 | real mode: waited out (no socket held) and the request repeated once, if ≤ 30 s | `--max-retry-after S` |
| robots.txt `Crawl-delay` | real mode: honoured between requests to that host, up to 30 s; above it the page is skipped (`skip: "crawl_delay"`) | `--max-crawl-delay S` |
| unreachable IPs | after 5 failed connections in a row (refused, unreachable, timed out, no reply) the IP's remaining hosts are skipped (`skip: "ip_unreachable"`) | `--ip-fail-limit N` (0 = never) |
| CDN IPs (Cloudflare ranges, `data/cloudflare-ips-v4.txt`) | 16 connections, no spacing, no back-off; host budget unlimited unless `--hosts-per-ip` is 1 | `--cdn-ip-concurrency`, `--cdn-ip-interval`, `--cdn-hosts-per-ip`, `--no-cdn-policy` |
| redirects to a busy IP | wait ahead of new sites; at most 64 may wait per IP, past that the hop is given up (`fetch: "ip_busy"`) | fixed |

Why these choices:

- **Real mode keeps a budget of 1 by default.** The published study, the
  README numbers and every existing run stay reproducible with the same
  command. Measurement runs opt in explicitly (recommended settings below).
- **2 connections, 250 ms apart** is about 4 connection starts per second at
  most per IP: little load for a server that hosts thousands of sites, and
  still enough that a shared host with 2,000 sites finishes in ~30 minutes.
- **CDN edges are exempt from the origin limits.** Per-IP limits protect the
  origin behind the IP. An anycast Cloudflare IP fronts thousands of unrelated
  origins (the largest CF IP in the study carries 3,184 hosts); each host is
  still fetched once, with its own robots.txt and Crawl-delay. A 429 from one
  zone says nothing about the edge's other zones, so CDN IPs get no back-off.
  `--no-cdn-policy` treats them like any other IP.
- **Retry-After is per host, not per IP.** On shared hosting a 503 often comes
  from one vhost's maintenance page (WordPress answers `503` with
  `Retry-After: 600`). Pushing the whole IP by the server's Retry-After stalled
  unrelated hosts: on the rig, whose synthetic 503s carry `Retry-After: 120`,
  it turned a 20 s run into 79–137 s. The IP gets the doubling penalty
  instead; the host itself waits out its Retry-After once.
- **robots.txt 429 means disallow.** RFC 9309 §2.3.1.3 lets a crawler treat
  4xx as "no robots.txt", but a rate-limited robots.txt is not an invitation;
  Google likewise treats 429 like a server error
  ([How Google interprets robots.txt](https://developers.google.com/crawling/docs/robots-txt/robots-txt-spec):
  "all 4xx errors, except 429"). Classic mode keeps the assignment's rule.
- **Unreachable IPs are cut short.** In the 1M study 23,818 IPs carrying
  78,557 hosts refused the first connection and 6,049 IPs (16,265 hosts) timed
  out. At 2 connections per IP, 4,899 refused hosts on one IP would take over
  an hour of 2–5 s connect failures; the breaker stops after 5.

### Crawl-delay and RFC 9309

`Crawl-delay` is not part of RFC 9309. §2.2.4 ("Other Records") allows
crawlers to interpret records outside the protocol, which is the status it
has: a de-facto extension. Google does not support it ("other fields such as
crawl-delay aren't supported", same Google page); Bing documents it. wincrawl
honours it because a site that asks for one is telling us its capacity, and
caps it because a site asking for minutes between requests would otherwise
hold a crawl slot for that long. In the live check below 2.7% of robots.txt
files (15 of 552) set one, mostly 5–10 s.

## Design

```
DNS ok ─► IpGates::seed(ip) ─┬─ over budget / IP dead ─► record, no fetch
                             ├─ Now ─► connect (robots, then page on the same connection)
                             └─ Queued ─► 48-byte waiter in the IP's FIFO, the task slot is freed
release / spacing timer (any loop) ─► pop waiter ─► post to its loop ─► free task ─► connect ─► started()
```

- **Shared, sharded gate table** (`src/crawl/politeness.{h,cpp}`): one gate per
  IPv4 in 256 SRWLOCK shards, the layout of the existing dedupe sets. It
  replaces `IpSet`: the IP dedupe is the budget at 1. The alternative, routing
  each site to an IP-owner loop, would move live sites between loops, but a
  site's socket, timers, HTTPS RR query and record all belong to its loop.
  With shared gates the fast path is one lock to admit and one to release,
  and loops only talk when a waiter is woken.
- **Waiting never holds a socket.** A new site that cannot start becomes a
  48-byte waiter (input line, IP, timestamps) and its task slot goes straight
  back to work, so 27,000 hosts queued on one IP cost about 1.3 MB, not 27,000
  task slots. A site already under way (redirect to another IP, reconnect
  after Crawl-delay or Retry-After, spacing before a reconnect) parks its task:
  no socket, and up to `-c / threads` parked tasks per loop do not count
  against `-c`. The task pool grows to twice the slots for that.
- **FIFO with priority.** Sites under way queue ahead of new sites, so a site
  that started finishes first. At most 64 may wait per IP for a redirect hop.
- **Who wakes waiters.** A release on any loop pops what the gate can admit
  and posts it to the waiter's loop. When the gate has room but its spacing has
  not elapsed, the loop that noticed arms a timer and stays alive until it
  fires.
- **Spacing counts from the real connect.** A woken site connects only when
  its loop gets to it, which under full load takes a while. An admitted but not
  yet connected start blocks further starts at that IP until it reports
  `started()`, and the spacing counts from that moment. Before this, the
  tracked rig measured gaps down to 210 ms at 250 ms spacing.
- **Clock.** Gate decisions use a QueryPerformanceCounter clock. Loop timers
  tick every 15.6 ms; a timer that fires early re-arms, so the spacing is never
  shorter than configured on the crawler's side.
- **No deadlock.** A task never waits while holding a slot (it releases before
  it acquires elsewhere), and a woken site always gets a task.
- **Termination and Ctrl+C.** A loop's live count includes parked tasks and
  queued sites; it exits only when both are zero and its spacing timers have
  fired. Ctrl+C cancels queued sites (they are still recorded, with
  `robots_error: "aborted"`) and parked tasks; the e2e test stops a run with
  ~290 hosts queued on one IP and it ends in under a second.

## Records and counters

New record keys, appended after `ms` (`docs/study-method.md` has the rest):

| key | meaning |
|---|---|
| `skip` | why politeness skipped the host or its page: `ip_budget` (over the IP's host budget; `ip_dup` true), `ip_unreachable` (its IP failed `--ip-fail-limit` times in a row), `crawl_delay` (Crawl-delay above `--max-crawl-delay`); null otherwise |
| `wait_ms` | time the site waited on politeness: IP queue and spacing, Crawl-delay, Retry-After |
| `crawl_delay` | Crawl-delay (seconds) in the seed origin's robots.txt, null if none |
| `crawl_delay_ms` | the part of `wait_ms` spent waiting for a Crawl-delay |
| `retry_after` | Retry-After (seconds) of the first 429/503 that carried one |
| `retried` | that Retry-After was waited out and the request repeated |

Redirect hops can also end with `fetch: "ip_busy"` or `"ip_unreachable"`.

`--json` keeps every existing key and appends, before `peak_inflight`:
`ip_extra_hosts`, `ip_budget_skips`, `ip_unreachable`, `ip_busy`,
`cdn_hosts`, `polite_waits`, `polite_wait_ms`, `crawl_delay_waits`,
`crawl_delay_ms`, `crawl_delay_skips`, `throttled`, `retry_after_retries`.
The `I` column still counts unique IPs (the first host of each); hosts
fetched beyond the first per IP are `ip_extra_hosts`. The summary gains two
lines, and the periodic rate line shows how many sites wait on politeness.
`peak_inflight` now includes waiting sites, which hold no socket.

## Analysis: IP weighting

With a host budget, hosts on big IPs are a sample. `tools/study/analyze.py`
weights each fetched host by its IP's resolving hosts / fetched hosts
(inverse-probability weighting, computed from the records themselves) and
reports every HTTP/TLS fact unweighted and weighted, with a Wilson interval on
the Kish effective sample size. It also reports coverage (fetched / resolving
hosts) overall, on Cloudflare IPs and elsewhere, and a politeness summary.

Applied to the published one-host-per-IP study it shows why the rerun is
needed: weighting one host per IP up to 27,391 hosts leaves an effective
sample of only ~100–220 hosts per fact (e.g. PQ hybrid of TLS 1.3 handshakes
56.5% unweighted, 64.5% [56.9–71.4] weighted, n_eff 162).

## Verification

- `crawl_tests`: `IpGates` budget, cap, spacing, early timers, priority order,
  restart spacing, back-off, CDN class, breaker, cancel, a woken start
  blocking the next until it connects, 8 threads × 2,000 sites never exceeding
  a cap of 3; HTTP-date (all three RFC 9110 forms) and Retry-After parsing.
- `crawl_polite_tests` (engine against the benchsrv rig, deterministic, ~10 s):
  2,000 hosts on 5 IPs under load (each ordinary IP exactly at its cap of 2,
  the CDN-range IP above it and within its own cap of 32), spacing between
  connection starts ≥ interval − 16 ms with the two IPs in parallel, the host
  budget, Crawl-delay honoured with 2 task slots for 8 delayed sites, a
  Crawl-delay above the cap, 429 + Retry-After within and above the cap, the
  unreachable-IP breaker, and a 300-host IP that neither starves 50 other
  hosts nor delays Ctrl+C.
- benchsrv tracking counts a connection from its accept to the last response
  sent on it. Counting until the server processed the client's reset raced
  with the next accept on another thread and occasionally reported 3 at a cap
  of 2; the server-side events used now both precede the client's close.

## Measurements

Ryzen 7 9700X, release builds, shared machine (another agent was building and
testing), rig `wincrawl-benchd serve --dns 127.0.0.1:45300 --http 0.0.0.0:48080 -t 4`
(lan), 200,000 URLs (179,960 hosts, 161,949 resolving), `-c 2000`, classic.

| run | elapsed s | process CPU s | notes |
|---|---|---|---|
| master `1ea6a06`, defaults | 18.62 / 19.24 / 19.23 | 114.7 / 119.0 / 116.6 | 129,488 unique IPs |
| this branch, defaults (`--hosts-per-ip 1`) | 18.93 / 18.92 / 19.41 | 116.2 / 118.0 / 120.4 | identical DNS ok / unique IPs; 32,461 budget skips; 0 politeness waits |
| `--hosts-per-ip 0`, default politeness | 22.41 / 22.65 | 130.1 / 131.0 | all 161,949 hosts; 32,461 waits, 343 ms average |
| `--hosts-per-ip 0 --ip-concurrency 0 --ip-interval 0` | 20.01 / 20.42 | 130.7 / 133.4 | only the 429/503 back-off left |

No regression at the default (runs alternated master/branch; the difference
is inside the spread). Politeness costs ~11% on the rig while every shared-IP
host waits, because the waits hold no slots.

Stress world: `serve --ip-pool 2000 --track` puts the 161,949 resolving hosts
on 2,000 IPs (~81 each); `--hosts-per-ip 0`, defaults: 37.8 s, peak 142,854
sites in flight (almost all queued waiters). The server saw at most 1
connection open at once per IP and a shortest gap of 227.4 ms between two
connection starts to one IP (210.5 ms before spacing counted from the real
connect). The remaining shortfall is consistent with the server's accept
timestamps, which the single acceptor thread stamps when it processes a
batch of completions on a saturated machine; the e2e tests at normal load
measure ≥ interval − 16 ms.

Live check, 2026-11-22, home connection, 1.1.1.1/1.0.0.1: the study's
validation sample (2,000 URLs, `random.Random(463).sample`), real mode,
`--hosts-per-ip 0 -c 2000 --record --https-rr`, defaults otherwise: 44.6 s,
1,921 records, 1,076 of 1,082 resolving hosts fetched (99.45%; the other 6 on
an IP that refused 5 times), 221 hosts beyond the first per IP, the largest
IP 73 hosts, 517 politeness waits, 45 Crawl-delay waits (339 s in total), one
page skipped for a Crawl-delay above 30 s, 12 429/503 replies. Median wait
per fetched host 0 ms, p90 2.9 s, max 41 s.

## Recommended settings for the full study

`tools/study/estimate.py` models a rerun from the published records: each
IP fetches min(resolving hosts, budget) hosts and drains at min(2 / site time,
1 / (connections per site × 250 ms)) sites per second; refused or timed-out
IPs stop after 5 failures; the rest is bound by the uplink (fixed 160 s plus
2.3 ms per fetched site, calibrated on the published classic and real runs).
Site times 1.2 s (http) and 1.8 s (https) are from the live check, where the
73-host IP finished inside 44.6 s.

| `--hosts-per-ip` | fetched hosts | coverage | CF | non-CF | slowest IP | est. wall |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 113,963 | 27.3% | 31.9% | 26.5% | 5 s | 7.4 min (published: 7.0) |
| 500 | 322,790 | 77.4% | 99.9% | 73.4% | 450 s | 15.4 min |
| 1,000 | 331,167 | 79.4% | 99.9% | 75.8% | 900 s | 15.7 min |
| 2,000 | 341,280 | 81.9% | 99.9% | 78.6% | 1,800 s | 30.3 min |
| 3,000 | 346,925 | 83.2% | 99.9% | 80.2% | 2,700 s | 45.3 min |
| unlimited | 375,131 | 90.0% | 99.9% | 88.2% | 16,435 s | 4.6 h |

Coverage tops out near 90% because hosts on IPs that refuse or time out are
skipped after 5 failures (they are dead at the HTTP level; the attempted ones
represent them in the weighting). With pessimistic site times (2.2 s / 2.8 s,
the live medians before subtracting DNS) the 2,000 budget estimates 47 min and
1,000 estimates 24 min. The slowest IPs at 2,000 are two parking IPs whose
hosts redirect to hugedomains.com over TLS and two Asian hosting IPs; they
are bound by 2 connections, not by the spacing.

Recommended for the 1M rerun (~30 min estimated, 341K of 417K resolving hosts,
every Cloudflare host, never more than 2 connections or 4 starts/s per non-CDN IP):

```powershell
build\release\wincrawl.exe --mode real --hosts-per-ip 2000 --record study.jsonl --https-rr --json study.json sample_urls\URL-input-1M.txt
python tools\study\analyze.py study.jsonl --seeds 1000000 > report.md
```

If the run must stay well under 45 minutes, `--hosts-per-ip 1000` costs 2.5
points of coverage and estimates 16–24 minutes.
