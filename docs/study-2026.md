# The 2015 web in 2026: what a 1M-URL seed list looks like now

The CSCE 463 seed list (`sample_urls/URL-input-1M.txt`, 1,000,000 `http://`
URLs, 824,981 unique hosts) dates from around 2015. I crawled it twice in
November 2026 with wincrawl in real mode and recorded what each host does
today: DNS, TLS, post-quantum key exchange, HTTP/3 and ECH advertisement,
HSTS, and whether it sits behind Cloudflare.

| | Run 1 (2026-11-21) | Run 2 (2026-11-22) |
|---|---|---|
| Hosts fetched | first host on each IP (the assignment's IP dedupe): 113,963 | up to 2,000 hosts per IP with per-IP politeness: 345,351 (83.9% of resolving hosts, every Cloudflare host) |
| Full report | [`study-2026-report.md`](study-2026-report.md) | [`study-2026-all-hosts-report.md`](study-2026-all-hosts-report.md) |
| Records | [`study-2026-11-21` release](https://github.com/contrafy/win-crawl/releases/tag/study-2026-11-21) | [`study-2026-11-22` release](https://github.com/contrafy/win-crawl/releases/tag/study-2026-11-22) |

Run 2 is the better estimate of what the hosts on this list do; the numbers
below come from it unless marked. Its HTTP and TLS shares are weighted so
every resolving host counts once (see [Method](#method)). The method and
record schema are in [`study-method.md`](study-method.md); the politeness
policy is in [`politeness.md`](politeness.md).

## Headline findings

1. **More than half the 2015 long tail is gone.** 56.5% of hosts are dead:
   - 37.9% NXDOMAIN;
   - 10.6% with no A record;
   - 4.7% resolve but refuse TCP;
   - 3.4% sit on an IP that never answered.

   Of the resolving hosts, 80.1% [76.4–83.4] still answer HTTP.
2. **Post-quantum key exchange is the majority of TLS 1.3.** With a
   ClientHello that offers X25519MLKEM768 first:
   - 66.7% [61.2–71.7] of TLS 1.3 handshakes negotiated it;
   - that is 54.7% [49.1–60.1] of all completed handshakes, ahead of plain
     x25519;
   - TLS 1.3 itself is 82.0% [79.0–84.7] of handshakes.
3. **Cloudflare is most of the modern-protocol story.** 15.9% of resolving
   hosts are behind Cloudflare:

   | | behind Cloudflare | not behind Cloudflare |
   |---|---:|---:|
   | TLS 1.3, of handshakes | 99.5% | 74.0% |
   | PQ hybrid, of TLS 1.3 handshakes | 99.4% | 46.2% |
   | HTTP/3 via Alt-Svc, of https replies | 87.5% | 4.4% |
   | HTTPS DNS record, of resolved hosts | 88.5% | 0.76% |
   | ECH in the HTTPS record, of resolved hosts | 84.7% | 7 hosts of 346,133 |
   | HSTS, of https replies | 29.2% | 30.0% |

   - **ECH in DNS is effectively Cloudflare-only:** 55,333 of the 55,340 ECH
     configs seen belong to Cloudflare-fronted hosts.
   - **HSTS is the one place Cloudflare makes no difference:** it is a
     per-site opt-in.
4. **Old http:// links mostly don't upgrade themselves.** Only 20.6%
   [16.5–25.6] of http seeds that returned a page ended up on https. Where a
   site serves https, 29.1% [26.0–32.5] send HSTS; two-thirds of those use a
   1–2 year max-age and 22% ask for preload.
5. **HTTPS-record queries fail often.** 14.8% of HTTPS (type 65) lookups for
   resolvable hosts came back SERVFAIL from 1.1.1.1. A sample re-checked over
   DoH at Cloudflare and Google failed the same way. This is authoritative-side
   breakage on a record type many old DNS servers mishandle, not a client bug
   ([`dns-notes.md`](dns-notes.md)).
6. **Few sites ask crawlers to slow down.** 1.8% of robots.txt files set a
   `Crawl-delay`; most of those ask for 5–10 s, and 9.5% ask for more than a
   minute. 32% of fetched hosts waited on per-IP politeness at some point.

## One host per IP vs every host

The assignment's IP dedupe makes a cheap sample, but a biased one. Run 1 sees
only the first host on each IP; run 2 weights every host back in:

| fact | run 1: first host per IP | run 2: every host, IP-weighted |
|---|---:|---:|
| PQ hybrid, of TLS 1.3 handshakes | 56.5% [55.9–57.1] | 66.7% [61.2–71.7] |
| TLS 1.3, of completed handshakes | 83.8% | 82.0% [79.0–84.7] |
| Alt-Svc h3, of https replies | 24.2% | 18.8% [16.7–21.1] |
| http seed ends on https | 30.3% | 20.6% [16.5–25.6] |
| HSTS, of https replies | 29.3% | 29.1% [26.0–32.5] |

A likely explanation, which I haven't verified host by host: the first host
on a shared IP is often the IP's "real" site, while the many hosts behind it
are parked or redirected domains on bulk hosting. Those sit on modern TLS
stacks that negotiate PQ, but rarely redirect old http:// URLs to https or
advertise HTTP/3.

Run 1's narrow intervals describe "the first host per IP" precisely; they
don't cover the bias from estimating every host with that sample. Run 2's
intervals are wider because hosts on one IP share a server configuration, so
the IP, not the host, is the sampling unit.

## Funnel (run 2)

| stage | count | of previous |
|---|---:|---:|
| seed URLs | 1,000,000 | |
| unique hosts with a record | 820,097 | 82.0% |
| DNS ok | 411,458 | 50.2% |
| fetched (within the per-IP host budget) | 345,351 | 83.9% |
| robots.txt allowed the page | 242,664 | 70.3% |
| page reply received | 233,093 | 96.1% |
| final reply 2xx | 141,553 | 60.7% |

Server software among hosts that answered: nginx 36.1%, Cloudflare 21.9%,
Apache 11.0%, OpenResty 6.6%, Microsoft-IIS 5.6%.

## The runs

| | Run 1 | Run 2 |
|---|---|---|
| Command | `wincrawl --mode real --record study.jsonl --https-rr` | same plus `--hosts-per-ip 2000` |
| Build | `bcc53af` | `84388a1` |
| Politeness | one host per IP | 2 connections and 250 ms between starts per IP; 10 s max 429/503 back-off; Cloudflare IPs 16 connections, no spacing; Crawl-delay ≤ 30 s and Retry-After ≤ 30 s honoured |
| Settings | 16 loops, `-c 4000`, DNS 1.1.1.1 + 1.0.0.1, 2048 queries in flight | same |
| TLS | Schannel on Windows 11 26200.9974, offering X25519MLKEM768, x25519 and P-256 key shares; offline certificate verification | same, with the full Microsoft root program loaded into the local store |
| Wall time | 422 s | 60 min (stopped, see caveats) |
| Records | 824,981 (430 MB, 25 MB gzipped) | 820,097 (523 MB, 30 MB gzipped) |

## Method

- **Weighting.** Run 2 fetches at most 2,000 hosts per IP, so hosts on
  bigger IPs are sampled. Each fetched host is weighted by (resolving hosts on
  its IP ÷ fetched hosts on its IP), so every resolving host counts once.
  Within an IP the fetched hosts are the first ones in input order, so this is
  model-based weighting, not a random sample. The full report shows weighted
  and unweighted values side by side.
- **Intervals.** 95% Wilson intervals on an effective sample size from the
  cluster-robust variance of the ratio estimator, with the IP as the cluster.
  Counts without an interval are exact.
- **Cloudflare.** Detected by published IPv4 range or `CF-RAY` header. The
  two agree on 98.1% of hosts where both are known.

## Caveats

- **This is the 2015 long tail, not today's popular web.** The list mixes
  big sites with many small ones that have since disappeared. Shares describe
  this list, not the web at large. A Tranco top-list comparison is on the
  [roadmap](roadmap.md).
- **Run 2 did not finish cleanly.**
  - **Where it stood:** by 30 minutes about 98.5% of the work was done. The
    rest was queued behind the handful of IPs with the most hosts, at 2
    connections each.
  - **How it ended:** at 60 minutes the shell driving the run hit its job
    limit and hard-killed the crawler, rather than stopping it with Ctrl+C.
  - **What's missing:** 4,884 hosts (0.6%), the sites still queued or in
    flight plus records still in the writer's buffers. They are almost all on
    the largest shared IPs, which are sampled and weighted anyway.
  - **What's affected:** the funnel's unique-host count (820,097 rather than
    824,981) and the crawler's own JSON summary, which was never written.
  - **The fix:** a `--deadline` option for a graceful stop is on the roadmap.
- **One vantage point, two evenings.** Measured from one residential IPv4
  connection. Bot defenses (403, 429, 444) may treat a crawler differently
  from a browser.
- **HTTP/3 is advertised, not tested.** h3 support comes from Alt-Svc and the
  HTTPS record's alpn; no QUIC connections were made.
- **Certificate verification is offline.** In run 2 the local store held the
  full Microsoft root program; 1.8% of handshakes still failed verification.
  The negotiated TLS parameters were recorded for them anyway.
- **10% of handshakes never finished,** mostly robots.txt fetches that hit
  the 10 s timeout. They are not in the version or group shares.
- **PQ is offered as the first group only by this client.** A server that
  supports X25519MLKEM768 but prefers x25519 when both are offered would show
  as x25519.

## Reproducing

```powershell
cmake --preset release; cmake --build --preset release
build\release\wincrawl.exe --mode real --hosts-per-ip 2000 --record study.jsonl --https-rr --json study.json sample_urls\URL-input-1M.txt
python tools\study\analyze.py study.jsonl --seeds 1000000 --title "1M seeds (2015 list), crawled <date>" > report.md
```

- Post-quantum offers need the machine-wide Schannel setting described in
  [`tls-notes.md`](tls-notes.md); `--no-pq` gives a control run without it.
- Budget at least 60 minutes for the run, or use `--hosts-per-ip 1000`.
