# The 2015 web in 2026: what a 1M-URL seed list looks like now

The CSCE 463 seed list (`sample_urls/URL-input-1M.txt`, 1,000,000 `http://`
URLs, 824,981 unique hosts) dates from around 2015. On 2026-11-21 I crawled
every host once with wincrawl in real mode and recorded what each one does
today: DNS, TLS, post-quantum key exchange, HTTP/3 and ECH advertisement,
HSTS, and whether it sits behind Cloudflare.

The full generated report, with every table and Wilson 95% interval, is in
[`study-2026-report.md`](study-2026-report.md). The method and record schema
are in [`study-method.md`](study-method.md).

## Headline findings

1. **Half the 2015 long tail is gone.** 50.9% of hosts are dead: 37.6%
   NXDOMAIN, 10.4% with no A record, 2.9% resolving but refusing TCP. Of the
   hosts that resolved and were fetched, 76.6% still answered HTTP.
2. **Post-quantum key exchange is already the most common group.** With a
   ClientHello that offers X25519MLKEM768 first, 47.4% of completed TLS
   handshakes negotiated it, ahead of plain x25519 (41.9%). That is 56.5% of
   TLS 1.3 handshakes. TLS 1.3 itself is 83.8% of handshakes.
3. **Cloudflare is most of the modern-protocol story.** 15.3% of resolving
   hosts are behind Cloudflare. For those hosts and everyone else:

   | | behind Cloudflare | not behind Cloudflare |
   |---|---:|---:|
   | TLS 1.3, of handshakes | 98.7% | 78.8% |
   | PQ hybrid, of TLS 1.3 handshakes | 99.1% | 38.3% |
   | HTTP/3 via Alt-Svc, of https replies | 84.0% | 5.7% |
   | HTTPS DNS record, of resolved hosts | 90.0% | 0.82% |
   | ECH in the HTTPS record, of resolved hosts | 86.6% | 8 hosts of 353,171 |

   ECH in DNS is effectively a Cloudflare-only deployment: 55,192 of the
   55,200 ECH configs seen belong to Cloudflare-fronted hosts.
4. **Old http:// links mostly don't upgrade themselves.** Only 30.3% of http
   seeds that returned a page ended up on https. Where a site does serve
   https, 29.3% send HSTS; of those, 72% use a 1–2 year max-age and 20.7%
   ask for preload.
5. **HTTPS-record queries fail often.** 16.0% of HTTPS (type 65) lookups for
   resolvable hosts came back SERVFAIL from 1.1.1.1. A sample re-checked over
   DoH at Cloudflare and Google failed the same way, so this is
   authoritative-side breakage on a record type many old DNS servers
   mishandle, not a client bug ([`dns-notes.md`](dns-notes.md)).
6. **Signals agree.** Cloudflare detection by published IP range and by the
   `CF-RAY` header agreed on 99.69% of hosts where both were known.

## Funnel

| stage | count | of previous |
|---|---:|---:|
| seed URLs | 1,000,000 | |
| unique hosts | 824,981 | 82.5% |
| DNS ok | 416,928 | 50.5% |
| unique IPs (fetched) | 113,963 | 27.3% |
| robots.txt allowed the page | 74,743 | 65.6% |
| page reply received | 72,752 | 97.3% |
| final reply 2xx | 45,409 | 62.4% |

Server software among hosts that answered: nginx 34.5%, Cloudflare 23.0%,
Apache 16.4%, Microsoft-IIS 7.8%, OpenResty 3.9%, LiteSpeed 1.9%. 403 is the
second most common final status (18.4%), well ahead of 404 (8.6%). I did
not classify the 403s, but much of that is probably bot blocking.

## The run

| | |
|---|---|
| Command | `wincrawl --mode real --record study.jsonl --https-rr --json study.json sample_urls\URL-input-1M.txt` |
| Build | `bcc53af`, release |
| Settings | defaults: 16 loops, `-c 4000`, DNS 1.1.1.1 + 1.0.0.1, 2048 queries in flight, 1500 ms × 3 attempts |
| TLS | Schannel on Windows 11 26200.9974, ClientHello offering X25519MLKEM768, x25519, P-256 key shares; certificate verification on, offline |
| Wall time | 422.3 s |
| Traffic | 1.50M DNS queries (A + HTTPS), 4.06 GB received, 33,593 redirects followed |
| Output | 824,981 records (430 MB JSONL; 25 MB gzipped in the [`study-2026-11-21` release](https://github.com/contrafy/win-crawl/releases/tag/study-2026-11-21)); analysis takes 3.5 s |

## Caveats

- **This is the 2015 long tail, not today's popular web.** The list mixes
  big sites with many small ones that have since disappeared. Shares describe
  this list, not the web at large. A Tranco top-list comparison is on the
  [roadmap](roadmap.md).
- **One site per IP at the HTTP level.** The assignment's IP dedupe skips any
  host whose IP was already fetched: 72.6% of resolving hosts, similar for
  Cloudflare (68.1%) and non-Cloudflare (73.5%) hosts. HTTP and TLS facts
  therefore describe the first host on each IP. DNS facts (Cloudflare range,
  HTTPS records, ECH) cover every resolving host.
- **One vantage point, one evening.** Measured from one residential IPv4
  connection. Bot defenses (403, 429, 444) may treat a crawler differently
  from a browser.
- **HTTP/3 is advertised, not tested.** h3 support comes from Alt-Svc and the
  HTTPS record's alpn; no QUIC connections were made.
- **Certificate failures include missing roots.** Verification uses only the
  local root store and never downloads; the machine had not preloaded the
  full Microsoft root program. 2.6% of handshakes failed verification. The
  negotiated TLS parameters were still recorded for them.
- **10% of handshakes never finished,** mostly robots.txt fetches that hit
  the 10 s timeout. They count in the denominator of "sites that reached
  TLS" but not in version or group shares.
- **PQ is offered as the first group only by this client.** A server that
  supports X25519MLKEM768 but prefers x25519 when both are offered would show
  as x25519 here.

## Reproducing

```powershell
cmake --preset release; cmake --build --preset release
build\release\wincrawl.exe --mode real --record study.jsonl --https-rr --json study.json sample_urls\URL-input-1M.txt
python tools\study\analyze.py study.jsonl --seeds 1000000 --title "1M seeds (2015 list), crawled <date>" > report.md
```

Post-quantum offers need the machine-wide Schannel setting described in
[`tls-notes.md`](tls-notes.md). `--no-pq` gives a control run without it.
