# Benchmark rig

The rig measures crawler throughput on one Windows machine without touching the
internet: `wincrawl-benchd` plays every DNS server and web server the crawler
talks to, over loopback, with a deterministic synthetic "internet". Same
options, same world, same counters — so runs are comparable and regressions
show up as numbers, not anecdotes.

```
wincrawl --dns 127.0.0.1:5300  ──UDP──►  benchd DNS   h<N>.bench.test → 127.x.y.z
         http://h<N>.bench.test:8080/…  ──TCP──►  benchd HTTP 0.0.0.0:8080 (keyed by Host / local IP)
```

## Pieces

| | |
|---|---|
| `src/benchsrv/` (`wc_benchsrv`) | `DnsServer`, `HttpServer`, the `Behavior` model and the URL generator, embeddable in tests |
| `apps/benchd/` (`wincrawl-benchd`) | `serve`, `gen`, `load` subcommands |
| `bench/run-local.ps1` | starts benchd, generates inputs, sweeps the crawler(s), writes `bench/results/local/<timestamp>.md` (gitignored) |

### The synthetic world (`Behavior`)

Every decision is a hash of `(seed, host number N[, path])`, never a random
draw, so a host always behaves the same way:

- **DNS** (`DnsServer`, UDP, own minimal codec — deliberately independent of
  `wc_dns` so it is an oracle): `h<N>.<zone>` A → `127.0.0.0/8 + N + 1`
  (`h0` → 127.0.0.1). `--ip-share` of hosts reuse the address of the nearest
  earlier resolving host (exercises IP dedupe); `--nxdomain` of hosts get
  NXDOMAIN; other names in the zone → NXDOMAIN, other types → NODATA, names
  outside the zone → REFUSED, malformed → FORMERR/NOTIMP. Optional reply delay
  `--dns-delay-ms mean[,jitter]` (uniform, per name, loop timers). The question
  is echoed verbatim, so 0x20 case randomisation works.
- **HTTP** (`HttpServer`): host number from the `Host` header (`h<N>.zone[:port]`
  or an IP literal `127.a.b.c`) or, without one, from the local address the
  client connected to. `/robots.txt` → 404 for `--robots-404` of hosts, else 200
  with a small robots.txt. `/p/…` pages → 200 `text/html` (8 pre-built
  templates averaging `--page-kb`, each with exactly `--links` links in six
  syntactic shapes: absolute, protocol-relative, root-relative, relative,
  single-quoted with `&amp;`, uppercase `<A HREF>`, `<area>`), or 301 → `/r/1`,
  404, 503 by `--redirect`/`--not-found`/`--server-error`; `--chunked` of 200
  pages use chunked encoding. `/r/…` is always 200 so redirects terminate.
  Optional per-request delay `--http-delay-ms mean[,jitter]`.
- **Inputs** (`gen`): `http://h<N>.bench.test:8080/p/<k>` with `--dup-hosts`
  of lines repeating an earlier host, or `--ip-literal` for
  `http://127.a.b.c:8080/p/<k>` (needs no DNS; used for the legacy crawler,
  which can only use system DNS).

Defaults: ip-share 0.2, nxdomain 0.1, robots-404 0.6, page 32 KB, 30 links,
3xx 0.05, 404 0.05, 5xx 0.02, chunked 0.1, dup-hosts 0.1.

### Server design

All responses (every status × keep-alive/close × plain/chunked) are formatted
once at start; serving a request is parsing the head plus one `WSASend` of a
shared immutable buffer (HEAD sends its header prefix). One acceptor loop
(AcceptEx, backlog `SOMAXCONN_HINT(16384)`) hands sockets round-robin to `-t`
worker loops. HTTP/1.1 keep-alive and pipelining, HTTP/1.0 close unless
`Connection: keep-alive`.

Connection teardown:

- a client that closes or resets a keep-alive connection is answered with an
  abortive close (`SO_LINGER {1,0}` → RST). The client goes FIN_WAIT_2 →
  CLOSED and nobody keeps a TIME_WAIT entry. Idle connections
  (`--idle-timeout-ms`, default 30 s) and shutdown are resets too.
- a response to a client that asked for close (`Connection: close`, HTTP/1.0)
  is followed by a normal close: close-delimited readers such as the legacy
  crawler need the FIN. The server is then the active closer and keeps one
  TIME_WAIT entry per connection for 2 MSL (120 s on Windows). Clients that
  read by length and reset first avoid it; EOF readers cannot (see the
  tuning notes for why and what it costs).

## Running

```powershell
cmake --preset release; cmake --build --preset release

# servers until Ctrl+C (prints req/s, conn/s, Mbit/s, DNS q/s, CPU every 2 s)
build\release\apps\benchd\wincrawl-benchd.exe serve --profile wan
build\release\apps\benchd\wincrawl-benchd.exe gen --count 200000 --out urls.txt
build\release\wincrawl.exe --dns 127.0.0.1:5300 -c 2000 --json out.json urls.txt

# capacity of the server itself
build\release\apps\benchd\wincrawl-benchd.exe load -t 4 -c 256 --duration 10            # keep-alive
build\release\apps\benchd\wincrawl-benchd.exe load -t 4 -c 256 --duration 10 --close    # new connection per request

# the whole sweep
bench\run-local.ps1 -Wincrawl build\release\wincrawl.exe -Profile lan -Concurrency 500,2000,8000

# the original crawler, built from the `legacy-threaded` tag (its sources left master at the
# cutover; at that tag the target is still called `wincrawl`)
git worktree add --detach ..\wc-legacy legacy-threaded
pushd ..\wc-legacy; cmake --preset release; cmake --build --preset release; popd
bench\run-local.ps1 -Legacy ..\wc-legacy\build\release\wincrawl.exe -LegacyCount 20000 -LegacyThreads 500,2000 -Profile wan
```

`run-local.ps1` parameters: `-Wincrawl`, `-Legacy`, `-Benchd` (default
`build\release\apps\benchd\wincrawl-benchd.exe`), `-Profile lan|wan`, `-Count`
(200000), `-LegacyCount`, `-Concurrency`, `-LegacyThreads`, `-Threads`
(wincrawl `-t`), `-ServerThreads` (4), `-HttpPort` (8080), `-DnsPort` (5300),
`-ServeArgs`/`-CrawlArgs` (extra options), `-RunTimeoutSec`, `-SettleSec` (150:
before each run wait until fewer than 1000 TIME_WAIT sockets remain on the HTTP
port). It refuses to start when the ports are taken and always stops benchd on
exit. Logs, JSON and the URL files of a run sit in
`bench/results/local/<timestamp>/`. Use non-default ports (`-HttpPort 18080
-DnsPort 15300`) when something else on the box may be using the rig defaults.

### Profiles

| profile | DNS delay | HTTP delay | models |
|---|---|---|---|
| `lan` | 0 | 0 | pure CPU / syscall cost of the crawler |
| `wan` | 30 ± 10 ms | 80 ± 40 ms per request | resolver RTT and origin latency; concurrency has to hide it |

Explicit `--dns-delay-ms` / `--http-delay-ms` (via `-ServeArgs`) override the
profile. Delays are quantised to the system timer tick (~15.6 ms): `wc::net`
timers run on `GetTickCount64`.

### Reading results

The wincrawl table comes from its `--json` (schema in the top-level README);
URLs/s and pages/s are over the whole run. Expected shape for the defaults: DNS
ok ≈ 90% of unique hosts, unique IPs ≈ 80% of those, robots 4xx ≈ 60% of
attempts, pages: ≈ 88% 2xx / 5% 3xx / 5% 4xx / 2% 5xx, links = 30 × 2xx pages.
Deviations from these ratios are crawler bugs (or a changed seed), not noise.
Small run-to-run differences in robots/pages counts are expected: which of the
hosts sharing an IP wins IP dedupe depends on DNS completion order, and the
winner's robots/page behaviour is per host. "crawler CPU s" / "server CPU s"
are process CPU seconds during the run; at equal throughput lower is better.
TIME_WAIT counts sockets on the HTTP port right after the run (0 for
keep-alive crawlers; one per connection for close-per-request ones).

## Measured on the dev box

Ryzen 7 9700X (8C/16T), Windows 11, release build.

**Server capacity** (`wincrawl-benchd serve -t 4` + `load` on the same box;
CPU in % of one logical CPU):

| workload | throughput | server CPU | client CPU |
|---|---|---|---|
| keep-alive `GET /robots.txt`, 256 conns | ≈258K req/s | ≈380% | — |
| keep-alive `GET /p/1` (32 KB pages), 256 conns | ≈194K req/s, ≈44 Gbit/s | ≈330% | — |
| new connection per request (`--close`), 256–512 conns | ≈6.8–8.2K req/s | ≈90% (acceptor ≈30%) | ≈390% (kernel) |
| DNS A queries, 4×32 in flight | ≈114K answers/s (≈150K/s from one client) | ≈100% (one loop) | — |

The connection-per-request ceiling is Windows loopback connection setup (see
tuning notes), not the server.

**Crawlers** (`run-local.ps1`, defaults: 200K URLs / 179,960 hosts for
`wincrawl`, 20K URLs / 18,012 hosts for the legacy crawler; `-t 4` server).
wincrawl at `master` after the cutover (classic mode, keep-alive):

| profile | -c | elapsed s | URLs/s | pages ok/s | crawler CPU s | server CPU s | TIME_WAIT |
|---|---:|---:|---:|---:|---:|---:|---:|
| lan | 500 | 18.5 | 10,821 | 4,192 | 117 | 32 | 0 |
| lan | 2000 | 18.9 | 10,601 | 4,115 | 117 | 32 | 0 |
| lan | 8000 | 18.7 | 10,686 | 4,145 | 112 | 32 | 0 |
| wan | 500 | 51.0 | 3,922 | 1,523 | 108 | 30 | 0 |
| wan | 2000 | 22.5 | 8,905 | 3,456 | 107 | 28 | 0 |
| wan | 8000 | 21.7 | 9,219 | 3,579 | 115 | 27 | 0 |

Every run had the expected shape: DNS ok 161,949 / fail 18,011, 129,488 unique
IPs, ≈60% robots 4xx, ≈88/5/5/2% page statuses, exactly 30 links per 2xx page,
no timeouts or connect failures. In lan the crawler opens ≈7K connections/s,
i.e. it sits at the loopback connection ceiling regardless of `-c`.

Legacy baseline (`legacy-threaded`, thread per URL, IP-literal URLs):

| profile | threads | URLs | elapsed s | URLs/s | pages/s | crawler CPU s | TIME_WAIT after |
|---|---:|---:|---:|---:|---:|---:|---:|
| lan | 500 | 20K | 2.3–2.5 | 8,000–8,900 | 4,400–4,800 | 20–23 | 28,913 |
| lan | 2000 | 20K | 2.0–2.7 | 7,500–10,000 | 4,100–5,500 | 14–24 | 28,911 |
| wan | 500 | 20K | 5.5 | 3,667 | 1,999 | 20 | 28,913 |
| wan | 2000 | 20K | 2.9 | 6,994 | 3,812 | 25 | 28,914 |
| lan | 500 | 200K | 150.6 | 1,328 | 716 | 1,348 | 160,186 |
| lan | 2000 | 200K | 161.0 | 1,242 | 670 | 1,593 | 147,861 |
| lan | 5000 | 200K | 166.3 | 1,203 | 649 | 1,542 | 148,513 |

Short legacy runs look fast because they finish before TIME_WAIT pressure
builds; at 200K URLs the server-side TIME_WAIT entries (two connections per
crawled host) collapse its connect rate (tuning notes). Its course HTML
parser counts 25 of the 30 links per page (239,425 links for 9,577 pages).

## Windows tuning notes

Findings from building and running the rig on Windows 11 (none of these
settings were changed on the dev box; the admin-only ones are suggestions).

- **UDP 5353 is taken.** It is mDNS: Chrome and the DNS Client service hold
  `0.0.0.0:5353`, so binding `127.0.0.1:5353` fails with WSAEACCES (10013).
  UDP 53 is held by svchost (ICS/SharedAccess). The rig uses `127.0.0.1:5300`.
- **Listen backlog.** Plain `SOMAXCONN` gives a backlog of ~200 on Windows;
  crawler connect bursts overflow it. The server listens with
  `SOMAXCONN_HINT(16384)` and keeps 256 AcceptEx calls posted.
- **Loopback connection setup is the ceiling, not the server.** A new TCP
  connection costs ~0.2 ms wall per blocking `connect` (≈5K/s per thread) and
  ~0.4–0.5 ms of client *kernel* CPU through IOCP/ConnectEx; machine-wide the
  box tops out at ≈7–9K new loopback connections/s no matter how many client
  threads or processes (2 threads 3.7K/s, 8 threads 6.9K/s, 3 processes 6.5K/s
  combined). Connecting to many different `127.x.y.z` destinations costs ~30%
  more per connect than to `127.0.0.1` alone (per-destination path state). The
  server side of the same connections used ~0.1 ms CPU each (acceptor thread
  ~30% of a core at 8K conn/s). So any crawler pipeline that needs one TCP
  connection per URL is capped near 7K URLs/s on loopback; keep-alive is what
  makes the server fast (≈258K req/s on one connection per client vs ≈7K/s
  with a connection per request).
- **TIME_WAIT is 120 s and on loopback it eats client ports.** Whoever closes
  first keeps the TIME_WAIT entry. Close-delimited clients (HTTP/1.0, the
  legacy crawler) read until EOF, so the server must send the FIN and owns
  one TIME_WAIT per connection. That cannot be avoided from user mode:
  an RST that is not preceded by a FIN discards the client's unread data
  (it gets WSAECONNRESET and 0 bytes), and on Windows `SO_LINGER {1,0}` +
  `closesocket` (or `shutdown(SD_BOTH)`) after `shutdown(SD_SEND)` sends no
  RST at all — the orphaned connection still goes FIN_WAIT_2 → TIME_WAIT.
  On loopback the server-side entries (`127.x.y.z:8080 ↔ 127.0.0.1:P`) still
  pin the client's ephemeral port P, so with only 16,384 dynamic ports
  (49152–65535, the default) a close-per-request client degrades as entries
  pile up: the legacy crawler started at ≈9.6K connections/s and was down to
  ≈0.9K/s within a minute (200K URLs: 1.2–1.3K URLs/s overall vs 8–10K URLs/s
  for a 20K-URL run), with most of its ~9 cores of CPU spent in the kernel.
  It also starves unrelated programs of ports (other test suites failed with
  WSAENOBUFS meanwhile). Clients that know the response length and reset
  (`wc::net`'s default close) and keep-alive clients leave no TIME_WAIT at all
  (100K+ load-generator connections → ~0 entries); the server also resets
  keep-alive connections the client closes, so the client does not keep one
  either.
- **Cool-down.** After a close-per-request run, TIME_WAIT on the HTTP port
  drains in 120 s (observed: 28.9K entries → 25 after ~150 s). `run-local.ps1`
  waits for it (`-SettleSec`) before each run; keep legacy runs to ~20–30K
  URLs (≈30–50K connections) so they stay below the port budget. With admin
  rights, `netsh int ipv4 set dynamicport tcp start=10000 num=55535` (more
  ports) and `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpTimedWaitDelay`
  = 30 (REG_DWORD seconds; reboot) shrink the problem.
- **Counting TIME_WAIT.** `Get-NetTCPConnection -State TimeWait` takes minutes
  with 10^5 entries; `netstat -an -p TCP` takes under a second.
- **Ephemeral ports and `SO_REUSE_UNICASTPORT`.** An explicit `bind(0)`
  reserves a unique port for the socket's lifetime; `SO_REUSE_UNICASTPORT` is
  inert unless an administrator configured an auto-reuse port range. Keep
  concurrent outbound connections well under ~16K minus whatever else holds
  ports (the `-c 8000` runs above were fine).
- **Firewall / Defender.** Firewall profiles are at their defaults and
  Defender real-time protection is on (Network Protection off). Neither
  needed an exclusion: loopback traffic is not filtered, the hot paths do no
  file I/O, and listening on `0.0.0.0:8080` works even if the first-run
  firewall prompt is dismissed. Listening on `0.0.0.0` (not `127.0.0.1`) is
  what lets clients reach every `127.x.y.z` the DNS hands out.
- **Loopback fast path** (`SIO_LOOPBACK_FAST_PATH`) is deprecated since
  Windows 10 1607 and was not used.
- **Timer granularity.** Injected delays are multiples of the ~15.6 ms system
  tick (see Profiles), so short delays are coarse; means of 30 ms and up are
  still representative.
