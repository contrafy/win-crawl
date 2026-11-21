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

Connection teardown is chosen so that neither side accumulates TIME_WAIT:

- after a response to a client that asked for close, the server half-closes
  (`shutdown(SD_SEND)` → FIN; the client sees EOF, which close-delimited
  HTTP/1.0 readers such as the legacy crawler need), then waits for the
  client's FIN/RST and resets (`SO_LINGER {1,0}`). The client ends in
  LAST_ACK → CLOSED, the server never enters TIME_WAIT.
- a keep-alive client that closes (FIN or RST) is reset as well; idle
  connections (`--idle-timeout-ms`, default 30 s) and shutdown are resets.
- `--graceful-close` switches the first case to a plain close for comparison
  (TIME_WAIT then lands on the server, one entry per connection for 2 MSL).

## Running

```powershell
cmake --preset release; cmake --build --preset release

# servers until Ctrl+C (prints req/s, conn/s, Mbit/s, DNS q/s, CPU every 2 s)
build\release\apps\benchd\wincrawl-benchd.exe serve --profile wan
build\release\apps\benchd\wincrawl-benchd.exe gen --count 200000 --out urls.txt
build\release\apps\wincrawl\wincrawl.exe --dns 127.0.0.1:5300 -c 2000 --json out.json urls.txt

# capacity of the server itself
build\release\apps\benchd\wincrawl-benchd.exe load -t 4 -c 256 --duration 10            # keep-alive
build\release\apps\benchd\wincrawl-benchd.exe load -t 4 -c 256 --duration 10 --close    # new connection per request

# the whole sweep
bench\run-local.ps1 -Wincrawl build\release\apps\wincrawl\wincrawl.exe -Profile lan -Concurrency 500,2000,8000
bench\run-local.ps1 -Legacy build\release\wincrawl_legacy.exe -LegacyCount 20000 -LegacyThreads 500,2000 -Profile wan
```

`run-local.ps1` parameters: `-Wincrawl`, `-Legacy`, `-Benchd` (default
`build\release\apps\benchd\wincrawl-benchd.exe`), `-Profile lan|wan`, `-Count`
(200000), `-LegacyCount`, `-Concurrency`, `-LegacyThreads`, `-Threads`
(wincrawl `-t`), `-ServerThreads` (4), `-HttpPort` (8080), `-DnsPort` (5300),
`-ServeArgs`/`-CrawlArgs` (extra options), `-RunTimeoutSec`. It refuses to start
when the ports are taken and always stops benchd on exit. Logs, JSON and the URL
files of a run sit in `bench/results/local/<timestamp>/`.

### Profiles

| profile | DNS delay | HTTP delay | models |
|---|---|---|---|
| `lan` | 0 | 0 | pure CPU / syscall cost of the crawler |
| `wan` | 30 ± 10 ms | 80 ± 40 ms per request | resolver RTT and origin latency; concurrency has to hide it |

Explicit `--dns-delay-ms` / `--http-delay-ms` after `--profile` (or via
`-ServeArgs`) override the profile.

### Reading results

The wincrawl table comes from its `--json` (schema in the top-level README);
URLs/s and pages/s are over the whole run. Expected shape for the defaults: DNS
ok ≈ 90% of unique hosts, unique IPs ≈ 80% of those, robots 4xx ≈ 60% of
attempts, pages: ≈ 88% 2xx / 5% 3xx / 5% 4xx / 2% 5xx, links = 30 × 2xx pages.
Deviations from these ratios are crawler bugs (or a changed seed), not noise.
"crawler CPU s" / "server CPU s" are process CPU seconds during the run; at
equal throughput lower is better. TIME_WAIT counts sockets on the HTTP port
right after the run (should stay near 0; see below).

## Measured on the dev box

Ryzen 7 9700X (8C/16T), Windows 11, release build.

RESULTS_PLACEHOLDER

## Windows tuning notes

TUNING_PLACEHOLDER
