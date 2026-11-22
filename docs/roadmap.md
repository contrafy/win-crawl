# Roadmap

What comes next, in priority order. Each item names the evidence behind it.
Finished work is described in the README and the other notes in `docs/`.

## 1. Crawl politely enough to drop IP dedupe

The study's page-level numbers (TLS, HTTP/3, HSTS) describe "the first site
on each IP": the assignment's IP dedupe skipped 72.6% of resolving hosts in
the 1M study (CDNs, shared hosting). Dropping the dedupe is only acceptable
with per-target
politeness:

- per-IP and per-host connection caps and request-rate budgets, a small
  per-loop token bucket keyed by IP;
- `Crawl-delay` honoured (already parsed by `RobotsRules`);
- backoff on 429/503 and `Retry-After`.

Then add `--no-ip-dedupe` for measurement runs and rerun the study over every
resolving host.

## 2. Web Bot Auth

Sign requests per Cloudflare's
[Web Bot Auth](https://blog.cloudflare.com/web-bot-auth) draft
([draft-ietf-webbotauth-httpsig-protocol](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol)):

- RFC 9421 HTTP Message Signatures with an Ed25519 key, plus the
  `Signature-Agent` header;
- a key directory served from a domain I control.

Open question: whether Windows CNG supports Ed25519. If it doesn't, vendor a
small audited implementation.

## 3. Profile-guided CPU wins (measured, not yet applied)

From [`profiling.md`](profiling.md):

| Change | Expected gain | Notes |
|---|---|---|
| Connected UDP sockets for DNS: one per server per loop | ~15% crawler CPU on the rig | handle or disable `WSAECONNRESET` (`SIO_UDP_CONNRESET`) |
| Verify each certificate chain once instead of twice | up to ~17% real-mode CPU | offline-only verification must hold |
| Drop the extra NIST-curve key share | ~5–6% real-mode CPU | costs a HelloRetryRequest on P-256-only servers; changes what the study observes |
| Cheaper `bind`/`closesocket` | ≤5% rig, ≤9% real | check whether the widened port range makes `bind` slower |

None of these raise throughput. That is bound by the network on the internet
and by kernel connection setup on loopback. They lower CPU per URL, which
matters once more work (HTTP/2, rendering hints, content hashing) moves into
the loop.

## 4. A Linux backend

Cloudflare-scale networking runs on Linux. Two options:

- **io_uring behind `wc::net`:** the completion contract was designed to be
  backend-neutral apart from `OVERLAPPED` in `IoRequest`. Run the same
  benchmark rig on IOCP, io_uring and epoll on one machine, then write it up.
- **A Rust port of the engine:** the stronger signal for Rust-heavy teams, but
  a much bigger job. Pairs naturally with
  [quiche](https://github.com/cloudflare/quiche) for HTTP/3.

Pick one, not both.

## 5. Protocols

- **HTTP/3 over QUIC:** today h3 support is inferred from Alt-Svc and HTTPS
  RRs. Actually connecting (msquic on Windows, quiche elsewhere) would measure
  real h3 success rates and handshake times.
- **HTTP/2** with ALPN, for multiplexing robots and page.
- **IPv6** (AAAA, happy eyeballs): currently IPv4 only.
- **DNS over TCP** for truncated replies, Extended DNS Errors, and DoH/DoT to
  the configured resolvers.

## 6. Study follow-ups

- **Repeat runs** to report change over time (PQ and ECH adoption move monthly).
- **Distinguish failure causes** for certificate failures: missing local roots
  vs expired vs name mismatch. Load the full Windows Update root set before the
  run.
- **Compare against the Tranco top list**, so findings about long-tail 2015
  sites can be set against today's popular sites.

## 7. Crawl the frontier

wincrawl counts links but never follows them. An IRLbot-style frontier
([Lee et al., WWW 2008](https://irl.cse.tamu.edu/people/hsin-tsang/papers/www2008.pdf)):

- disk-backed URL uniqueness (DRUM);
- spam-resistant per-domain budgets (STAR);
- politeness scheduling (BEAST).

These would turn it from a seed-list fetcher into a real crawler. It's the
natural continuation of the course and builds on item 1.

## Housekeeping

- `ilammy/msvc-dev-cmd@v1` still runs on Node 20. Replace it with
  `tools/vsdev.cmd` in CI if it isn't updated.
- Add UBSan alongside ASan in the fuzz preset.
- Fuzz the TLS session with a recorded-transcript harness. TLS and sockets are
  the only unfuzzed input surfaces.
