# Roadmap

What comes next, in priority order. Each item names the evidence behind it.
Finished work is described in the README and the other notes in `docs/`.

## Done

- **Politeness, so studies cover every host.** `--hosts-per-ip`, per-IP
  connection caps and spacing shared across loops, 429/503 back-off with
  `Retry-After`, `Crawl-delay`, CDN-aware limits, and an IP-weighted analyzer
  ([`politeness.md`](politeness.md)). The rerun of the 1M study is in
  [`study-2026.md`](study-2026.md).
- **Web Bot Auth.** RFC 9421 Ed25519 signatures on every request, the
  `wincrawl-botauth` key tool and the directory Worker
  ([`web-bot-auth.md`](web-bot-auth.md)). What remains is for the owner:
  deploy the Worker and register the key with Cloudflare's Bot Submission
  Form, which turns production's 401 "unknown public key" into verified-bot
  status.

## 1. Web Bot Auth follow-ups

- **Deploy the key directory and register it** (steps in
  `tools/bot-auth-directory/README.md`).
- **Switch to dictionary-form `Signature-Agent`** once Cloudflare's verifier
  accepts it; the IETF draft already requires it, and the signer supports it.
- **Cover more components** (`@path`, `@method`) if the draft adds them. This
  narrows replay to the same request.

## 2. Profile-guided CPU wins (measured, not yet applied)

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

## 3. A Linux backend

Cloudflare-scale networking runs on Linux. Two options:

- **io_uring behind `wc::net`:** the completion contract was designed to be
  backend-neutral apart from `OVERLAPPED` in `IoRequest`. Run the same
  benchmark rig on IOCP, io_uring and epoll on one machine, then write it up.
- **A Rust port of the engine:** the stronger signal for Rust-heavy teams, but
  a much bigger job. Pairs naturally with
  [quiche](https://github.com/cloudflare/quiche) for HTTP/3.

Pick one, not both.

## 4. Protocols

- **HTTP/3 over QUIC:** today h3 support is inferred from Alt-Svc and HTTPS
  RRs. Actually connecting (msquic on Windows, quiche elsewhere) would measure
  real h3 success rates and handshake times.
- **HTTP/2** with ALPN, for multiplexing robots and page.
- **IPv6** (AAAA, happy eyeballs): currently IPv4 only.
- **DNS over TCP** for truncated replies, Extended DNS Errors, and DoH/DoT to
  the configured resolvers.

## 5. Study follow-ups

- **`--deadline`:** stop intake and drain at a wall-clock limit through the
  Ctrl+C path, so every host gets a record. The no-dedupe run was hard-killed
  at 60 minutes with 0.6% of hosts unrecorded
  ([`politeness.md`](politeness.md)).
- **Calibrate `estimate.py` per IP class.** It predicted 30 minutes. 98.5% of
  the work was done by then, but the biggest parking and bulk-hosting IPs
  drain at about 1 site/s, not the modelled 2 per 1.8 s.
- **Repeat runs** to report change over time (PQ and ECH adoption move monthly).
- **Distinguish failure causes** for certificate failures: expired vs name
  mismatch vs untrusted. The full root set is loaded now, so what remains
  should be real.
- **Compare against the Tranco top list**, so findings about long-tail 2015
  sites can be set against today's popular sites.
- **Test whether the hosts behind a shared IP really are parked or bulk
  hosting.** That is the likely explanation for the run 1 vs run 2 gap.

## 6. Crawl the frontier

wincrawl counts links but never follows them. An IRLbot-style frontier
([Lee et al., WWW 2008](https://irl.cse.tamu.edu/people/hsin-tsang/papers/www2008.pdf)):

- disk-backed URL uniqueness (DRUM);
- spam-resistant per-domain budgets (STAR);
- politeness scheduling (BEAST).

These would turn it from a seed-list fetcher into a real crawler. It's the
natural continuation of the course and builds on the per-IP gates
(politeness), which BEAST-style budgets would extend.

## Housekeeping

- `ilammy/msvc-dev-cmd@v1` still runs on Node 20. Replace it with
  `tools/vsdev.cmd` in CI if it isn't updated.
- Add UBSan alongside ASan in the fuzz preset.
- Fuzz the TLS session with a recorded-transcript harness. TLS and sockets are
  the only unfuzzed input surfaces.
