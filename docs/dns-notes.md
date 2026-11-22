# DNS notes

How `src/dns/` behaves, what its HTTPS record (RFC 9460) support does and
does not do, and what it measured on the 2015-era seed list in November 2026.

## Resolver

`dns::Resolver` is a stub resolver, one per `net::Loop`, with one UDP socket
on an OS-chosen ephemeral port. Everything runs on the loop thread, and
callbacks always run later, never inside the call that started the lookup.

- **Lookups.** `resolve(host, cb)` asks for A records and returns the first
  address. `resolve_https(host, cb)` asks for the HTTPS RRset and returns the
  selected record (described below). Both go through the same slots,
  transaction ids, timers, retries, reply validation and FIFO. Each slot
  remembers its question type.
- **Validation.** A reply counts only if it comes from a configured server
  (address and port), has QR set, carries a transaction id that is in
  flight, and its question matches what that slot sent: same type (A or
  HTTPS), class IN, and the same name ignoring case. Anything else increments
  `mismatched`, `late` or `malformed` and is dropped. An A-typed reply to an
  HTTPS query is therefore ignored, and so is the reverse.
- **Retries.** Each attempt has its own timer (`timeout_ms`, 1500 ms by
  default). A timeout, SERVFAIL, REFUSED, NOTIMP or FORMERR moves the query to
  the next server with the same transaction id, up to `attempts` sends (3 by
  default). NXDOMAIN and NOERROR are final. A truncated (TC) reply resolves as
  NoAnswer because there is no TCP fallback.
- **Back-pressure.** At most `max_inflight` queries are outstanding. Later
  requests wait in a FIFO. A slot is refilled before its callback runs, so a
  callback that starts a new lookup queues behind older requests.
- **Shutdown.** `shutdown()` fails every in-flight and queued request (and any
  later one) with Timeout, then closes the socket. HTTPS callbacks get an
  empty `HttpsRecord`.

### EDNS0

Every query carries an OPT pseudo-RR (RFC 6891): root owner, a payload size of
`ResolverConfig::edns_udp_size` (default `kEdnsUdpSize` = 1232, the DNS Flag
Day 2020 value), version 0, DO bit clear, and no options. 1232 bytes is enough
for HTTPS RRsets that carry ECH configs, which the 512-byte RFC 1035 limit
would push toward truncation. It is also small enough to avoid IP
fragmentation on common paths. A `static_assert` and a constructor clamp keep
the advertised size at or below `net::UdpSocket::kRecvBufferSize` (4096). A
larger value would invite replies that the socket's receive buffers drop.

- `edns_udp_size = 0` sends plain RFC 1035 queries.
- **FORMERR fallback.** A FORMERR reply turns EDNS off for that query's
  remaining attempts (RFC 6891 section 7). This is counted in
  `edns_fallbacks`. With `attempts = 1` there is nothing to fall back to and
  the query fails with ServFail.
- The OPT record in replies is ignored, so extended rcodes and Extended DNS
  Errors are not read.

### Counters

The outcome counters (`ok`, `nxdomain`, `noanswer`, `servfail`, `timeouts`,
...) and the transport counters (`queries_sent`, `retries`, ...) cover both
query types. HTTPS-only counters:

- `https_requests` counts `resolve_https()` calls.
- `https_present` counts lookups that returned a usable RRset.
- `https_malformed` counts RRsets that were rejected because one of their
  records was malformed.

The crawler's `DnsQueriesSent` stat therefore includes HTTPS queries once
`--https-rr` issues them.

## Wire codec (`dns/packet.h`)

- `build_query(id, name, qtype, out, cap, edns_udp_size = kEdnsUdpSize)`
  writes RD=1, one IN question and the OPT record. `kMaxQuerySize` includes
  the OPT record's 11 bytes.
- `parse_response` parses the header, the single question and the answer
  section. It bounds-checks every byte, caps compression pointer jumps and
  name length, and accepts a cut answer section only when TC is set. It
  follows a CNAME chain (up to 8 hops) from the question name to the first
  owner that has an RRset of the wanted type: HTTPS when the question type is
  HTTPS, A otherwise. `cname_hops` reports how many hops it took. Records at
  other owners are ignored, and so are authority and additional records.
- **No allocation.** `parse_response` allocates nothing. `Response` holds
  fixed buffers: question text, 16 addresses, and one decoded `HttpsRr` (about
  270 bytes, with TargetName stored as text). The resolver keeps one
  `Response` and reuses it for every datagram. The only allocation on the
  HTTPS path is the `std::string target` in the `HttpsRecord` handed to the
  callback. The A path allocates nothing beyond what it did before. Its
  callbacks and pending entries now have room for an unused HTTPS callback,
  but an empty `std::function` never allocates.

### HTTPS RRs (RFC 9460)

`parse_https_rdata(rdata, rdlen, HttpsRr&)` decodes one record. It is public
so the fuzz targets can call it directly. The rules:

- **SvcPriority and TargetName.** TargetName must be uncompressed (section
  2.2), so a compression pointer makes the record malformed rather than
  something to follow. Labels must stay inside the rdata, total at most 255
  wire bytes, and contain no `.`. The root name is reported as `"."`, which
  means "the owner itself" in ServiceMode and "service unavailable" in
  AliasMode.
- **AliasMode** (priority 0). SvcParams are ignored unread, as section 2.4.2
  requires.
- **ServiceMode SvcParams.** Every key/length header and value must fit
  inside the rdata, and keys must be strictly increasing (which also rules
  out duplicates). Unknown keys are skipped. Known keys must have the right
  shape:

  | Key | Accepted value |
  |---|---|
  | `mandatory` (0) | non-empty, even length, strictly increasing, never lists key 0, and every listed key present in the record |
  | `alpn` (1) | non-empty list of 1..255-byte ids that exactly fills the value; `h3`, `h2` and `http/1.1` are recorded by exact match, so `h3-29` is not h3 |
  | `no-default-alpn` (2) | empty, and only valid alongside `alpn` |
  | `port` (3) | exactly 2 bytes; 0 in `HttpsRr::port` / `HttpsRecord::port` means absent |
  | `ipv4hint` (4) | non-empty multiple of 4 bytes |
  | `ech` (5) | an ECHConfigList whose u16 length prefix is at least 4 and exactly fills the value; the configs themselves are not parsed |
  | `ipv6hint` (6) | non-empty multiple of 16 bytes |

- **RRset selection.** The first AliasMode record wins, because section 2.4.2
  says ServiceMode records are then ignored. Otherwise the record with the
  lowest SvcPriority wins, with ties going to the earliest. `https_count`
  counts the well-formed records.
- **Malformed records.** One malformed record makes the whole RRset unusable
  (section 2.2: "the client MUST reject the entire RRset"). `parse_response`
  sets `https_malformed`, and the resolver returns NoAnswer with
  `present = false` and `malformed = true`. A malformed HTTPS record never
  fails the packet parse, though: only framing errors do that.
- **Not done:**
  - AliasMode targets are reported, not resolved.
  - Records whose `mandatory` list names a key we don't understand are still
    reported. This is a measurement, not a connection attempt, so the
    section 8 "incompatible RR" rule does not apply.
  - Hint addresses and ECH configs are validated for shape only and not kept.
  - Only the origin name is queried. There is no `_port._https` prefix
    naming, so lookups cover https on port 443 only.

### `resolve_https` results

| Status | `present` | Meaning |
|---|---|---|
| Ok | true | usable RRset; fields describe the selected record, `rrset_size` well-formed records, `cname_hops` CNAMEs followed |
| NoAnswer | false | NODATA (the normal "no HTTPS record" answer), a malformed RRset (`malformed = true`), a TC reply, or an IPv4-literal host (no query sent) |
| NxDomain | false | the name does not exist |
| ServFail | false | SERVFAIL/REFUSED/FORMERR on every attempt; common for HTTPS, see below |
| Timeout | false | no reply within `attempts * timeout_ms`, or cancelled by shutdown |
| Invalid | false | not a valid DNS name |

## Tests

`src/dns/tests/` (doctest, offline, about 1.5 s):

- **Packet tests.**
  - The OPT bytes, with a custom size and with EDNS off.
  - ServiceMode with alpn h3,h2, ipv4hint, ech and ipv6hint.
  - Lowest priority wins; ties go to the first record; AliasMode wins in
    either order; AliasMode SvcParams are ignored.
  - CNAME to the HTTPS RRset, with a decoy record at another owner.
  - NODATA; A records are not an HTTPS answer and HTTPS records are not an A
    answer.
  - Valid edge cases: unknown keys, `mandatory` listing unknown keys, a
    255-byte alpn id, `h3-29`, a 253-character target.
  - 26 malformed shapes, each checked directly and inside a response next to
    a good record.
  - Every truncation of an HTTPS packet is rejected, and 50,000 random
    mutations are survived.
- **Resolver tests** (in-process fake server):
  - Every query carries the OPT record.
  - The full set of HTTPS outcomes, run concurrently with an A query for the
    same name.
  - Replies of the other query type are rejected in both directions.
  - FORMERR leads to a retry without EDNS, for A and for HTTPS.
  - `edns_udp_size = 0` sends plain queries.
  - Shutdown cancels in-flight and queued HTTPS lookups.

## Measurements (2026-11-21)

**Conditions.** Home internet, Ryzen 9700X, Windows 11 26200, release build.
One resolver per run against 1.1.1.1 only, with `timeout_ms` 1500,
`attempts` 3 and `max_inflight` 256. The sample is every 137th unique host
(lowercased, in file order) of the 824,985 unique hosts in
`sample_urls/URL-input-1M.txt`, which gives 6,000 hosts:

- hosts 0–1,999 were used for the HTTPS run;
- hosts 2,000–5,999 were used for the EDNS A/B, alternating between the arms.

The probe was a throwaway program and is not in the repo.

### HTTPS records

Each of the 2,000 hosts got one A lookup and one HTTPS lookup, all issued
concurrently:

| | Hosts | Share of 2,000 | Share of hosts with an A record (1,214) | Share of hosts with an HTTPS RR |
|---|---|---|---|---|
| HTTPS RR present (usable) | 120 | 6.0% | 9.9% | 100% |
| alpn includes `h3` | 112 | 5.6% | 9.2% | 93.3% |
| alpn includes `h2` | 120 | 6.0% | 9.9% | 100% |
| alpn includes `http/1.1` | 0 | 0 | 0 | 0 |
| `ech` | 111 | 5.55% | 9.1% | 92.5% |
| `ipv4hint` / `ipv6hint` | 119 / 116 | | | 99.2% / 96.7% |
| AliasMode, `port`, `no-default-alpn`, >1 record | 0 | | | 0 |
| reached via CNAME | 1 | | | 0.8% |
| malformed RRset | 0 | | | |

Every HTTPS record seen had the shape `1 . alpn=... ipv4hint=... [ech=...]
[ipv6hint=...]`: priority 1, the owner as target, and a single record. That
is the form Cloudflare publishes automatically for proxied zones.
[INFERENCE: HTTPS RR presence on this list is close to "proxied by
Cloudflare"; the Study's Cloudflare IP-range check can confirm this.] Only 2
hosts advertise h3 without ECH, and 1 advertises ECH without h3.

HTTPS lookup status across all 2,000 hosts:

| Status | Hosts |
|---|---|
| Ok | 120 |
| NoAnswer (NODATA) | 1,020 |
| NxDomain | 614 |
| ServFail | 238 |
| Timeout | 8 |

**SERVFAIL for HTTPS is common and real.** 204 hosts whose A lookup succeeded
or returned NODATA got SERVFAIL for type 65. The A lookups on the same run had
only 30 SERVFAILs. Of 40 of those hosts re-checked through DoH, Cloudflare
SERVFAILed all 40 and Google 39. So the cause is old authoritative servers
that mishandle an unknown query type, not our client. Each such host costs 3
queries (SERVFAIL is retried). The run sent 4,630 queries for 4,000 lookups,
with 646 retries, most of them HTTPS SERVFAIL retries.

### Correctness check against independent parsers

`Resolve-DnsName` on this Windows build cannot ask for HTTPS records.
`-Type HTTPS` and `-Type 65` are both rejected: "Unable to match the
identifier name HTTPS to a valid enumerator name". `nslookup -type=TYPE65`
answers "unknown query type: TYPE65". Instead, 19 hosts were checked against
the DoH JSON APIs of Cloudflare (`cloudflare-dns.com/dns-query?type=HTTPS`)
and Google (`dns.google/resolve?type=65`). Each API decodes HTTPS rdata into
presentation format with its own parser. The comparison covered status plus,
for present records, priority, target, h3, h2, http/1.1, ech, ipv4hint,
ipv6hint and port.

| Hosts | Kind | Result |
|---|---|---|
| altlab.com, www.hartwilliams.com, rebelion.org, a-cho.com, www.example.com | h3+h2, ech and/or ipv6hint | match on every field (both providers) |
| www.wreckedexotics.com, holodilshchik.ru, www.epstrong.org, sexy-eyes.net, szbglqj.bolixiangbao.com | h2 only, no ECH | match (both) |
| www.calculatoredge.com | h2 + ECH, no h3 | match (both) |
| www.anyongbio.com | reached via CNAME, `1 . alpn=h2` | match (both) |
| xhtml.com, www.warrenzevon.com, www.win.net, allaboutalpha.com | NODATA | match (both) |
| www.clone-remover.com, www.anzow.com | SERVFAIL | match (both) |
| www.m5uk.com | SERVFAIL | Cloudflare SERVFAIL (match); Google NODATA |

That is 18/19 hosts agreeing with both providers, and 12/12 present records
agreeing field-for-field. The one difference is the resolver's own verdict
on a broken zone, not a parsing difference.

### EDNS0 does not change A success

Two disjoint arms of 2,000 hosts each ran concurrently against 1.1.1.1. One
used `edns_udp_size` 1232 and the other 0 (plain queries):

| Arm | OK | NoAnswer | NxDomain | ServFail | Timeout | Queries sent | Retries | TC | EDNS fallbacks |
|---|---|---|---|---|---|---|---|---|---|
| EDNS 1232 | 921 (46.05%) | 249 | 808 | 20 | 2 | 2,124 | 124 | 0 | 0 |
| Plain | 930 (46.50%) | 259 | 803 | 5 | 3 | 2,092 | 95 | 0 | 0 |

The 0.45-point OK difference is noise: z ≈ 0.29 for two proportions with
n = 2,000 each. The ServFail gap (20 vs 5) is host-specific. All 25 SERVFAIL
hosts were re-queried 3 times each, with and without EDNS:

- 20 failed in both arms in every round, mostly SERVFAIL with an occasional
  timeout or NXDOMAIN on either arm.
- 4 now return NXDOMAIN both ways.
- 1 answered OK in both arms, apart from a single SERVFAIL on a plain
  query.

No host failed only with EDNS. 1.1.1.1 never answered FORMERR, and no reply
was truncated.
