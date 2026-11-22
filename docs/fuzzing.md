# Fuzzing

Every parser that reads bytes from the network (or from a hostile server's
reply) has a [libFuzzer](https://llvm.org/docs/LibFuzzer.html) target built
with clang-cl and AddressSanitizer. The targets do more than look for memory
errors: each one checks invariants of the code it drives (round trips,
whole-vs-incremental parsing, a reference implementation, cross-checks
between two independent codecs), so logic bugs crash too.

## Targets

| Target | Code under test | Invariants checked |
|---|---|---|
| `dns_response` | `dns::parse_response`, `dns::build_query` | Parsing into a fresh and into a garbage-filled `Response` gives identical results (every field is reset). On success the question is NUL-terminated dotted text ≤ 253 chars with no empty label, ≤ 16 addresses, ≤ 8 CNAME hops; addresses only for non-HTTPS questions and an HTTPS RRset only for HTTPS ones. Any name `build_query` accepts parses back from the query it built (same id, qtype, class IN, RD, no answers); a too-small buffer is refused, never overrun; without EDNS the query is the same bytes minus the OPT record. |
| `dns_https` | `dns::parse_https_rdata`, HTTPS answers in `dns::parse_response` | Fresh vs dirty output identical. On success the TargetName is "." or valid dotted text. The prefix ending at the TargetName always parses, to the same record for AliasMode (whose SvcParams must be ignored). The same rdata inside a full response (directly, and behind a CNAME) gives matching `https_count` / `https_malformed` / `https` and the right `cname_hops`. With a second record (fuzz-chosen priority), the selected record follows RFC 9460 §2.4 (first AliasMode, else lowest SvcPriority, earliest on ties) and one malformed record poisons the RRset. |
| `http_response` | `parse::ResponseParser` | Input is 4 config bytes (HEAD or GET, call `finish()` at EOF, one of 8 size caps from 0 to unlimited, up to 15 split points) plus the byte stream. The stream is parsed whole and incrementally; each incremental step copies what has arrived into a buffer of exactly that size (so ASan flags any read past the bytes presented) and up to four pipelined responses are parsed from `consumed()`. Both runs must agree on state, error (except that a partial message over the cap may fail `TooLarge` first), status, headers, body, `consumed()`, keep-alive and chunked. Always `consumed()` ≤ bytes presented, header and body views inside the buffer. When Done: status 100–999 and not an interim 1xx (only 101 is final), `consumed()` ≤ cap, no body for HEAD/204/304, identity bodies byte-equal to the received bytes, Content-Length bodies exactly that long. Errors carry an error code and never keep-alive. |
| `url` | `parse::parse_url`, `resolve_url`, `to_string`, `parse_ipv4_literal` | Input is `base\nref`. Every Url produced is well formed (host 1–253 chars of `[a-z0-9._-]`, port ≠ 0, target starts with `/` and holds only bytes that may go on a request line, no `#`). `to_string(u)` re-parses to the same Url, also as a reference resolved against another base; `append_*` agree with `to_string`/`host_header`; resolving `""` gives the base; an absolute ref resolves to itself against any base; resolving into the base object itself (aliasing) equals resolving into a fresh one; a parsed IPv4 literal prints back as the host. |
| `robots` | `parse::RobotsRules` | Raw mode: arbitrary robots.txt plus fuzz targets; `/robots.txt` always allowed, no rules ⇒ everything allowed, crawl-delay finite and ≥ 0, `allowed()` deterministic. Model mode: each input line becomes an Allow/Disallow rule of one `*` group, and every decision is compared with an independent reference (RFC 9309 longest match, Allow wins ties, `*`, trailing `$`, percent-encoding normalization, textbook DP matcher) on targets derived from the patterns, both for the `*` group and for the same rules under a `User-agent: WinCrawl/2.0` group. |
| `links` | `parse::LinkExtractor` | Optional first line is the page URL. Count-only and collecting extraction return the same count, equal to the number of URLs collected; a fresh and a warm (reused across inputs) extractor agree in both modes; `extract()` clears its output vector; every collected URL is well formed and `to_string()` of it re-parses to the same Url. The document is an exact-size heap copy so over-reads are caught. |
| `benchsrv_dns` | `benchsrv::build_dns_reply` (the fake DNS server's own query codec) | Drop exactly for datagrams shorter than a header or with QR set, and then no reply bytes; otherwise a reply ≥ 12 and ≤ 512 bytes echoing the id with QR set; non-error replies carry the question verbatim; Answered replies parse with `wc::dns` (cross-codec check; skipped when a label contains `.`, which `wc::dns` rejects by design) to exactly one A record equal to `host_ip()` for the `h<N>` name. |
| `record` | `crawl::append_json_string`, `truncate_utf8`, `alt_svc_has_h3`, `parse_hsts` (study record) | `append_json_string` appends exactly one string literal accepted by a strict RFC 8259 validator, in valid UTF-8 (no overlongs, surrogates, > U+10FFFF), keeping what was in the buffer, and decoding back to the input when the input was valid UTF-8. `truncate_utf8` returns a prefix ≤ max that, for valid input, is valid UTF-8 and at most 3 bytes short of max. `alt_svc_has_h3` is false without `h3` in the value, true once an h3 alternative is prepended, unaffected by leading OWS. A valid `parse_hsts` result survives a round trip through its canonical serialization; directive names are case-insensitive. |
| `sig` | `sig::sfv` parsers, `parse_jwk`/`parse_key_set`/`parse_private_key`, `parse_http_message`, `verify_signatures`, `verify_directory`, `RequestSigner` (Web Bot Auth) | Byte 0 picks a mode. SFV: a parsed Dictionary or Item serializes, reparses to an equal value, and is a fixed point of serialization; each member value serialized alone reparses to the same member. JWK: every key found has a 43-character thumbprint equal to `thumbprint(x)`, and its canonical public JWK (and private JWK, when `d` loaded) parses back to the same key; `find_key` finds it. Verify: message text checked under the RFC 9421, Web Bot Auth and directory profiles against the RFC 9421 test key gives deterministic results; the overall result is valid exactly when every signature is; a valid signature names a known key and was checked over a base ending in its `@signature-params` line; a valid directory has every key proven. Sign: whatever authority, `Signature-Agent`, label, form, window and nonce `RequestSigner` accepts verifies under the Web Bot Auth profile with the same label, nonce and agent, and fails for another authority. |

Each target has a seed corpus in `fuzz/corpus/<target>/` (hand-written
examples of normal and edge-case inputs, a few files each; `fuzz/.gitattributes`
keeps them byte-exact) and a dictionary in `fuzz/dict/<target>.dict`.

## Build

The `fuzz` preset uses clang-cl (LLVM ≥ 20 with compiler-rt; the LLVM that
ships with Visual Studio 2026 is clang 22) and sets `WINCRAWL_BUILD_FUZZ=ON`:

```powershell
tools\vsdev.cmd cmake --preset fuzz
tools\vsdev.cmd cmake --build --preset fuzz
tools\vsdev.cmd ctest --preset fuzz        # the unit tests, under ASan
```

Outputs land in `build/fuzz/bin/` (`fuzz_<target>.exe`, the unit tests and
benchd) and `build/fuzz/wincrawl.exe`, each next to a copy of LLVM's
`clang_rt.asan_dynamic-x86_64.dll`.

How it is wired (root `CMakeLists.txt`): with `WINCRAWL_BUILD_FUZZ` every
target is compiled with `-fsanitize=address -fsanitize=fuzzer-no-link`
through `wc_options`, so the libraries carry coverage instrumentation and the
unit tests and apps run under ASan too. LLVM's Windows libFuzzer runtime is
built `/MT` with MSVC STL container annotations off and records both with
`/FAILIFMISMATCH`, so the fuzz build uses `/MT` and defines
`_DISABLE_VECTOR_ANNOTATION` / `_DISABLE_STRING_ANNOTATION` (container-overflow
detection is the one ASan check given up). CMake links clang-cl targets with
lld-link directly rather than through the clang driver, so the runtimes are
named explicitly: `clang_rt.asan_dynamic` + `clang_rt.asan_static_runtime_thunk`
for every executable, and `clang_rt.fuzzer_no_main`, which provides the
coverage callbacks; the fuzz targets get `main()` from `fuzz/main.cpp`
(`LLVMFuzzerRunDriver`). The `debug` and `release` presets do not see any of
this.

## Run

`fuzz/run.ps1` runs targets one after another from their corpora. New inputs
go to a work corpus (`build/fuzz/corpus-work/<target>/`, never into the
committed seeds) and findings to `build/fuzz/artifacts/<target>/`:

```powershell
powershell -NoProfile -File fuzz\run.ps1                          # every target, 60 s each (what CI runs)
powershell -NoProfile -File fuzz\run.ps1 -Seconds 600 -Targets robots,url
powershell -NoProfile -File fuzz\run.ps1 -Seconds 3600 -Targets http_response -Extra '-jobs=4','-workers=4'
```

Or directly:

```powershell
build\fuzz\bin\fuzz_http_response.exe build\fuzz\corpus-work\http_response fuzz\corpus\http_response `
    -dict=fuzz\dict\http_response.dict -max_total_time=600 -timeout=10 -artifact_prefix=build\fuzz\artifacts\
```

## Reproduce, minimize, keep

A crash, leak, timeout or OOM writes `crash-<sha1>` (`timeout-`, `oom-`,
`leak-`) to the artifact prefix and prints the failing invariant or the ASan
report.

```powershell
# Re-run one input (exits non-zero and prints the report)
build\fuzz\bin\fuzz_url.exe build\fuzz\artifacts\url\crash-<sha1>
# Shrink it
build\fuzz\bin\fuzz_url.exe -minimize_crash=1 -runs=100000 -exact_artifact_path=min.bin build\fuzz\artifacts\url\crash-<sha1>
# Debug it: the targets are RelWithDebInfo, so any debugger works on
#   build\fuzz\bin\fuzz_url.exe min.bin
```

After fixing: add a regression test to the owning module's doctest suite and
copy the minimized input into `fuzz/corpus/<target>/` so CI replays it on
every run. To fold a long local run's discoveries into the seeds, merge
rather than copy:
`fuzz_<t>.exe -merge=1 fuzz\corpus\<t> build\fuzz\corpus-work\<t>`
(keep seed corpora small; a few dozen files at most).

## CI

`.github/workflows/ci.yml` job `fuzz` (windows-latest): locates a clang-cl
that ships libFuzzer (the Visual Studio-bundled LLVM, else a standalone LLVM
install), configures and builds the `fuzz` preset, runs `ctest --preset
fuzz` (unit tests under ASan), then `fuzz/run.ps1 -Seconds 60` over every
target. Any failure uploads `build/fuzz/artifacts/` as the `fuzz-artifacts`
artifact. The job takes about 9 minutes.

## Results

Local campaign, 2026-11-21, Ryzen 9700X (8C/16T, 32 GB) shared with other
builds and benchmarks; clang 22.1.3 + ASan, one libFuzzer process per target,
at most 4 at once, starting from the seed corpora with dictionaries,
`-timeout=10`, default `-max_len` (4096) and RSS limit (2 GB). `cov` is
libFuzzer's count of covered coverage points (edges) at the end, `ft` its
feature count.

| Target | Time | Executions | exec/s | cov | ft | Corpus | Findings |
|---|---:|---:|---:|---:|---:|---:|---|
| `dns_response` (A only, before the HTTPS RR merge) | 10 min | 98.1 M | 163,185 | 145 | 453 | 168 | none |
| `dns_response` (with HTTPS RRs) | 10 min | 135.5 M | 225,504 | 233 | 794 | 362 | none |
| `dns_https` | 10 min | 8.86 M | 14,735 | 228 | 433 | 106 | none |
| `http_response` | 10 min | 7.34 M | 12,218 | 504 | 2,159 | 604 | none |
| `url` | 10 min | 15.1 M | 25,158 | 520 | 1,834 | 476 | none |
| `robots` (old matcher) | 10 min | 1.87 M | 3,115 | 933 | 5,362 | 1,492 | algorithmic DoS, see below |
| `robots` (linear matcher) | 10 min | 1.98 M | 3,300 | 969 | 5,746 | 1,613 | none |
| `links` | 10 min | 3.97 M | 6,609 | 666 | 3,500 | 1,203 | none |
| `benchsrv_dns` | 10 min | 53.0 M | 88,128 | 184 | 389 | 89 | none |
| `record` | 10 min | 8.83 M | 14,691 | 431 | 1,864 | 632 | none |

About 1 h 40 min of fuzzing in total (plus ~5 min of smoke runs), roughly
335 M executions: no crash, ASan report, leak, timeout, OOM or invariant
failure. The exec/s figures include each harness's own checking (the robots
target runs a reference matcher over up to 16 rules × 34 targets twice per
input; `http_response` parses every input twice and copies the buffer at
each split) on a shared machine, so they are lower bounds. The unit tests
also all pass under ASan (`ctest --preset fuzz`).

`sig` (added 2026-11-22 with Web Bot Auth, [`web-bot-auth.md`](web-bot-auth.md)):
3 min from the seed corpus, then 10 min continuing from that work corpus,
same machine and settings. 12.3 M executions in total; the 10-minute run
averaged 13,660 exec/s and ended at cov 2,694, ft 10,498, corpus 2,382. No
findings. The sign mode runs an Ed25519 signature and verification per input,
which bounds its speed.

The first CI run of the job (60 s per target, 4-vCPU windows-latest runner)
saw 53–110 k exec/s for the DNS targets, 14–16 k for `http_response`, `url`
and `links`, and 1.9 k for `robots`.

### Finding: quadratic robots.txt matching (fixed)

Not a crash: while looking into the `robots` target's low exec/s, the
slowest inputs in its corpus took ~11 ms each, which pointed at
`RobotsRules::allowed()`. Its matcher tracked the set of reachable path
positions, costing O(pattern × target) per rule. A hostile robots.txt
within the real-mode size cap (512 KiB: 260 rules of 1000 `*a` pairs and a
final `b`) made one `allowed()` call on a 2 KB URL take **297.9 ms** in a
release build (4.2 ms for a 200-byte URL), all of it on the per-core event
loop thread that serves thousands of other connections.

Fix (`src/parse/robots.cpp`, `matches()` / `find_end()`): a pattern is
literal segments separated by `*`; the first must start the path, the
others are found at their leftmost occurrence (optimal for a prefix match),
and a trailing `$` instead requires the last segment to end the path.
Segments are located with Knuth-Morris-Pratt, so each rule costs
O(pattern + target) whatever the input. Same hostile file: **2.5 ms** on the
2 KB URL (119× faster), 0.27 ms on the 200-byte one. The semantics are
checked by the `robots` target's model mode against its independent DP
reference (10 min, 1.98 M inputs, no disagreement) and by new doctest cases
(`wildcard segments: …` and `hostile robots.txt matches in linear time`,
which runs the 512 KiB file against an 8 KB target in 76 ms in a debug
build). A small version of the hostile file is in the seed corpus.

### Not covered

- The TLS layer (Schannel parses the records; `tls::ClientSession` only
  shuttles bytes) and the event loop / socket code, which need I/O rather
  than a byte-buffer entry point.
- ASan's container-overflow checks (see Build); UBSan is not enabled.
