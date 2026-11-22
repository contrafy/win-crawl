# Web Bot Auth

wincrawl can sign every request it sends the way Cloudflare's
[Web Bot Auth](https://blog.cloudflare.com/web-bot-auth) asks: an
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signature with
an Ed25519 key, plus a `Signature-Agent` header naming a key directory the
verifier can fetch. This note pins down the protocol as of 2026-11-22, then
covers the implementation (`src/sig/`, `wincrawl-botauth`, the directory
Worker in `tools/bot-auth-directory/`), how to run it, what was verified
against which reference, and what it costs.

## The protocol, pinned

Sources, read on 2026-11-22:

- Cloudflare blog: [Forget IPs: using cryptography to verify bot and agent traffic](https://blog.cloudflare.com/web-bot-auth/) (May 2025) and
  [Message Signatures are now part of our Verified Bots Program](https://blog.cloudflare.com/verified-bots-with-cryptography/) (July 2025).
- Cloudflare docs: [Web Bot Auth](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/) (modified 2026-10-08). The page
  pins [draft-meunier-http-message-signatures-directory-03](https://datatracker.ietf.org/doc/html/draft-meunier-http-message-signatures-directory-03)
  and [draft-meunier-web-bot-auth-architecture-02](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture-02).
- IETF: [draft-ietf-webbotauth-httpsig-protocol-01](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) (webbotauth WG, 2026-10-29),
  which folded the directory draft in;
  [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures),
  [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651) (Structured Field Values),
  [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519),
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) (OKP JWKs),
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) (JWK thumbprints),
  [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) (Content-Digest).
- [github.com/cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth) at `ce5e54f` (2026-11-14): the TypeScript and Rust
  reference implementations, the directory validator (`http-signature-directory`),
  the example verification Worker, and JSON test vectors.

A signed request carries three header fields:

| Field | Value |
|---|---|
| `Signature-Agent` | where the verifier finds the keys: an https URL as a Structured Field string (see below) |
| `Signature-Input` | `sig1=(<covered components>);created=…;keyid=…;alg="ed25519";expires=…;nonce=…;tag="web-bot-auth"` |
| `Signature` | `sig1=:<64-byte Ed25519 signature, base64>:` |

**Covered components.** At least `@authority` (or `@target-uri`), and the
`signature-agent` field. `@authority` is the target host, lowercased, with a
non-default port (RFC 9421 §2.2.3): the `Host` header wincrawl already sends.
Cloudflare also accepts `@method`, `@path`, `@query` and other fields, but no
`@query-param`, `@status`, or the `sf`, `bs`, `key`, `req` component
parameters.

**Parameters.** `created` and `expires` (Unix seconds; the draft recommends
`expires` ≤ 24 h after `created`, Cloudflare recommends about a minute),
`keyid` = the base64url SHA-256 JWK thumbprint (RFC 7638 with RFC 8037
Appendix A.3: SHA-256 of `{"crv":"Ed25519","kty":"OKP","x":"…"}`),
`alg="ed25519"`, `tag="web-bot-auth"`, and an optional `nonce`. Cloudflare
does not track nonces; it relies on short `expires`. The reference signers use
64 random bytes, base64. Parameter order is free (the signature covers the
serialization as sent); wincrawl uses the reference order `created, keyid,
alg, expires, nonce, tag`.

**`Signature-Agent`: string or dictionary.** This is where the sources
disagree today:

| Source | Form | Covered as |
|---|---|---|
| directory-03, Cloudflare docs, Radar URL Scanner | `Signature-Agent: "https://bot.example"` (sf-string) | `"signature-agent"` |
| draft-ietf-webbotauth-httpsig-protocol-01 §5.2.1 | `Signature-Agent: sig1="https://bot.example"` (dictionary, one member per signature label) | `"signature-agent";key="sig1"` |

The IETF draft says signers MUST send the dictionary and verifiers MAY accept
the string. Cloudflare's docs say its verifier fails the dictionary form and
the `key` parameter. **wincrawl sends the string form by default**, since that
is what Cloudflare verifies; `RequestSigner` and `wincrawl-botauth sign --dict`
produce the dictionary form too, and the verifier accepts both. The value is
the directory's origin (`https://bot-auth-directory.<sub>.workers.dev`):
verifiers append `/.well-known/http-message-signatures-directory`. Draft -01
instead makes every value a direct JWK Set URL; Cloudflare's reference
verifier handles both (it tries the well-known path when the URL's path is
`/`).

**Key directory.** `GET /.well-known/http-message-signatures-directory` over
https returns 200, `Content-Type: application/http-message-signatures-directory+json`,
a JWK Set of public keys (only `kty`, `crv`, `x` matter to Cloudflare; `kid`,
when present at the well-known path, must equal the thumbprint), and one
signature per key proving possession: covered components `("@authority";req
"content-digest")` (the request's authority, and RFC 9530 `Content-Digest:
sha-256=:…:` over the body), parameters `created`, `expires`, `keyid`,
`tag="http-message-signatures-directory"`. Cloudflare's docs still show the
older proof over `"@authority";req` alone; draft -01 Appendix B.1 and
Cloudflare's own validator (`http-signature-directory`) require
`content-digest`, so the Worker signs both.

Example with the RFC 9421 test key (`test-key-ed25519`, keyid
`poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`); this is draft -01 vector E.2.2,
which `RequestSigner` reproduces byte for byte:

```
GET /path/to/resource HTTP/1.1
Host: example.com
Signature-Agent: "https://signature-agent.test"
Signature-Input: sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"
Signature: sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:
```

The signature base it signs (RFC 9421 §2.5; lines end in LF, no trailing
newline):

```
"@authority": example.com
"signature-agent": "https://signature-agent.test"
"@signature-params": ("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"
```

The dictionary form of the same request (vector E.2.1) differs in
`Signature-Agent: sig2="https://signature-agent.test"`, the component
`"signature-agent";key="sig2"`, and the signature.

## Design

### Ed25519 without CNG support

Windows CNG has no Ed25519 signatures. On this machine (Windows 11 build
26200, SDK 10.0.26100) `BCryptOpenAlgorithmProvider` knows no
`ED25519`/`EdDSA` name, ECDSA with `BCRYPT_ECC_CURVE_25519` returns
`STATUS_NOT_SUPPORTED`, and the signature algorithms CNG enumerates are RSA,
ECDSA (P-256/384/521), DSA, ML-DSA and composite ML-DSA; curve25519 is
ECDH-only. So Ed25519 comes from [Monocypher](https://monocypher.org/) 4.0.3
(BSD-2-Clause or CC0, small, audited by Cure53 in 2020 at version 3.1.1;
4.0.3 fixes a timing leak in EdDSA signing), vendored unmodified in
`third_party/monocypher/` with its hashes and provenance. It compiles as C++
inside its own namespace (`MONOCYPHER_CPP_NAMESPACE`, an upstream option), so
the fuzz preset instruments it like everything else; it is `/W4`-clean under
MSVC and clang-cl. SHA-256 (thumbprints, Content-Digest) and randomness
(`BCryptGenRandom`, system-preferred RNG) come from CNG.

### `src/sig/` (`wc_sig`)

| File | |
|---|---|
| `crypto.h` | `Ed25519Key` (seed + public key, wiped on destruction), `ed25519_verify`, `sha256`, `random_bytes` |
| `base64.h` | padded base64 for Structured Fields (lenient decoding, as RFC 9651 §4.2.7 asks) and canonical unpadded base64url for JOSE |
| `sfv.h` | RFC 9651 parser and canonical serializer (Dictionary, Item, Inner List, all RFC 8941 bare item types) |
| `jwk.h` | strict JSON reader for Ed25519 JWKs and JWK Sets (other key types skipped), PKCS#8 PEM import, thumbprints, serialization |
| `signer.h` | `RequestSigner`: the three header lines per request |
| `httpsig.h` | signature bases for any covered components, verification with three profiles (plain RFC 9421, Web Bot Auth, directory), `verify_directory`, `parse_http_message` |

**Signing on the hot path.** `RequestSigner::init` does everything that does
not change per request: thumbprint, the covered-components list, the
`Signature-Agent` header line and its signature base line. `sign(authority)`
then writes the parameters (fresh `created`, `expires = created + 60`, a
64-byte nonce from CNG), the base, the Ed25519 signature and the headers into
buffers it owns and reuses. It is one object per event loop, so no locks.
Measured below: zero heap allocations per request after warm-up, ~23 µs per
request, nearly all of it Ed25519.

**Verifying.** The verifier is general RFC 9421, not only what wincrawl
signs. It derives `@method`, `@authority`, `@scheme`, `@target-uri`,
`@request-target`, `@path`, `@query`, `@status` and header fields (combined
per RFC 9421 §2.1), supports the `req` and `key` component parameters, and
rebuilds `@signature-params` by canonically re-serializing the received
Inner List. It rejects duplicate components, non-ASCII values (which would
need `bs`), and `sf`/`bs`/`tr`/`@query-param` as unsupported. Profiles add
the Web Bot Auth rules (tag, `created`/`expires`/`keyid` present, bare
`@authority` or `@target-uri` covered, `Signature-Agent` present, https and
covered in whichever form it has, at most one member per signature) or the
directory rules (`"@authority";req` and `content-digest` covered). Every
failure has a reason (`SigError` plus text). It is used by the tests, the
`verify` tools and the fake server in the crawl end-to-end tests, so it
allocates freely.

## Keys

```powershell
mkdir secrets
build\release\wincrawl-botauth.exe keygen --out secrets\bot-auth.jwk
#   wrote secrets\bot-auth.jwk (Ed25519 private JWK, owner-only ACL)
#   keyid  <thumbprint>
#   public {"kty":"OKP","crv":"Ed25519","kid":"<thumbprint>","x":"…","use":"sig"}
build\release\wincrawl-botauth.exe jwks --key secrets\bot-auth.jwk   # the directory body
```

`keygen` writes the private JWK (`{"kty":"OKP","crv":"Ed25519","kid":…,"x":…,"d":…}`)
with `CREATE_NEW` and a protected DACL granting only the current user full
control (checked: one ACE, not inherited). It never prints the private key;
`--out -` sends it to stdout when that is what you want (for example straight
into `wrangler secret put`). Keys made with `openssl genpkey -algorithm
ed25519` (PKCS#8 PEM, as Cloudflare's docs suggest) work anywhere a key file
is read. `*.jwk`, `*.pem`, `secrets/` and `.dev.vars` are gitignored.

## The key directory

`tools/bot-auth-directory/` is a Cloudflare Worker (plain JavaScript, Web
Crypto Ed25519, no dependencies at runtime) that serves the directory for the
key in its `BOT_AUTH_PRIVATE_JWK` secret: the JWK Set (`kid` = thumbprint,
`use":"sig"`, the same bytes `wincrawl-botauth jwks` prints), `Content-Digest`,
and a fresh `binding0` signature per request valid for `SIGNATURE_TTL`
(300 s, also its `max-age`; `no-transform` keeps the edge from compressing the
digested bytes). Several keys in the secret give one signature each, for
rotation. Exact deploy steps (generate the key, `npx wrangler secret put
BOT_AUTH_PRIVATE_JWK`, `npx wrangler deploy`, verify, optionally register with
Cloudflare's Verified Bots) are in
[`tools/bot-auth-directory/README.md`](../tools/bot-auth-directory/README.md).
It is not deployed: that needs the owner's Cloudflare account.

## Verification results

All of the following were run on 2026-11-22.

**Published vectors (`sig_tests`, debug, release and the ASan fuzz build).**

- RFC 8032 §7.1: all five Ed25519 vectors (TEST 1, 2, 3, 1024, SHA(abc)):
  public key derivation, signatures byte for byte, verification, and rejection
  of flipped message/signature/key bits and of `S + L`.
- RFC 8037 Appendix A.3 thumbprint (`kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`)
  and the RFC 9421 test key's (`poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`),
  from the JWK and from the PKCS#8 PEM in RFC 9421 Appendix B.1.4.
- RFC 9421 Appendix B.2.6: the signature base over `test-request` and the
  Ed25519 signature `wqcAqbmY…KRCw==`, byte for byte, then verified.
- draft-ietf-webbotauth-httpsig-protocol-01 Appendix E.2.1 (dictionary),
  E.2.2 (sf-string) and E.2.3 (signed directory response).
- cloudflare/web-bot-auth fixtures: `web_bot_auth_architecture_v1/v2.json`
  (the Ed25519 cases, including `@authority`-only signatures and a
  dictionary member key that differs from the label) and
  `web_bot_auth_directory_response_v1.json`.
- A directory response captured from Cloudflare Research's example server
  (older proof without `content-digest`): verifies with `--legacy`, and is
  reported as lacking `Content-Digest` without it.

The signer reproduces every request vector's headers exactly, and the
verifier accepts them; changing the authority, the `Signature-Agent` value,
a signed parameter, the tag, alg or keyid, coverage, or the validity window
fails with the matching `SigError`.

**Cross-implementation.** Against Cloudflare's npm `web-bot-auth` 0.2.0
(`http-message-sig` 0.3.0): headers from `wincrawl-botauth sign` verify with
its `verify()` in both forms (and fail for another authority); headers from
its `sign()` verify with `wincrawl-botauth verify` in both forms.

**Fuzzing.** `fuzz/sig.cpp` drives the Structured Field and JSON parsers,
message parsing, verification under all three profiles, and a
sign-then-verify property over fuzz-chosen authorities, URLs, labels and
nonces ([`fuzzing.md`](fuzzing.md) lists the invariants). 13 minutes under
ASan, 12.3 M executions: no findings.

**The Worker.** `npm test` (Node 24, `node --test`): thumbprints, the
directory body equal to vector E.2.3's, and a `signDirectory` signature equal
to `web_bot_auth_directory_response_v1.json`'s `binding0` byte for byte; key
rotation; secret validation; the handler's 200/404/405/503/500 paths. Then the
real runtime: `npx wrangler dev` (wrangler 4.166.0, workerd, local) with a
throwaway key, fetched with `curl -si`, checked by `wincrawl-botauth
verify-directory --authority 127.0.0.1:58787`: valid; the same response
checked under another authority: rejected (`bad signature`).

**Live verifiers**, with the `wincrawl-botauth sign` output sent by curl.
Cloudflare Research's example server
(`https://http-message-signatures-example.research.cloudflare.com/v0/api/verify`)
verifies with the RFC 9421 test key, which its own directory publishes:

| Request | Answer |
|---|---|
| test key, `Signature-Agent` = the example origin, sf-string | `valid` |
| test key, no `Signature-Agent` (its built-in key) | `valid` |
| test key, dictionary form (origin or well-known URL) | `invalid: invalid signature` |
| own key, `Signature-Agent` = the example origin | `invalid: invalid signature` (its directory has only the test key) |
| test key, signed for another `@authority` | `invalid: invalid signature` |
| test key, expired | `invalid: Signature expired` |

The dictionary-form failure is the deployed example's, not wincrawl's: the
same headers verify with Cloudflare's current npm library and reproduce the
draft's E.2.1 vector, and Cloudflare's docs say the dictionary form is not
accepted yet.

Cloudflare's production verifier (`https://crawltest.com/cdn-cgi/web-bot-auth`)
answers 400 for a malformed message, 401 for a well-formed one whose key is
not registered with Cloudflare, and 200 for a registered, valid one:

| Request | Answer |
|---|---|
| unsigned | 400 `missing signature / signature-input / signature-agent headers` |
| own key or test key, sf-string, any `Signature-Agent` | 401 `unknown public key or unknown verified bot ID for keyid` |
| same, dictionary form | 401 (same text) |
| no `Signature-Agent` | 400 (missing headers) |
| `signature-agent` not covered, `tag="other"`, or no `keyid` | 400 `signature, signature-input, or signature-agent is malformed` |

So wincrawl's signatures pass every format check Cloudflare's edge applies;
the key lookup comes before signature and expiry checks (a wrong authority
or an expired signature also gets 401), so a 200 needs the owner's key
directory deployed and the key registered (Verified Bots form, "Request
Signature"). The deploy README ends with that check.

## Cost

`wincrawl-botauth bench --n 50000`, release build, Ryzen 9700X, three runs:

| | |
|---|---|
| `RequestSigner::sign()` per request | 23.2–23.4 µs (≈43K requests/s per core) |
| of which Ed25519 signing (358-byte base) | 22.7–22.8 µs |
| of which the 64-byte nonce (CNG) | 0.07–0.08 µs |
| heap allocations | 0 in 50,000 calls after warm-up |
| bytes added to each request | 428 (sf-string `Signature-Agent` of 23 characters) |
| `verify_signatures()` per request (parse + base + verify) | 65–66 µs |

At the crawler's ~5K requests/s that is ~0.12 CPU-seconds per second spread
over all loops (under 1% per loop with 16 loops).

## Limitations

- Signatures cover `@authority` and `signature-agent` only, as Web Bot Auth
  requires. Anyone who sees one request can replay it to the same host, with
  any method and path, until it expires: 60 s by default, and wincrawl uses a
  fresh nonce and window per request. Covering `@method`/`@path` too would
  narrow that; nothing in the current verifiers asks for it.
- Only the sf-string `Signature-Agent` reaches wincrawl's crawl path (the
  form Cloudflare verifies). Switching to the dictionary form the IETF draft
  mandates is one `SignerOptions` field once Cloudflare accepts it.
- Plain-http requests carry the signature in clear text; on https it is
  inside TLS.
- The verifier does not fetch directories (it is offline by design); the
  tools take the response as text. It accepts Ed25519 only (no RSA-PSS).
- A 200 from Cloudflare's verifier needs the directory deployed under the
  owner's account and the key registered; until then the expected answer is
  401.
- Monocypher's signing (~23 µs) is slower than the fastest Ed25519
  implementations (libsodium/ref10-style assembly), but well below anything
  that matters next to a network round trip.
