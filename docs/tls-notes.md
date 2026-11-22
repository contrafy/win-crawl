# Schannel and post-quantum TLS: notes

What wincrawl's `src/tls` does about hybrid post-quantum key exchange, how to turn it on, and what
was verified. All measurements were taken on Windows 11 25H2 build 26200.9974 (x64) in November 2026.

## Enabling PQ: one machine-wide setting

Schannel has supported the ML-KEM groups (`X25519MLKEM768`, `SecP256r1MLKEM768`,
`SecP384r1MLKEM1024`, plus pure `MLKEM512/768/1024`) since KB5089573 (26200.8524) and the July 2026
GA update. They are **off by default**: the default list is `curve25519, NistP256, NistP384`.
Sources: Microsoft Learn, [TLS Supported Groups in Windows 11 24H2 and later](https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-supported-groups-in-windows-11-24h2-and-later),
and the [Windows, TLS 1.3 and Post Quantum Crypto FAQ](https://techcommunity.microsoft.com/blog/post-quantum-crypto-tech-blog/windows-tls-1-3-and-post-quantum-crypto-faq/4556389).

**A process or a credential cannot add a group.** We looked for a way:

- `SCH_CREDENTIALS` / `TLS_PARAMETERS` (SDK 10.0.26100, the newest installed, and the current
  win32metadata headers): the only crypto knob is `pDisabledCrypto`, a deny list. Nothing in it
  enables a group.
- There are no new `SECPKG_ATTR_*` values and no new `SCH_CRED_*` flags.
- The BCrypt context configuration (`CRYPT_LOCAL` / `"SSL"` / `NCRYPT_SCHANNEL_INTERFACE`) is
  machine-wide and needs admin rights. It is the registry value below.

So PQ is a machine setting. Run this from an elevated PowerShell:

```powershell
Enable-TlsEccCurve -Name X25519_MLKEM768 -Position 0   # undo: Disable-TlsEccCurve -Name X25519_MLKEM768
Get-TlsEccCurve                                        # X25519_MLKEM768, curve25519, NistP256, NistP384
```

The cmdlet writes `HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002`,
value `EccCurves` (REG_MULTI_SZ). A Group Policy "ECC Curve Order" (under
`HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`) overrides it. This
machine has no such policy. `-Position 0` matters, because both client and server walk the list in
order.

- **No reboot needed.** Some write-ups say a reboot is required. Here, a process started right
  after the change already sent the new ClientHello. We did not test whether credential handles
  acquired before the change pick it up.
- **State of this machine:** enabled on 2026-11-21 through one UAC prompt. Before the change,
  `EccCurves` and `Get-TlsEccCurve` both read `curve25519,NistP256,NistP384`. After it, both read
  `X25519_MLKEM768,curve25519,NistP256,NistP384`. It stays enabled for the measurement study,
  which the owner approved; the integrator restores the original value afterwards. Exact commands,
  run in an elevated PowerShell:

  ```powershell
  # enable (what was run)
  Enable-TlsEccCurve -Name 'X25519_MLKEM768' -Position 0
  # restore the original list
  Disable-TlsEccCurve -Name 'X25519_MLKEM768'
  # or write the original value back directly
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002' `
      -Name EccCurves -Type MultiString -Value @('curve25519','NistP256','NistP384')
  Get-TlsEccCurve   # expect: curve25519, NistP256, NistP384
  ```

### What wincrawl does with it

- `tls::startup(StartupOptions{.post_quantum = true})` (the default) uses the machine list as it is.
- `post_quantum = false` adds the ML-KEM groups to the credential's `pDisabledCrypto` list, with
  `eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange` and `strCngAlgId = "X25519_MLKEM768"`,
  and so on. That process then sends the classical ClientHello byte for byte, whatever the machine
  setting is. This gives a per-process A/B switch without admin rights.
- `tls::post_quantum_available()`: at startup, `startup()` builds a ClientHello locally (an
  `InitializeSecurityContext` with no peer, so nothing is sent) and checks its `supported_groups`
  for an ML-KEM code point. It reports what Schannel really sends, not what the registry claims.
  Cost: one local ClientHello, about 1 ms, once per process.

## Reading the negotiated group

No documented attribute names the TLS 1.3 group:

| Attribute | TLS 1.3 x25519 | TLS 1.3 X25519MLKEM768 | TLS 1.2 ECDHE x25519 | TLS 1.2 RSA kx |
|---|---|---|---|---|
| `CONNECTION_INFO.aiExch` / `dwExchStrength` | 0 / 255 | 0 / 1216 | `CALG_ECDH_EPHEM` / 255 | `CALG_RSA_KEYX` / 2048 |
| `CONNECTION_INFO_EX.szExchange` | "" | "" | "ECDH" | "RSA" |
| `CIPHER_INFO.szExchange` | "" | "" | "ECDH" | "RSA" |
| **`CIPHER_INFO.dwKeyType`** | **29** | **4588 (0x11EC)** | **29** | **0** |
| `KEY_INFO` | sig "", enc AES | same | ECDSA / AES | RSA / AES |

`SecPkgContext_CipherInfo.dwKeyType` is documented only as "the key type". In every case we tried,
it equals the IANA supported-group code point that the server picked. We checked it against the
ServerHello `key_share` (TLS 1.3) and the ServerKeyExchange named curve (TLS 1.2) on the wire:

- x25519 = 29, secp256r1 = 23, secp384r1 = 24, X25519MLKEM768 = 4588;
- TLS 1.2 and TLS 1.3, against live servers and the loopback test server;
- 48 live hosts × 4 runs, all matching (see below).

`ClientSession::info()` reports it as `group`, as `key_exchange` (IANA name via `tls::group_name()`),
and as `pq_hybrid`.

- **RSA key transport:** gives 0, so the group name is empty. The cipher name (`TLS_RSA_WITH_*`)
  shows that case.
- **Resumed TLS 1.2 session:** reports the group of the handshake that created the session. No key
  exchange happens on the wire.
- **Resumed TLS 1.3 session:** runs a fresh PSK-(EC)DHE, and the group reported is that new one.

`resumed` comes from `SECPKG_ATTR_SESSION_INFO` (`SSL_SESSION_RECONNECT`). It works for both
versions: tested in memory, and live, where 47 of 48 hosts resumed on the second connection. The
exception was github.com, which did not resume.

`info()` stays valid after `Failure::Certificate`. The handshake completed and only our offline chain
check rejected the peer, so a study still gets the TLS facts for sites with bad certificates.

## Schannel quirks seen on the wire

- **Schannel sends three key shares, for the first three groups in the list.**
  - Default list: x25519 (32 B), P-256 (65 B), P-384 (97 B). The ClientHello is 428–448 B.
  - With PQ first: X25519MLKEM768 (1216 B), x25519, P-256. The P-384 share is dropped, and the
    ClientHello is 1549–1569 B.

  So a server without PQ still finds an x25519 share and never needs a HelloRetryRequest. We saw no
  HRR on any host.
- The PQ ClientHello is larger than a 1460-byte MSS, so it takes **two TCP segments**. None of the
  48 test hosts failed because of it. Older middleboxes that expect the whole ClientHello in the
  first segment are the documented risk. The 1M-site study is where that would show up, and
  `post_quantum = false` is the control.
- **Group names in `CRYPTO_SETTINGS` are case-sensitive.**
  - `X25519_MLKEM768` (as configured) worked. `x25519_mlkem768` (the Learn table spelling),
    `X25519MLKEM768`, `ML-KEM`, `Composite-ML-KEM` and `MLKEM` were silently ignored.
  - Classical groups use `curve25519`, `ECDH_P256` and `ECDH_P384`. `NistP256` is ignored.
  - Unknown names never fail the credential, so wincrawl lists both spellings of every ML-KEM group.
    Only `X25519_MLKEM768` could be verified, because the others are not enabled.
- **The loopback Schannel server**, which uses the same machine list:
  - TLS 1.3 picks X25519MLKEM768.
  - With the hybrid disabled, it picks **secp384r1** over x25519 for both TLS 1.3 and TLS 1.2. The
    server's own preference wins even though x25519 is first in the list. That is why the tests
    and benchmarks disable P-384/P-256 on the server side when they want x25519.

## Measurements

### Live A/B

Setup:
- Throwaway tool, built on `wc_tls` with `Verify::Chain`.
- 48 hosts, 5 full handshakes per host per run, and the median taken.
- Two PQ runs alternated with two non-PQ runs; the two medians are averaged.
- Home connection, about 15 ms RTT to most CDNs.
- "Handshake" runs from sending the ClientHello to Established, including the chain check.

| | PQ on | PQ off |
|---|---|---|
| hosts negotiating X25519MLKEM768 | 42 / 48 | 0 / 48 |
| failures | 0 | 0 |
| ClientHello bytes | 1549–1569 | 428–448 |
| median handshake, 42 PQ-capable hosts | 27.0 ms | 25.5 ms |
| median per-host delta (PQ − classic) | +0.9 ms (+3.2 %) | |
| median TCP connect (control) | 16.8 ms | 17.1 ms |

- **Hybrid negotiated:** cloudflare.com, www.cloudflare.com, pq.cloudflareresearch.com,
  discord.com, www.google.com, youtube.com, the Meta properties, both Amazon hosts, www.apple.com,
  www.microsoft.com, www.bing.com, www.linkedin.com, www.akamai.com, www.fastly.com, www.reddit.com,
  x.com, www.yahoo.com, www.twitch.tv, www.bbc.co.uk, www.nytimes.com, www.cnn.com,
  stackoverflow.com, example.com, www.mozilla.org, www.debian.org, www.kernel.org,
  www.openssl.org, www.ietf.org, www.python.org, www.gov.uk, www.usa.gov, www.tamu.edu,
  www.ebay.com, www.paypal.com, www.adobe.com, www.oracle.com, www.ibm.com, www.salesforce.com,
  www.cisco.com.
- **Classical only:** github.com, www.wikipedia.org, www.netflix.com, www.qq.com and ya.ru use x25519.
  www.baidu.com uses TLS 1.2 with secp256r1.

The +3 % median matches Microsoft's "3–6 % latency" figure. Per-host deltas are mostly within the
run-to-run noise of a home connection.

### CPU cost

Setup: in memory, client and loopback server in one thread, TLS 1.3, 300 handshakes per run, three
runs per mode, release build. The server is limited to x25519 or the hybrid, so the comparison is
x25519 vs X25519MLKEM768.

| | X25519MLKEM768 | x25519 |
|---|---|---|
| `start()`, building the ClientHello | 0.65–0.95 ms | 1.0–1.3 ms |
| full handshake, client + server | 2.2–3.3 ms | 2.7–3.4 ms |

PQ is not more expensive here. The classical ClientHello carries a P-384 share, and generating it
costs more than the ML-KEM-768 keypair that replaces it. Most of these milliseconds are the LSASS
round trips that every Schannel call makes, not the cryptography.

## Tests

`src/tls/tests`:
- `tls_tests` checks `info()` against the ServerHello / ServerKeyExchange bytes. Cases: TLS 1.3 and
  1.2; a server forced to secp256r1; a hybrid-only server, which is skipped with a message when the
  machine offers no ML-KEM group; resumption for both versions; and a certificate failure.
- `tls_tests` also checks that `post_quantum_available()` matches the `supported_groups` in our own
  ClientHello.
- `tls_nopq_tests` is a separate process, because the options are process-wide. It checks that
  `post_quantum = false` leaves no ML-KEM group in `supported_groups` or `key_share`, and that the
  handshake negotiates a classical group.

On a machine without the setting, such as a CI runner, every test still passes. The hybrid-only
case reports itself as skipped.
