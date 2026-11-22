# Monocypher 4.0.3 (Ed25519 subset)

Ed25519 signing and verification for `src/sig/` (Web Bot Auth). Windows CNG
has no Ed25519 signature algorithm (checked on Windows 11 build 26200:
`BCryptOpenAlgorithmProvider` knows no EdDSA/Ed25519 name, and ECDSA with
`BCRYPT_ECC_CURVE_25519` returns `STATUS_NOT_SUPPORTED`; curve25519 is ECDH
only), so a small audited implementation is vendored instead.

- Upstream: https://monocypher.org/ (https://github.com/LoupVaillant/Monocypher)
- Release: 4.0.3 (2026-06-15), `monocypher-4.0.3.tar.gz`,
  SHA-256 `8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`
  (identical from monocypher.org/download and the GitHub release asset).
  4.0.3 fixes a timing leak in EdDSA/Ed25519 signing present in 4.0.2.
- Licence: dual BSD-2-Clause / CC0-1.0, see `LICENCE.md`.
- Files, byte-for-byte from the tarball (only the directory layout is
  flattened; `monocypher-ed25519.h` includes `"monocypher.h"` by name, so no
  edit was needed):

  | File | Tarball path | SHA-256 |
  |---|---|---|
  | `monocypher.c` | `src/monocypher.c` | `57eb914fc88136119bd41655cccb8c250048bf54d470540625186f8ab16f64be` |
  | `monocypher.h` | `src/monocypher.h` | `c494da712122da7ff679fdcf318a5317e84972b6c950fe9d896212947797facd` |
  | `monocypher-ed25519.c` | `src/optional/monocypher-ed25519.c` | `60fce3578fb00b00da96490653d993c4cb427b1e1be38183285c66e04d22cc18` |
  | `monocypher-ed25519.h` | `src/optional/monocypher-ed25519.h` | `abc4fad381879f5c29176ebe014b9189956b3dfe0a3e36459b6990bc57212380` |

`src/sig/CMakeLists.txt` compiles the two `.c` files as C++ (so the fuzz
preset instruments them with the same clang-cl flags as everything else) with
`MONOCYPHER_CPP_NAMESPACE=wc_monocypher`, which upstream provides to put the
API in a C++ namespace instead of `extern "C"`. They build clean at `/W4`
under MSVC and clang-cl. Only `wc::sig` calls them; RFC 8032 §7.1 vectors in
`src/sig/tests/` check the result.
