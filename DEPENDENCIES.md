# Dependency policy

All cryptography comes from established open-source libraries. Hand-rolled
crypto is forbidden in this project. This file records exact pins, the audit
basis, and how to upgrade.

## Pin table (verified 2026-09-07; all latest stable at that date)

| Library | Pin | Commit | License | Sourced via | Used for |
|---|---|---|---|---|---|
| libsecp256k1 (bitcoin-core) | v0.8.0 | 18f07c422187 | MIT | FetchContent source build | ECDSA sign/verify/keygen |
| libargon2 reference (PHC) | 20190702 | 62358ba2123a | CC0/Apache-2.0 | FetchContent source build | Argon2id PoW + wallet KDF |
| OpenSSL | OS package / vcpkg | n/a (see below) | Apache-2.0 | system package, vcpkg on Windows CI | SHA256, RIPEMD160, AES-256-GCM, CSPRNG |
| nlohmann/json | v3.12.0 | release tarball | MIT | FetchContent URL | RPC + wallet JSON (text parser only) |
| standalone Asio | asio-1-38-2 | 12b52a54a25d | BSL-1.0 | FetchContent headers | dual-stack TCP transport |
| doctest | v2.5.3 | 2d0a9359a60c | MIT | FetchContent | test framework (dev only) |
| Qt6 | system / vcpkg, optional | n/a | LGPL | system package | GUI wallet (optional) |

## CVE audit (2026-09-07)

- secp256k1 C library: no CVEs on record. Public hits refer to other
  products (npm `secp256k1-node` binding CVE-2024-48930, AMD Vitis, an
  experimental adaptor-signatures fork). We use plain ECDSA sign/verify
  only (no ECDH, no adaptors), so even related classes do not apply.
- argon2 reference: no CVEs on record. CVE-2026-8463 is the Perl binding's
  `argon2_verify` wrapper on empty input, not the C code; we call
  `argon2id_hash_raw` / `argon2id_ctx` with fixed non-empty buffers.
- nlohmann/json: latest. The open recursion issue (#5104) affects only the
  CBOR/MessagePack/UBJSON/BSON binary parsers; we use the text `parse()`
  (iterative) and every parse site catches exceptions (see fuzz_test).
- OpenSSL: recent CVEs (3.5.5 through 3.5.7 advisories) are all in
  TLS/PKCS#12/CMS/QUIC/OCB/CLI paths. We use only one-shot EVP digests
  (SHA256, RIPEMD160), AES-256-GCM, and RAND_bytes - none of the affected
  code paths. OS packages and vcpkg float to patched releases automatically.
- doctest/Asio: no crypto role (test framework / transport); pinned current.

## Sourcing rationale (system vs bundled)

- OpenSSL from OS packages (apt/brew) and vcpkg on Windows: security fixes
  must flow without a Coin release, so the most-attack-surfaced C library
  in the tree is never vendored.
- secp256k1 + argon2 built from pinned source: distro packages lag (or are
  missing) and consensus needs byte-exact code on every platform; pins move
  only deliberately (see below).
- json/doctest/asio header-only via FetchContent: zero build risk, trivial
  to audit, trivial to upgrade.

## Upgrade policy

- Version rule: latest stable release, one step behind bleeding edge for
  major lines (e.g. secp256k1 v0.8.x, not an rc). Patch releases are
  adopted promptly.
- Re-pinning: change `GIT_TAG` in CMakeLists.txt, update the commit column
  above (`git ls-remote <url> <tag>`), rebuild on all three CI platforms,
  run the full suite plus a live regtest (mine, transfer, sync), then push.
- Freshness: `.github/workflows/audit.yml` runs weekly and compares pins
  against upstream latest releases. It is informational (never red): when
  it reports a newer stable, file a task to re-pin following this policy.
- New CVE in a pinned lib: upgrade out of band the same day; consensus libs
  additionally get a chain-compat check (old blocks must still validate).
