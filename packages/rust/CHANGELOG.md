# Changelog

All notable changes to the Rust SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0-rc.7] - 2026-07-01

Aligned with the metakit `1.8.x` reference line
(`io.constellationnetwork:metakit_2.13:1.8.0-rc.7`). Released together with the
rest of the SDK by the unified `v*` tag.

### Added
- `committed_roots` module: `CommittedRoots`, `CommittedBreadcrumb`, and
  `CommitKey` (validated newtype + `to_hex` MPT path), plus
  `CommittedRoots::combined_hash` — the roots-only light-client verification
  surface, byte-aligned with the Scala `CommittedRootsCodecKatSuite`. See
  `docs/committed-roots.md`.

## [0.2.0] - 2026-05-08

Initial crates.io release. Version aligned with the TypeScript SDK at 0.2.0; there is no 0.1.0 published on crates.io.

### Added
- Published as `constellation-metagraph-sdk` on crates.io
- Data transaction signing and verification (standard and DataUpdate modes)
- Currency transaction creation, signing, and verification (v2 format)
- Multi-signature support via `add_signature` and `batch_sign`
- Wallet utilities: key generation, address derivation, key validation
- Optional secp256r1 (NIST P-256) signing under the `r1` cargo feature, exposed via the `r1::` submodule (`r1::sign`, `r1::verify`, `r1::wallet`, `r1::signed_object`). Note: cross-language interop for R1 is Rust-only at this release.
- Optional metagraph network clients behind the `network` feature flag
- Cross-language compatibility (K1) with TypeScript, Python, Go, and Java SDKs

### Fixed
- `HttpClient::new` now rejects empty `base_url` with a `ConfigError` instead of silently building an unusable client.
