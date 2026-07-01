# Changelog

All notable changes to `@constellation-network/metagraph-sdk-core` (the offline
signing kernel) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0-rc.7] - 2026-07-01

Released together with the rest of the SDK by the unified `v*` tag; the version
tracks metakit's `1.8.x` line. Prereleases publish to the npm `next` dist-tag.

### Added
- Committed-roots light-client codecs (`CommittedRoots`, `CommittedBreadcrumb`,
  `CommitKey`) and `committedRootsCombinedHash()`, byte-aligned to the metakit
  Scala reference (`CommittedRootsCodecKatSuite`). See `docs/committed-roots.md`.

### Notes
- This package is the fully offline signing/canonicalization kernel
  (`@constellation-network/metagraph-sdk` re-exports it and adds the currency
  and network layers). No JLVM — see `@constellation-network/metagraph-sdk-jlvm`.

## [1.8.0-rc.3] - 2026-06

First independent publish of the core kernel after the TypeScript monolith was
split into three packages (`-core`, `-jlvm`, and the full `metagraph-sdk`).

### Added
- Extracted the offline signing kernel from `@constellation-network/metagraph-sdk`:
  canonicalization (`canonicalize`, `dropNullFields`), byte encoding
  (`toBytes`, `encodeDataUpdate`, `decodeDataUpdate`), hashing, ECDSA
  sign/verify (`sign`, `signDataUpdate`, `signHash`, `verify*`), signed-object
  helpers (`createSignedObject`, `addSignature`, `batchSign`), and the
  `wallet` / `data` namespaces.
- Native crypto via `@noble/curves` (secp256k1) and `@noble/hashes`.
