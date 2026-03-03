# Versioning Strategy

## Overview

Each SDK package is versioned **independently** using [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Packages may have different version numbers at any given time since they can evolve at different rates.

## What Ties the Packages Together

All five SDKs implement the same **metagraph signing protocol** defined by the [metakit](https://github.com/Constellation-Labs/metakit) framework. This protocol is distinct from the tessellation (hypergraph/L0) signing protocol:

| | Metakit (Metagraph) | Tessellation (Hypergraph) |
|---|---|---|
| Serialization | **RFC 8785 JSON Canonicalization** | JSON + Brotli compression |
| Hashing | SHA-256 of canonical UTF-8 bytes | SHA-256 of Brotli-compressed bytes |
| Signing | ECDSA secp256k1 | ECDSA secp256k1 (same) |

The ECDSA curve and signing algorithm are identical, but the **serialization differs** — metakit uses RFC 8785 canonicalization while tessellation uses Brotli compression. Having a dedicated SDK for metagraph development keeps it lightweight and decoupled from the tessellation release lifecycle.

Compatibility across the five SDKs is enforced by:

1. **Shared test vectors** in `/shared/test_vectors.json` and `/shared/currency_transaction_vectors.json`, generated from the Scala metakit reference implementation
2. **Cross-language CI** that validates all five SDKs produce identical outputs for the same inputs
3. **Protocol version** embedded in the test vectors (currently v2 for currency transactions)

A signature produced by any SDK at any version will verify correctly in any other SDK, as long as both implement the same protocol version.

## Versioning Rules

### Patch (0.0.x)
- Bug fixes
- Performance improvements
- Documentation updates
- Dependency updates that don't affect behavior

### Minor (0.x.0)
- New features (e.g., new network client methods, new utility functions)
- New optional fields on existing types
- Non-breaking additions to the public API

### Major (x.0.0)
- Breaking API changes (e.g., function signature changes, removed exports)
- Protocol version changes (e.g., v2 -> v3 transaction format)
- Dependency changes that affect the public interface

## Protocol Versions

### Currency Transaction Format

| Version | Description | Serialization |
|---------|-------------|---------------|
| v2 | Current format | Kryo with `setReferences=false`, length-prefixed encoding starting with `"2"` prefix |

The v2 format is the only supported format. There is no v1 in the SDK — v1 was an internal format that predates the SDK.

If a v3 format is introduced, the SDK will:
1. Add v3 support alongside v2 in a minor release
2. Default to v3 in a subsequent major release
3. Deprecate v2 with a migration period

### Data Signing Protocol

The signing protocol (`SECP256K1_RFC8785_V1`) consists of:
1. RFC 8785 JSON canonicalization
2. SHA-256 hash of canonical JSON (or DataUpdate-encoded bytes)
3. SHA-512 of the hash hex treated as UTF-8 bytes (not hex-decoded)
4. Truncation to 32 bytes
5. ECDSA secp256k1 signing with low-S normalization

This protocol is stable and versioned by the `ALGORITHM` constant. A protocol change would require a new algorithm identifier.

## Tag Format

Each language uses a tag prefix for release automation:

| Language | Tag Format | Example | Notes |
|----------|------------|---------|-------|
| TypeScript | `typescript-vX.Y.Z` | `typescript-v0.2.0` | Triggers npm publish |
| Python | `python-vX.Y.Z` | `python-v0.1.1` | Triggers PyPI publish |
| Rust | `rust-vX.Y.Z` | `rust-v0.1.0` | Triggers crates.io publish |
| Go | `packages/go/vX.Y.Z` | `packages/go/v0.1.0` | Required by Go module proxy for nested modules |
| Java | `java-vX.Y.Z` | `java-v0.1.0` | Triggers Maven Central publish |

**Go note:** Go modules in a monorepo subdirectory require tags matching the module's path relative to the repo root. Since the module path is `github.com/Constellation-Labs/metakit-sdk/packages/go`, tags must use the `packages/go/vX.Y.Z` format for `go get` to work correctly.

## Version Files

| Language | File | Field |
|----------|------|-------|
| TypeScript | `packages/typescript/package.json` | `"version"` |
| Python | `packages/python/pyproject.toml` | `version` |
| Rust | `packages/rust/Cargo.toml` | `version` |
| Go | (tag only) | N/A |
| Java | `packages/java/pom.xml` | `<version>` |

## Cross-Language Compatibility

When a protocol change affects all SDKs:
1. Update the shared test vectors first
2. Implement the change in all five SDKs
3. Verify cross-language CI passes
4. Release all five packages (versions don't need to match)

Feature additions (e.g., new utility functions) can be released per-package without coordinating across languages.

## Changelog

Each package maintains its own `CHANGELOG.md` following the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Update the changelog as part of every PR that changes package behavior.
