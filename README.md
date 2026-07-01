# Constellation Metagraph SDK

Multi-language SDK for Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:**
> - Data transactions for metakit-based metagraphs
> - Currency transactions (metagraph token transfers)
> - Network operations for L1 node interactions
> - **Compatibility:** This SDK implements metakit's standardized serialization and may not be compatible with data metagraphs using custom routines.

[![CI](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@constellation-network/metagraph-sdk/next.svg?label=npm%40next)](https://www.npmjs.com/package/@constellation-network/metagraph-sdk)
[![PyPI version](https://img.shields.io/pypi/v/constellation-metagraph-sdk.svg?include_prereleases)](https://pypi.org/project/constellation-metagraph-sdk/)
[![Crates.io](https://img.shields.io/crates/v/constellation-metagraph-sdk.svg)](https://crates.io/crates/constellation-metagraph-sdk)

## Packages & coverage

The SDK spans two capability layers, ported to different language sets:

- **Signing SDK** — canonicalization (RFC 8785 + `dropNulls`), hashing, ECDSA on secp256k1 (plus optional secp256r1/R1), DER encoding, data- and currency-transaction encoding, and L1 network clients. Byte-compatible with the Constellation `tessellation-sdk` reference.
- **JLVM** — the [metakit](https://github.com/Constellation-Labs/metakit) JSON-Logic VM: base opcodes **and** the full zero-knowledge / auth-DB opcode suite (Poseidon, Merkle/SMT/MPT inclusion & prefix proofs, BN254, BLS, Groth16, ECVRF, Schnorr, and Σ-protocols). Byte-for-byte parity with the Scala reference.

| Language | Package | Signing SDK | JLVM (base + ZK) | Published |
|----------|---------|:-----------:|:----------------:|-----------|
| TypeScript | [`@constellation-network/metagraph-sdk`](https://www.npmjs.com/package/@constellation-network/metagraph-sdk) (+ [`-core`](https://www.npmjs.com/package/@constellation-network/metagraph-sdk-core), [`-jlvm`](https://www.npmjs.com/package/@constellation-network/metagraph-sdk-jlvm)) | ✅ | ✅ | npm ([`@next`](https://www.npmjs.com/package/@constellation-network/metagraph-sdk?activeTab=versions)) |
| Rust | [`constellation-metagraph-sdk`](https://crates.io/crates/constellation-metagraph-sdk) (+ [`-jlvm`](https://crates.io/crates/constellation-metagraph-sdk-jlvm), [`-poseidon-bn254`](https://crates.io/crates/constellation-metagraph-sdk-poseidon-bn254)) | ✅ | ✅ | [crates.io](https://crates.io/crates/constellation-metagraph-sdk) |
| Python | [`constellation-metagraph-sdk`](https://pypi.org/project/constellation-metagraph-sdk/) | ✅ | — | [PyPI](https://pypi.org/project/constellation-metagraph-sdk/) |
| Go | [`packages/go`](./packages/go/README.md) | ✅ | — | not yet published |
| Java | [`packages/java`](./packages/java/README.md) | ✅ | — | not yet published |

> **The JLVM ships in TypeScript and Rust only.** Python, Go, and Java implement the **signing SDK** — they produce byte-identical canonical bytes, digests, and signatures — but not the JSON-Logic VM. Go and Java are complete signing SDKs that are not yet wired into the unified release train (they remain at `0.1.0`); track them via `packages/{go,java}/CHANGELOG.md`.
>
> **Reference alignment:** this SDK tracks metakit's `1.8.x` line and is currently byte-aligned to [`io.constellationnetwork:metakit_2.13:1.8.0-rc.7`](https://central.sonatype.com/artifact/io.constellationnetwork/metakit_2.13) (the Scala reference implementation).
>
> **Prerelease install:** the `1.8.0-rc.*` line publishes to npm's `next` dist-tag and as PyPI/crates prereleases — use `npm install @constellation-network/metagraph-sdk@next`, `pip install --pre constellation-metagraph-sdk`, or pin `constellation-metagraph-sdk = "=1.8.0-rc.7"` on crates.io. (`npm install` without `@next` still resolves the older stable `latest`.)

## Features

- **Data Transactions** - Sign and verify data for metakit-based metagraphs with multi-signature support
- **Currency Transactions** - Create, sign, and verify metagraph token transfers
- **Network Operations** - Submit transactions and query L1 nodes (Currency L1 and Data L1)
- **Cryptography** - ECDSA on secp256k1 (+ optional secp256r1/R1), SHA-256/SHA-512 hashing, DER signature encoding
- **JLVM (TypeScript + Rust)** - the metakit JSON-Logic VM with the full ZK / auth-DB opcode suite, byte-for-byte parity with the Scala reference
- **Cross-SDK Compatibility** - every signing-SDK implementation produces identical canonical bytes, digests, and signatures; the TS and Rust JLVMs additionally reproduce the metakit opcode vectors byte-for-byte — all validated against the shared test vectors

## Installation & Usage

See the package-specific READMEs for installation instructions and API documentation:

- **[TypeScript](./packages/typescript/README.md)** - Node.js and browser support
- **[Python](./packages/python/README.md)** - Python 3.10+
- **[Rust](./packages/rust/README.md)** - Safe and performant
- **[Go](./packages/go/README.md)** - Simple and efficient
- **[Java](./packages/java/README.md)** - JVM 11+

## Development

### Prerequisites

- Node.js 18+ (TypeScript)
- Python 3.10+ (Python)
- Rust 1.70+ (Rust)
- Go 1.18+ (Go)
- Java 11+ and Maven 3.8+ (Java)
- Make (standard on Linux/macOS)

### Setup

```bash
git clone https://github.com/Constellation-Labs/metakit-sdk.git
cd metakit-sdk

make install          # Install all dependencies
make test             # Run all tests
make lint             # Lint all packages
make format           # Format all code
make help             # Show all available commands
```

## Cross-Language Compatibility

All SDKs are validated against shared vectors in [`/shared`](./shared). Metakit (Scala) is the reference; the shared vectors are the cross-language source of truth (also vendored into the metakit test suite), and each port must reproduce every `expected` byte-for-byte.

- **Signing** (`test_vectors.json`, `currency_transaction_vectors.json`) — every language (TypeScript, Rust, Python, Go, Java) reproduces the same canonical bytes and digests, and a signature created in one language verifies in all others.
- **JLVM** (`json_logic_test_vectors.json`, `zk_opcode_test_vectors.json`, `gas_test_vectors.json`) — TypeScript and Rust reproduce every opcode result byte-for-byte, including all ZK / auth-DB and Σ-protocol opcodes and gas costs.

Vector files carry their own protocol versions (base JLVM `1.6.0`, ZK opcodes `1.12.0`, gas `1.2.0`) independent of the SDK release version.

## Releasing

A single `vX.Y.Z` tag publishes TypeScript (npm), Rust (crates.io), and Python
(PyPI) together at the same version:

```bash
git tag -a v1.8.0-rc.1 -m "SDK v1.8.0-rc.1"
git push origin v1.8.0-rc.1
```

See [docs/RELEASING.md](./docs/RELEASING.md) for the full release flow and
[docs/PUBLISHING.md](./docs/PUBLISHING.md) for registry-account setup.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

Apache-2.0
