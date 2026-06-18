# Constellation Metagraph SDK

Multi-language SDK for Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:**
> - Data transactions for metakit-based metagraphs
> - Currency transactions (metagraph token transfers)
> - Network operations for L1 node interactions
> - **Compatibility:** This SDK implements metakit's standardized serialization and may not be compatible with data metagraphs using custom routines.

[![CI](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@constellation-network/metagraph-sdk.svg)](https://www.npmjs.com/package/@constellation-network/metagraph-sdk)
[![PyPI version](https://img.shields.io/pypi/v/constellation-metagraph-sdk.svg)](https://pypi.org/project/constellation-metagraph-sdk/)
[![Crates.io](https://img.shields.io/crates/v/constellation-metagraph-sdk.svg)](https://crates.io/crates/constellation-metagraph-sdk)

## Packages

| Language | Package | Documentation |
|----------|---------|---------------|
| TypeScript | [@constellation-network/metagraph-sdk](https://www.npmjs.com/package/@constellation-network/metagraph-sdk) | [README](./packages/typescript/README.md) |
| Python | [constellation-metagraph-sdk](https://pypi.org/project/constellation-metagraph-sdk/) | [README](./packages/python/README.md) |
| Rust | [constellation-metagraph-sdk](https://crates.io/crates/constellation-metagraph-sdk) | [README](./packages/rust/README.md) |
| Go | [github.com/Constellation-Labs/metakit-sdk/packages/go](https://pkg.go.dev/github.com/Constellation-Labs/metakit-sdk/packages/go) | [README](./packages/go/README.md) |
| Java | [io.constellationnetwork:metagraph-sdk](https://central.sonatype.com/artifact/io.constellationnetwork/metagraph-sdk) | [README](./packages/java/README.md) |

## Features

- **Data Transactions** - Sign and verify data for metakit-based metagraphs with multi-signature support
- **Currency Transactions** - Create, sign, and verify metagraph token transfers
- **Network Operations** - Submit transactions and query L1 nodes (Currency L1 and Data L1)
- **Cryptography** - ECDSA on secp256k1, SHA-256/SHA-512 hashing, DER signature encoding
- **Cross-SDK Compatibility** - All implementations produce identical results, validated against shared test vectors

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

All SDKs are validated against shared test vectors in `/shared/test_vectors.json`. This ensures:

- Canonicalization produces identical output across all languages
- Hashing produces identical digests
- Signatures created in one language verify in all others

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
