# Changelog

All notable changes to the Java SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-05-01

### Added
- Initial release
- Data transaction signing and verification (standard and DataUpdate modes)
- Currency transaction creation, signing, and verification (v2 format)
- Multi-signature support via `addSignature` and `batchSign`
- Wallet utilities: key generation, address derivation, key validation
- Network clients: `CurrencyL1Client` and `DataL1Client`
- Cross-language compatibility with TypeScript, Python, Rust, and Go SDKs
