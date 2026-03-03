# Changelog

All notable changes to the TypeScript SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `SigningMode` type (`'standard' | 'dataUpdate'`) and optional `mode` field on `Signed<T>` for self-describing signed objects
- `verify()` auto-detects signing mode from `signed.mode` when present
- Namespaced exports: `wallet`, `data`, `currency`, `network`, `jlvm` for cleaner imports
- `currency` namespace provides shorter aliases (e.g., `currency.createTransaction` instead of `createCurrencyTransaction`)
- `MetagraphClient.transfer()` — high-level method that fetches last ref, signs, and submits in one call (CL1 layer)
- `MetagraphClient.transferBatch()` — sequential transfers with automatic reference chaining (CL1 layer)
- `TransferResult` type with hash, transaction, and chaining reference
- Native crypto implementation using `@noble/curves` (secp256k1) and `@noble/hashes` (SHA-256, SHA-512)
- `src/crypto.ts` — centralized cryptographic primitives
- `src/transaction-encoding.ts` — native Kryo serialization and transaction encoding

### Changed
- **BREAKING**: All signing and verification functions are now **synchronous** (previously async due to dag4 dependency)
  - Affected: `sign`, `signDataUpdate`, `signHash`, `verify`, `verifyHash`, `verifySignature`, `createSignedObject`, `addSignature`, `batchSign`, `createCurrencyTransaction`, `createCurrencyTransactionBatch`, `signCurrencyTransaction`, `verifyCurrencyTransaction`, `hashCurrencyTransaction`, `getTransactionReference`
- `toBytes()`, `hashData()`, `computeDigest()` now accept `SigningMode | boolean` (backward compatible)
- `createSignedObject`, `addSignature`, `batchSign` accept `{ mode: 'dataUpdate' }` in addition to legacy `{ isDataUpdate: true }`
- Network clients (`checkHealth()`) now only catch `NetworkError`, re-throwing unexpected errors
- `HttpClient` now throws `NetworkError` on unparseable JSON responses instead of silently returning raw text

### Removed
- **BREAKING**: Removed `@stardust-collective/dag4` and `@stardust-collective/dag4-keystore` dependencies
- Removed `js-sha256` and `js-sha512` dependencies
- Removed `normalizeSignatureToLowS` export (low-S normalization is now handled internally by `@noble/curves`)

### Dependencies
- Added `@noble/curves` ^1.8.0
- Added `@noble/hashes` ^1.7.0
- Added `bs58` ^6.0.0

## [0.1.0] - 2025-05-01

### Added
- Initial release
- Data transaction signing and verification (standard and DataUpdate modes)
- Currency transaction creation, signing, and verification (v2 format)
- Multi-signature support via `addSignature` and `batchSign`
- Wallet utilities: key generation, address derivation, key validation
- Network client: `MetagraphClient` with layer-based routing (ML0, CL1, DL1)
- Cross-language compatibility with Python, Rust, Go, and Java SDKs
- JSON Logic VM with 60+ operators and gas metering
