# constellation-metagraph-sdk-core

The fully-offline kernel of the [Constellation Metagraph SDK] for Rust.

This crate is the Rust counterpart of the `metagraph-sdk-core` TypeScript
package in the SDK's 3-tier packaging model. It contains everything needed to
sign and verify metagraph data **without any network dependency**:

- **RFC 8785 canonicalization** — deterministic JSON serialization
- **SHA-256 hashing** and binary `DataUpdate` encoding
- **ECDSA signing / verification**
  - secp256k1 (K1) — always available
  - secp256r1 / P-256 (R1) — behind the `r1` cargo feature (TPM-native curve)
- **Committed-roots** light-client codecs, byte-aligned with the metakit reference

Higher tiers — currency transactions and the metagraph network client — live in
the [`constellation-metagraph-sdk`] crate, which re-exports this crate so
existing `constellation_sdk::*` paths keep working unchanged.

## Quick start

```rust
use constellation_sdk_core::{
    wallet::generate_key_pair,
    signed_object::create_signed_object,
    verify::verify,
};
use serde_json::json;

let key_pair = generate_key_pair();
let data = json!({"action": "transfer", "amount": 100});
let signed = create_signed_object(&data, &key_pair.private_key, false).unwrap();
assert!(verify(&signed, false).is_valid);
```

## Cargo features

| Feature | Default | Effect |
| ------- | ------- | ------ |
| `r1`    | off     | Enables secp256r1 (P-256) signing via `constellation_sdk_core::r1`. Pulls in the `p256` / `ecdsa` / `elliptic-curve` dep tree. |

## License

Apache-2.0

[Constellation Metagraph SDK]: https://github.com/Constellation-Labs/metakit-sdk
[`constellation-metagraph-sdk`]: https://crates.io/crates/constellation-metagraph-sdk
