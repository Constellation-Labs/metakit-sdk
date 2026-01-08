# Constellation Metagraph SDK - Rust

Rust SDK for signing data transactions on Constellation Network data metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Note:** This SDK is for data transactions only. It implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
constellation-metagraph-sdk = "0.1"
```

Or use cargo:

```bash
cargo add constellation-metagraph-sdk
```

## Quick Start

```rust
use constellation_sdk::{
    wallet::generate_key_pair,
    signed_object::create_signed_object,
    verify::verify,
};
use serde_json::json;

fn main() {
    // Generate a key pair
    let key_pair = generate_key_pair();
    println!("Address: {}", key_pair.address);

    // Sign data
    let data = json!({ "action": "UPDATE", "payload": { "key": "value" } });
    let signed = create_signed_object(&data, &key_pair.private_key, false).unwrap();

    // Verify
    let result = verify(&signed, false);
    println!("Valid: {}", result.is_valid);
}
```

## API Reference

### High-Level API

#### `create_signed_object(value, private_key, is_data_update) -> Result<Signed<T>>`

Create a signed object with a single signature.

```rust
let signed = create_signed_object(&data, &private_key, false)?;

// For L1 submission (DataUpdate)
let signed = create_signed_object(&data, &private_key, true)?;
```

#### `add_signature(signed, private_key, is_data_update) -> Result<Signed<T>>`

Add an additional signature to an existing signed object.

```rust
let mut signed = create_signed_object(&data, &party1_key, false)?;
signed = add_signature(&signed, &party2_key, false)?;
// signed.proofs.len() == 2
```

#### `batch_sign(value, private_keys, is_data_update) -> Result<Signed<T>>`

Create a signed object with multiple signatures at once.

```rust
let signed = batch_sign(&data, &[key1, key2, key3], false)?;
// signed.proofs.len() == 3
```

#### `verify(signed, is_data_update) -> VerificationResult`

Verify all signatures on a signed object.

```rust
let result = verify(&signed, false);
if result.is_valid {
    println!("All signatures valid");
} else {
    println!("Invalid proofs: {:?}", result.invalid_proofs);
}
```

### Low-Level Primitives

#### `canonicalize(data) -> Result<String>`

Canonicalize JSON data according to RFC 8785.

```rust
let canonical = canonicalize(&json!({"b": 2, "a": 1}))?;
// "{\"a\":1,\"b\":2}"
```

#### `to_bytes(data, is_data_update) -> Result<Vec<u8>>`

Convert data to binary bytes for signing.

```rust
// Regular encoding
let bytes = to_bytes(&data, false)?;

// DataUpdate encoding (with Constellation prefix)
let bytes = to_bytes(&data, true)?;
```

#### `hash_data(data) -> Result<Hash>` / `hash_bytes(bytes) -> Hash`

Compute SHA-256 hash.

```rust
let hash = hash_data(&data)?;
println!("{}", hash.value);  // 64-char hex
println!("{:?}", hash.bytes); // [u8; 32]
```

#### `sign(data, private_key)` / `sign_data_update(data, private_key)`

Sign data and return a proof.

```rust
let proof = sign(&data, &private_key)?;
// SignatureProof { id: "...", signature: "..." }
```

#### `sign_hash(hash_hex, private_key) -> Result<String>`

Sign a pre-computed hash.

```rust
let hash = hash_data(&data)?;
let signature = sign_hash(&hash.value, &private_key)?;
```

### Wallet Utilities

#### `generate_key_pair() -> KeyPair`

Generate a new random key pair.

```rust
let key_pair = generate_key_pair();
// KeyPair { private_key, public_key, address }
```

#### `key_pair_from_private_key(private_key) -> Result<KeyPair>`

Derive a key pair from an existing private key.

```rust
let key_pair = key_pair_from_private_key(&existing_private_key)?;
```

#### `get_public_key_id(private_key) -> Result<String>`

Get the public key ID (128 chars, no 04 prefix) for use in proofs.

```rust
let id = get_public_key_id(&private_key)?;
```

## Types

```rust
pub struct SignatureProof {
    pub id: String,        // Public key (128 chars)
    pub signature: String, // DER signature hex
}

pub struct Signed<T> {
    pub value: T,
    pub proofs: Vec<SignatureProof>,
}

pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
    pub address: String,
}

pub struct Hash {
    pub value: String,     // 64-char hex
    pub bytes: [u8; 32],   // 32 bytes
}

pub struct VerificationResult {
    pub is_valid: bool,
    pub valid_proofs: Vec<SignatureProof>,
    pub invalid_proofs: Vec<SignatureProof>,
}
```

## Usage Examples

### Submit DataUpdate to L1

```rust
use constellation_sdk::{
    wallet::generate_key_pair,
    signed_object::create_signed_object,
};
use serde_json::json;

let data_update = json!({
    "action": "TRANSFER",
    "from": "address1",
    "to": "address2",
    "amount": 100
});

// Sign as DataUpdate
let signed = create_signed_object(&data_update, &private_key, true)?;

// Submit to data-l1 (using your HTTP client)
// POST http://l1-node:9300/data with signed as JSON body
```

### Multi-Signature Workflow

```rust
use constellation_sdk::{
    signed_object::{create_signed_object, add_signature},
    verify::verify,
};

// Party 1 creates and signs
let mut signed = create_signed_object(&data, &party1_key, false)?;

// Party 2 adds signature
signed = add_signature(&signed, &party2_key, false)?;

// Party 3 adds signature
signed = add_signature(&signed, &party3_key, false)?;

// Verify all signatures
let result = verify(&signed, false);
println!("{} valid signatures", result.valid_proofs.len());
```

## Development

```bash
# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Check for issues
cargo clippy

# Format code
cargo fmt

# Build release
cargo build --release
```

## License

Apache-2.0
