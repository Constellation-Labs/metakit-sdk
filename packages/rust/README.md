# Constellation Metagraph SDK - Rust

Rust SDK for signing data and currency transactions on Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:** This SDK supports both data transactions (state updates) and metagraph token transactions (value transfers). It implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

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

### Data Transactions

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

### Currency Transactions

```rust
use constellation_sdk::{
    generate_key_pair,
    create_currency_transaction,
    verify_currency_transaction,
    TransferParams,
    TransactionReference,
};

fn main() {
    // Generate keys
    let sender = generate_key_pair();
    let recipient = generate_key_pair();

    // Create token transaction
    let tx = create_currency_transaction(
        TransferParams {
            destination: recipient.address,
            amount: 100.5,
            fee: 0.0,
        },
        &sender.private_key,
        TransactionReference {
            hash: "abc123...".to_string(),
            ordinal: 0,
        },
    ).unwrap();

    // Verify
    let result = verify_currency_transaction(&tx);
    println!("Valid: {}", result.is_valid);
}
```

## API Reference

### Data Transactions

#### High-Level API

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

### Currency Transactions

#### `create_currency_transaction(params, private_key, last_ref) -> Result<CurrencyTransaction>`

Create a metagraph token transaction.

```rust
use constellation_sdk::{create_currency_transaction, TransferParams, TransactionReference};

let tx = create_currency_transaction(
    TransferParams {
        destination: "DAG...recipient".to_string(),
        amount: 100.5,  // 100.5 tokens
        fee: 0.0,
    },
    &private_key,
    TransactionReference {
        hash: "abc123...".to_string(),
        ordinal: 5,
    },
)?;
```

#### `create_currency_transaction_batch(transfers, private_key, last_ref) -> Result<Vec<CurrencyTransaction>>`

Create multiple token transactions in a batch.

```rust
let transfers = vec![
    TransferParams { destination: "DAG...1".to_string(), amount: 10.0, fee: 0.0 },
    TransferParams { destination: "DAG...2".to_string(), amount: 20.0, fee: 0.0 },
    TransferParams { destination: "DAG...3".to_string(), amount: 30.0, fee: 0.0 },
];

let txns = create_currency_transaction_batch(
    transfers,
    &private_key,
    TransactionReference { hash: "abc123...".to_string(), ordinal: 5 },
)?;
```

#### `sign_currency_transaction(transaction, private_key) -> Result<CurrencyTransaction>`

Add an additional signature to a currency transaction (for multi-sig).

```rust
let mut tx = create_currency_transaction(params, &key1, last_ref)?;
tx = sign_currency_transaction(&tx, &key2)?;
// tx.proofs.len() == 2
```

#### `verify_currency_transaction(transaction) -> VerificationResult`

Verify all signatures on a currency transaction.

```rust
let result = verify_currency_transaction(&tx);
println!("Valid: {}", result.is_valid);
```

#### `hash_currency_transaction(transaction) -> Hash`

Hash a currency transaction.

```rust
let hash = hash_currency_transaction(&tx);
println!("Hash: {}", hash.value);
```

#### `get_transaction_reference(transaction, ordinal) -> TransactionReference`

Get a transaction reference for chaining transactions.

```rust
let tx_ref = get_transaction_reference(&tx, 6);
// Use tx_ref as last_ref for next transaction
```

#### Utility Functions

```rust
// Validate DAG address
is_valid_dag_address("DAG...");  // true/false

// Convert between token units and smallest units
token_to_units(100.5);    // 10050000000
units_to_token(10050000000);  // 100.5

// Token decimals constant
TOKEN_DECIMALS;  // 1e-8
```

### Network Operations

Enable the `network` feature in your `Cargo.toml`:

```toml
[dependencies]
constellation-metagraph-sdk = { version = "0.1", features = ["network"] }
```

#### `CurrencyL1Client`

Client for interacting with Currency L1 nodes.

```rust
use constellation_sdk::network::{CurrencyL1Client, NetworkConfig};

let config = NetworkConfig {
    l1_url: Some("http://localhost:9010".to_string()),
    timeout: Some(30),  // optional, defaults to 30s
    ..Default::default()
};

let client = CurrencyL1Client::new(config)?;

// Get last transaction reference for an address
let last_ref = client.get_last_reference("DAG...").await?;

// Submit a signed transaction
let result = client.post_transaction(&signed_tx).await?;
println!("Transaction hash: {}", result.hash);

// Check pending transaction status
if let Some(pending) = client.get_pending_transaction(&result.hash).await? {
    println!("Status: {:?}", pending.status);  // Waiting, InProgress, or Accepted
}

// Check node health
let is_healthy = client.check_health().await;
```

#### `DataL1Client`

Client for interacting with Data L1 nodes (metagraphs).

```rust
use constellation_sdk::network::{DataL1Client, NetworkConfig};

let config = NetworkConfig {
    data_l1_url: Some("http://localhost:8080".to_string()),
    ..Default::default()
};

let client = DataL1Client::new(config)?;

// Estimate fee for data submission
let fee_info = client.estimate_fee(&signed_data).await?;
println!("Fee: {}, Address: {}", fee_info.fee, fee_info.address);

// Submit signed data
let result = client.post_data(&signed_data).await?;
println!("Data hash: {}", result.hash);

// Check node health
let is_healthy = client.check_health().await;
```

#### Combined Configuration

```rust
let config = NetworkConfig {
    l1_url: Some("http://localhost:9010".to_string()),      // Currency L1
    data_l1_url: Some("http://localhost:8080".to_string()), // Data L1
    timeout: Some(30),
};

let l1_client = CurrencyL1Client::new(config.clone())?;
let data_client = DataL1Client::new(config)?;
```

#### Network Types

```rust
pub struct NetworkConfig {
    pub l1_url: Option<String>,       // Currency L1 endpoint
    pub data_l1_url: Option<String>,  // Data L1 endpoint
    pub timeout: Option<u64>,         // Request timeout in seconds
}

pub struct PostTransactionResponse {
    pub hash: String,
}

pub struct PendingTransaction {
    pub hash: String,
    pub status: TransactionStatus,  // Waiting, InProgress, Accepted
    pub transaction: CurrencyTransaction,
}

pub struct EstimateFeeResponse {
    pub fee: i64,
    pub address: String,
}

pub struct PostDataResponse {
    pub hash: String,
}

pub enum NetworkError {
    HttpError { message: String, status_code: Option<u16>, response: Option<String> },
    Timeout,
    ConfigError(String),
    SerializationError(String),
}
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

// Currency transaction types
pub struct TransactionReference {
    pub hash: String,      // 64-char hex transaction hash
    pub ordinal: i64,      // Transaction ordinal number
}

pub struct CurrencyTransactionValue {
    pub source: String,         // Source DAG address
    pub destination: String,    // Destination DAG address
    pub amount: i64,           // Amount in smallest units (1e-8)
    pub fee: i64,              // Fee in smallest units (1e-8)
    pub parent: TransactionReference,
    pub salt: String,          // Random salt for uniqueness
}

pub type CurrencyTransaction = Signed<CurrencyTransactionValue>;

pub struct TransferParams {
    pub destination: String,   // Destination DAG address
    pub amount: f64,          // Amount in token units (e.g., 100.5 tokens)
    pub fee: f64,             // Fee in token units (defaults to 0)
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

### Currency Transactions

#### Create and Verify Token Transaction

```rust
use constellation_sdk::{
    generate_key_pair,
    create_currency_transaction,
    verify_currency_transaction,
    TransferParams,
    TransactionReference,
};

// Generate keys
let sender_key = generate_key_pair();
let recipient_key = generate_key_pair();

// Get last transaction reference (from network or previous transaction)
let last_ref = TransactionReference {
    hash: "abc123...previous-tx-hash".to_string(),
    ordinal: 5,
};

// Create transaction
let tx = create_currency_transaction(
    TransferParams {
        destination: recipient_key.address.clone(),
        amount: 100.5,  // 100.5 tokens
        fee: 0.0,
    },
    &sender_key.private_key,
    last_ref,
)?;

// Verify
let result = verify_currency_transaction(&tx);
println!("Transaction valid: {}", result.is_valid);

// Note: Network submission not yet implemented in this SDK
// You can submit the transaction using dag4.js or custom network code
```

#### Batch Token Transactions

```rust
use constellation_sdk::{
    create_currency_transaction_batch,
    TransferParams,
    TransactionReference,
};

let last_ref = TransactionReference {
    hash: "abc123...".to_string(),
    ordinal: 10,
};

let transfers = vec![
    TransferParams { destination: "DAG...1".to_string(), amount: 10.0, fee: 0.0 },
    TransferParams { destination: "DAG...2".to_string(), amount: 20.0, fee: 0.0 },
    TransferParams { destination: "DAG...3".to_string(), amount: 30.0, fee: 0.0 },
];

// Create batch (transactions are automatically chained)
let txns = create_currency_transaction_batch(
    transfers,
    &private_key,
    last_ref,
)?;

// txns[0].value.parent.ordinal == 10
// txns[1].value.parent.ordinal == 11
// txns[2].value.parent.ordinal == 12
```

#### Multi-Signature Token Transaction

```rust
use constellation_sdk::{
    create_currency_transaction,
    sign_currency_transaction,
    verify_currency_transaction,
    TransferParams,
    TransactionReference,
};

let key1 = generate_key_pair();
let key2 = generate_key_pair();
let recipient = generate_key_pair();

let last_ref = TransactionReference {
    hash: "abc123...".to_string(),
    ordinal: 0,
};

// Create transaction with first signature
let mut tx = create_currency_transaction(
    TransferParams {
        destination: recipient.address.clone(),
        amount: 100.0,
        fee: 0.0,
    },
    &key1.private_key,
    last_ref,
)?;

// Add second signature
tx = sign_currency_transaction(&tx, &key2.private_key)?;

// Verify both signatures
let result = verify_currency_transaction(&tx);
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
