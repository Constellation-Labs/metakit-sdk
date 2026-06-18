//! Constellation Metagraph SDK for Rust
//!
//! A toolkit for signing and verifying data on Constellation Network metagraphs.
//!
//! # Features
//!
//! - **ECDSA secp256k1 signing** — industry-standard elliptic curve signatures
//! - **RFC 8785 canonicalization** — deterministic JSON serialization
//! - **Cross-language compatibility** — interoperable with TypeScript, Python, Go implementations
//! - **Multi-signature support** — create and verify objects signed by multiple parties
//! - **Optional secp256r1 (P-256)** — TPM-native curve, behind the `r1` cargo feature
//!
//! # Quick Start
//!
//! ```rust
//! use constellation_sdk::{
//!     wallet::generate_key_pair,
//!     signed_object::create_signed_object,
//!     verify::verify,
//! };
//! use serde_json::json;
//!
//! let key_pair = generate_key_pair();
//! let data = json!({"action": "transfer", "amount": 100});
//! let signed = create_signed_object(&data, &key_pair.private_key, false).unwrap();
//! let result = verify(&signed, false);
//! assert!(result.is_valid);
//! ```
//!
//! # P-256 (R1) signing
//!
//! Enable the `r1` feature to access the parallel `crate::r1` namespace
//! mirroring the K1 API:
//!
//! ```toml
//! [dependencies]
//! constellation-metagraph-sdk = { version = "0.2", features = ["r1"] }
//! ```
//!
//! ```ignore
//! use constellation_sdk::r1::wallet::generate_key_pair;
//! use constellation_sdk::r1::sign::sign_hash;
//! let kp = generate_key_pair();
//! let sig = sign_hash(&"00".repeat(32), &kp.private_key)?;
//! ```

pub mod binary;
pub mod canonicalize;
pub mod codec;
pub mod currency_transaction;
pub mod currency_types;
pub mod hash;
pub mod sign;
pub mod signed_object;
pub mod types;
pub mod verify;
pub mod wallet;

#[cfg(feature = "r1")]
pub mod r1;

#[cfg(feature = "network")]
pub mod network;

// ─── Crate-root re-exports ──────────────────────────────────────────────

// Common types
pub use types::{
    Hash, KeyPair, Result, SdkError, SignatureProof, Signed, SigningOptions, SigningScheme,
    VerificationResult, ALGORITHM, ALGORITHM_R1, CONSTELLATION_PREFIX,
};

// secp256k1 (K1) — always present
pub use binary::{encode_data_update, to_bytes};
pub use canonicalize::{canonicalize, canonicalize_bytes, drop_null_fields};
pub use codec::decode_data_update;
pub use hash::{compute_digest, hash_bytes, hash_data};
pub use sign::{sign, sign_data_update, sign_hash};
pub use signed_object::{add_signature, batch_sign, create_signed_object};
pub use verify::{verify, verify_hash, verify_signature};
pub use wallet::{
    generate_key_pair, get_address, get_public_key_hex, get_public_key_id, is_valid_private_key,
    is_valid_public_key, key_pair_from_private_key,
};

// Currency transactions (K1-only API).
pub use currency_transaction::{
    create_currency_transaction, create_currency_transaction_batch, encode_currency_transaction,
    get_transaction_reference, hash_currency_transaction, is_valid_dag_address,
    sign_currency_transaction, token_to_units, units_to_token, verify_currency_transaction,
};
pub use currency_types::{
    CurrencyTransaction, CurrencyTransactionValue, TransactionReference, TransferParams,
    TOKEN_DECIMALS,
};
