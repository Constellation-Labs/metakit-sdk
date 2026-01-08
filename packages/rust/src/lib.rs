//! Constellation Metagraph SDK for Rust
//!
//! A complete toolkit for signing and verifying data on Constellation Network metagraphs.
//!
//! # Features
//!
//! - **ECDSA secp256k1 signing** - Industry-standard elliptic curve signatures
//! - **RFC 8785 canonicalization** - Deterministic JSON serialization
//! - **Cross-language compatibility** - Interoperable with TypeScript, Python, Go implementations
//! - **Multi-signature support** - Create and verify objects signed by multiple parties
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
//! // Generate a key pair
//! let key_pair = generate_key_pair();
//! println!("Address: {}", key_pair.address);
//!
//! // Create and sign data
//! let data = json!({
//!     "action": "transfer",
//!     "amount": 100
//! });
//!
//! let signed = create_signed_object(&data, &key_pair.private_key, false).unwrap();
//!
//! // Verify the signature
//! let result = verify(&signed, false);
//! assert!(result.is_valid);
//! ```
//!
//! # DataUpdate Signing
//!
//! For L1 submission, use DataUpdate signing which adds the Constellation prefix:
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
//! let data = json!({"id": "update-001", "value": 42});
//!
//! // Sign as DataUpdate
//! let signed = create_signed_object(&data, &key_pair.private_key, true).unwrap();
//!
//! // Verify (must specify is_data_update = true)
//! let result = verify(&signed, true);
//! assert!(result.is_valid);
//! ```

pub mod binary;
pub mod canonicalize;
pub mod codec;
pub mod hash;
pub mod sign;
pub mod signed_object;
pub mod types;
pub mod verify;
pub mod wallet;

// Re-export commonly used items at the crate root
pub use types::{
    Hash, KeyPair, Result, SdkError, SignatureProof, Signed, SigningOptions, VerificationResult,
    ALGORITHM, CONSTELLATION_PREFIX,
};

// Re-export main functions
pub use canonicalize::{canonicalize, canonicalize_bytes};
pub use binary::{encode_data_update, to_bytes};
pub use codec::decode_data_update;
pub use hash::{compute_digest, hash_bytes, hash_data};
pub use sign::{sign, sign_data_update, sign_hash};
pub use signed_object::{add_signature, batch_sign, create_signed_object};
pub use verify::{verify, verify_hash, verify_signature};
pub use wallet::{
    generate_key_pair, get_address, get_public_key_hex, get_public_key_id, is_valid_private_key,
    is_valid_public_key, key_pair_from_private_key,
};
