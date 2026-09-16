//! Constellation Metagraph SDK — offline core kernel
//!
//! The fully-offline kernel of the Constellation Metagraph SDK: RFC 8785
//! canonicalization, SHA-256 hashing, binary encoding, committed-roots
//! light-client codecs, and ECDSA signing/verification (secp256k1 by
//! default, secp256r1/P-256 behind the `r1` feature).
//!
//! This crate has **no network dependencies** and mirrors the
//! `metagraph-sdk-core` TypeScript package in the 3-tier packaging model.
//! Higher tiers (currency transactions, the metagraph network client) live
//! in the `constellation-metagraph-sdk` crate, which re-exports everything
//! here so `constellation_sdk::*` paths resolve unchanged.
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
//! use constellation_sdk_core::{
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
//! constellation-metagraph-sdk-core = { version = "1.8", features = ["r1"] }
//! ```
//!
//! ```ignore
//! use constellation_sdk_core::r1::wallet::generate_key_pair;
//! use constellation_sdk_core::r1::sign::sign_hash;
//! let kp = generate_key_pair();
//! let sig = sign_hash(&"00".repeat(32), &kp.private_key)?;
//! ```

pub mod binary;
pub mod canonicalize;
pub mod codec;
pub mod committed_roots;
pub mod hash;
pub mod sign;
pub mod signed_object;
pub mod types;
pub mod verify;
pub mod wallet;

#[cfg(feature = "r1")]
pub mod r1;

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

// Committed-roots light-client codecs (byte-aligned with the metakit reference).
pub use committed_roots::{
    CommitKey, CommitKeyError, CommittedBreadcrumb, CommittedRoots, SparseMerkleRoot,
};
