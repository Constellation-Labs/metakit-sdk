//! Core type definitions for the Constellation Metagraph SDK

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported signature algorithm
pub const ALGORITHM: &str = "SECP256K1_RFC8785_V1";

/// Constellation prefix for DataUpdate signing
pub const CONSTELLATION_PREFIX: &str = "\x19Constellation Signed Data:\n";

/// A signature proof containing the signer's public key ID and signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureProof {
    /// Public key hex (uncompressed, without 04 prefix) - 128 characters
    pub id: String,
    /// DER-encoded ECDSA signature in hex format
    pub signature: String,
}

/// A signed object wrapping a value with one or more signature proofs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    /// The signed value
    pub value: T,
    /// Array of signature proofs
    pub proofs: Vec<SignatureProof>,
}

/// A key pair for signing operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    /// Private key in hex format (64 characters)
    pub private_key: String,
    /// Public key in hex format (uncompressed, with 04 prefix - 130 characters)
    pub public_key: String,
    /// DAG address derived from the public key
    pub address: String,
}

/// A hash result containing both hex string and raw bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    /// SHA-256 hash as 64-character hex string
    pub value: String,
    /// Raw 32-byte hash
    pub bytes: Vec<u8>,
}

/// Result of signature verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// Whether all signatures are valid
    pub is_valid: bool,
    /// Proofs that passed verification
    pub valid_proofs: Vec<SignatureProof>,
    /// Proofs that failed verification
    pub invalid_proofs: Vec<SignatureProof>,
}

/// Options for signing operations
#[derive(Debug, Clone, Default)]
pub struct SigningOptions {
    /// Whether to sign as a DataUpdate (with Constellation prefix)
    pub is_data_update: bool,
}

/// SDK error types
#[derive(Error, Debug)]
pub enum SdkError {
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Invalid hex string: {0}")]
    HexError(String),

    #[error("At least one private key is required")]
    NoPrivateKeys,
}

impl From<hex::FromHexError> for SdkError {
    fn from(err: hex::FromHexError) -> Self {
        SdkError::HexError(err.to_string())
    }
}

impl From<secp256k1::Error> for SdkError {
    fn from(err: secp256k1::Error) -> Self {
        SdkError::CryptoError(err.to_string())
    }
}

impl From<serde_json::Error> for SdkError {
    fn from(err: serde_json::Error) -> Self {
        SdkError::SerializationError(err.to_string())
    }
}

/// Result type for SDK operations
pub type Result<T> = std::result::Result<T, SdkError>;
