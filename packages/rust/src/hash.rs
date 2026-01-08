//! Hashing Utilities
//!
//! SHA-256 and SHA-512 hashing functions for the Constellation protocol.

use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};

use crate::binary::to_bytes;
use crate::types::{Hash, Result};

/// Hash data using SHA-256
///
/// # Arguments
/// * `data` - Any serializable data
/// * `is_data_update` - Whether to encode as DataUpdate before hashing
///
/// # Returns
/// Hash struct with value (hex) and bytes
///
/// # Example
/// ```
/// use constellation_sdk::hash::hash_data;
/// use serde_json::json;
///
/// let data = json!({"id": "test"});
/// let hash = hash_data(&data, false).unwrap();
/// assert_eq!(hash.value.len(), 64); // 32 bytes = 64 hex chars
/// ```
pub fn hash_data<T: Serialize>(data: &T, is_data_update: bool) -> Result<Hash> {
    let bytes = to_bytes(data, is_data_update)?;
    Ok(hash_bytes(&bytes))
}

/// Hash raw bytes using SHA-256
///
/// # Arguments
/// * `data` - Raw bytes to hash
///
/// # Returns
/// Hash struct with value (hex) and bytes
pub fn hash_bytes(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_bytes = hasher.finalize().to_vec();
    let hash_hex = hex::encode(&hash_bytes);

    Hash {
        value: hash_hex,
        bytes: hash_bytes,
    }
}

/// Compute the full signing digest for Constellation protocol
///
/// Protocol:
/// 1. Serialize and hash with SHA-256
/// 2. Convert hash to hex string
/// 3. Treat hex string as UTF-8 bytes
/// 4. SHA-512 hash
/// 5. Truncate to 32 bytes
///
/// # Arguments
/// * `data` - Any serializable data
/// * `is_data_update` - Whether to encode as DataUpdate
///
/// # Returns
/// 32-byte digest ready for signing
pub fn compute_digest<T: Serialize>(data: &T, is_data_update: bool) -> Result<[u8; 32]> {
    let bytes = to_bytes(data, is_data_update)?;
    Ok(compute_digest_from_bytes(&bytes))
}

/// Compute signing digest from raw bytes
///
/// # Arguments
/// * `data` - Raw bytes to hash
///
/// # Returns
/// 32-byte digest ready for signing
pub fn compute_digest_from_bytes(data: &[u8]) -> [u8; 32] {
    // Step 1: SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256_hash = hasher.finalize();
    let hash_hex = hex::encode(sha256_hash);

    // Step 2-4: Treat hex as UTF-8 bytes, SHA-512, truncate
    let hash_hex_bytes = hash_hex.as_bytes();
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(hash_hex_bytes);
    let sha512_hash = sha512_hasher.finalize();

    // Step 5: Truncate to 32 bytes
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&sha512_hash[..32]);
    digest
}

/// Compute signing digest from a pre-computed SHA-256 hash hex string
///
/// # Arguments
/// * `hash_hex` - 64-character hex string of SHA-256 hash
///
/// # Returns
/// 32-byte digest ready for signing
pub fn compute_digest_from_hash(hash_hex: &str) -> [u8; 32] {
    // Treat hex as UTF-8 bytes
    let hash_hex_bytes = hash_hex.as_bytes();

    // SHA-512 hash
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(hash_hex_bytes);
    let sha512_hash = sha512_hasher.finalize();

    // Truncate to 32 bytes
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&sha512_hash[..32]);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hash_data() {
        let data = json!({"id": "test", "value": 42});
        let hash = hash_data(&data, false).unwrap();
        assert_eq!(hash.value.len(), 64);
        assert_eq!(hash.bytes.len(), 32);
    }

    #[test]
    fn test_hash_bytes() {
        let data = b"test data";
        let hash = hash_bytes(data);
        assert_eq!(hash.value.len(), 64);
        assert_eq!(hash.bytes.len(), 32);
    }

    #[test]
    fn test_compute_digest() {
        let data = json!({"id": "test"});
        let digest = compute_digest(&data, false).unwrap();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_compute_digest_data_update() {
        let data = json!({"id": "test"});
        let regular_digest = compute_digest(&data, false).unwrap();
        let update_digest = compute_digest(&data, true).unwrap();
        // DataUpdate should produce different digest
        assert_ne!(regular_digest, update_digest);
    }

    #[test]
    fn test_deterministic_hashing() {
        let data = json!({"id": "test", "value": 42});
        let hash1 = hash_data(&data, false).unwrap();
        let hash2 = hash_data(&data, false).unwrap();
        assert_eq!(hash1.value, hash2.value);
    }
}
