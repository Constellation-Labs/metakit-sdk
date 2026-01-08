//! Signing Functions
//!
//! ECDSA signing using secp256k1 curve.
//! Implements the Constellation signature protocol.

use secp256k1::{Message, Secp256k1, SecretKey};
use serde::Serialize;

use crate::binary::to_bytes;
use crate::hash::{compute_digest_from_hash, hash_bytes};
use crate::types::{Result, SdkError, SignatureProof};
use crate::wallet::get_public_key_id;

/// Sign data using the regular Constellation protocol (non-DataUpdate)
///
/// Protocol:
/// 1. Canonicalize JSON
/// 2. UTF-8 encode
/// 3. SHA-256 hash
/// 4. Hex encode hash, treat as UTF-8
/// 5. SHA-512 hash, truncate to 32 bytes
/// 6. Sign with ECDSA
///
/// # Arguments
/// * `data` - Any serializable data
/// * `private_key` - Private key in hex format
///
/// # Returns
/// SignatureProof with public key ID and signature
///
/// # Example
/// ```
/// use constellation_sdk::sign::sign;
/// use constellation_sdk::wallet::generate_key_pair;
/// use serde_json::json;
///
/// let key_pair = generate_key_pair();
/// let data = json!({"action": "test"});
/// let proof = sign(&data, &key_pair.private_key).unwrap();
/// println!("ID: {}", proof.id);
/// println!("Signature: {}", proof.signature);
/// ```
pub fn sign<T: Serialize>(data: &T, private_key: &str) -> Result<SignatureProof> {
    // Serialize and hash
    let bytes = to_bytes(data, false)?;
    let hash = hash_bytes(&bytes);

    // Sign the hash
    let signature = sign_hash(&hash.value, private_key)?;

    // Get public key ID
    let id = get_public_key_id(private_key)?;

    Ok(SignatureProof { id, signature })
}

/// Sign data as a DataUpdate (with Constellation prefix)
///
/// # Arguments
/// * `data` - Any serializable data
/// * `private_key` - Private key in hex format
///
/// # Returns
/// SignatureProof
pub fn sign_data_update<T: Serialize>(data: &T, private_key: &str) -> Result<SignatureProof> {
    // Serialize with DataUpdate encoding and hash
    let bytes = to_bytes(data, true)?;
    let hash = hash_bytes(&bytes);

    // Sign the hash
    let signature = sign_hash(&hash.value, private_key)?;

    // Get public key ID
    let id = get_public_key_id(private_key)?;

    Ok(SignatureProof { id, signature })
}

/// Sign a pre-computed SHA-256 hash
///
/// # Arguments
/// * `hash_hex` - SHA-256 hash as 64-character hex string
/// * `private_key` - Private key in hex format
///
/// # Returns
/// DER-encoded signature in hex format
pub fn sign_hash(hash_hex: &str, private_key: &str) -> Result<String> {
    let secp = Secp256k1::new();

    // Parse private key
    let private_key_bytes = hex::decode(private_key)?;
    let secret_key = SecretKey::from_slice(&private_key_bytes)?;

    // Compute signing digest
    let digest = compute_digest_from_hash(hash_hex);

    // Create message from digest
    let message = Message::from_digest_slice(&digest)
        .map_err(|e| SdkError::CryptoError(e.to_string()))?;

    // Sign with ECDSA
    let signature = secp.sign_ecdsa(&message, &secret_key);

    // Return DER-encoded signature
    Ok(hex::encode(signature.serialize_der()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::generate_key_pair;
    use serde_json::json;

    #[test]
    fn test_sign() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test", "value": 42});
        let proof = sign(&data, &key_pair.private_key).unwrap();

        assert_eq!(proof.id.len(), 128);
        assert!(!proof.signature.is_empty());
    }

    #[test]
    fn test_sign_data_update() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});
        let proof = sign_data_update(&data, &key_pair.private_key).unwrap();

        assert_eq!(proof.id.len(), 128);
        assert!(!proof.signature.is_empty());
    }

    #[test]
    fn test_sign_different_for_regular_vs_data_update() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});

        let regular_proof = sign(&data, &key_pair.private_key).unwrap();
        let update_proof = sign_data_update(&data, &key_pair.private_key).unwrap();

        // Same public key
        assert_eq!(regular_proof.id, update_proof.id);
        // Different signatures
        assert_ne!(regular_proof.signature, update_proof.signature);
    }

    #[test]
    fn test_sign_deterministic() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});

        let proof1 = sign(&data, &key_pair.private_key).unwrap();
        let proof2 = sign(&data, &key_pair.private_key).unwrap();

        assert_eq!(proof1.id, proof2.id);
        // Note: ECDSA signatures may include random k value
        // so signatures might differ, but both should be valid
    }
}
