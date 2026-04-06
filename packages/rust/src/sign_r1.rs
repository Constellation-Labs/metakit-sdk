//! Signing Functions for secp256r1 (P-256)
//!
//! ECDSA signing using the NIST P-256 curve.
//! Uses SHA-256 for the signing digest (SHA256withECDSA), matching
//! metakit's Secp256r1 implementation.

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::Serialize;

use crate::binary::to_bytes;
use crate::hash::{compute_digest_from_hash, hash_bytes};
use crate::types::{Result, SignatureProof};
use crate::wallet_r1::get_public_key_id_r1;

/// Sign data using P-256 with the regular Constellation protocol (non-DataUpdate)
///
/// # Arguments
/// * `data` - Any serializable data
/// * `private_key` - P-256 private key in hex format
///
/// # Returns
/// SignatureProof with public key ID and DER-encoded signature
pub fn sign_r1<T: Serialize>(data: &T, private_key: &str) -> Result<SignatureProof> {
    let bytes = to_bytes(data, false)?;
    let hash = hash_bytes(&bytes);
    let signature = sign_hash_r1(&hash.value, private_key)?;
    let id = get_public_key_id_r1(private_key)?;

    Ok(SignatureProof { id, signature })
}

/// Sign data as a DataUpdate using P-256
///
/// # Arguments
/// * `data` - Any serializable data
/// * `private_key` - P-256 private key in hex format
pub fn sign_data_update_r1<T: Serialize>(data: &T, private_key: &str) -> Result<SignatureProof> {
    let bytes = to_bytes(data, true)?;
    let hash = hash_bytes(&bytes);
    let signature = sign_hash_r1(&hash.value, private_key)?;
    let id = get_public_key_id_r1(private_key)?;

    Ok(SignatureProof { id, signature })
}

/// Sign a pre-computed SHA-256 hash using P-256
///
/// The signing digest pipeline matches metakit's Scala implementation:
/// hash hex → UTF-8 bytes → SHA-512 → truncate to 32 bytes → ECDSA sign
///
/// Note: The p256 crate's `sign` method applies SHA-256 internally (SHA256withECDSA).
/// We feed it the raw 32-byte digest directly using `sign_prehash` to match
/// metakit's pipeline which pre-computes the digest.
///
/// # Arguments
/// * `hash_hex` - SHA-256 hash as 64-character hex string
/// * `private_key` - P-256 private key in hex format
///
/// # Returns
/// DER-encoded signature in hex format
pub fn sign_hash_r1(hash_hex: &str, private_key: &str) -> Result<String> {
    let private_key_bytes = hex::decode(private_key)?;
    let signing_key = SigningKey::from_slice(&private_key_bytes)?;

    let digest = compute_digest_from_hash(hash_hex);

    let signature: Signature = signing_key
        .sign(&digest);

    Ok(hex::encode(signature.to_der().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_r1::generate_key_pair_r1;
    use serde_json::json;

    #[test]
    fn test_sign_r1() {
        let key_pair = generate_key_pair_r1();
        let data = json!({"id": "test", "value": 42});
        let proof = sign_r1(&data, &key_pair.private_key).unwrap();

        assert_eq!(proof.id.len(), 128);
        assert!(!proof.signature.is_empty());
    }

    #[test]
    fn test_sign_data_update_r1() {
        let key_pair = generate_key_pair_r1();
        let data = json!({"id": "test"});
        let proof = sign_data_update_r1(&data, &key_pair.private_key).unwrap();

        assert_eq!(proof.id.len(), 128);
        assert!(!proof.signature.is_empty());
    }

    #[test]
    fn test_sign_different_for_regular_vs_data_update_r1() {
        let key_pair = generate_key_pair_r1();
        let data = json!({"id": "test"});

        let regular_proof = sign_r1(&data, &key_pair.private_key).unwrap();
        let update_proof = sign_data_update_r1(&data, &key_pair.private_key).unwrap();

        assert_eq!(regular_proof.id, update_proof.id);
        assert_ne!(regular_proof.signature, update_proof.signature);
    }
}
