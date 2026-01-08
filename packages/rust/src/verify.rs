//! Signature Verification
//!
//! Verify ECDSA signatures using secp256k1 curve.

use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::Serialize;

use crate::binary::to_bytes;
use crate::hash::{compute_digest_from_hash, hash_bytes};
use crate::types::{Result, SignatureProof, Signed, VerificationResult};
use crate::wallet::normalize_public_key;

/// Verify a signed object
///
/// # Arguments
/// * `signed` - Signed object with value and proofs
/// * `is_data_update` - Whether the value was signed as a DataUpdate
///
/// # Returns
/// VerificationResult with valid/invalid proof lists
///
/// # Example
/// ```
/// use constellation_sdk::verify::verify;
/// use constellation_sdk::signed_object::create_signed_object;
/// use constellation_sdk::wallet::generate_key_pair;
/// use serde_json::json;
///
/// let key_pair = generate_key_pair();
/// let signed = create_signed_object(&json!({"id": "test"}), &key_pair.private_key, false).unwrap();
/// let result = verify(&signed, false);
/// assert!(result.is_valid);
/// ```
pub fn verify<T: Serialize>(signed: &Signed<T>, is_data_update: bool) -> VerificationResult {
    // Compute the hash that should have been signed
    let bytes = match to_bytes(&signed.value, is_data_update) {
        Ok(b) => b,
        Err(_) => {
            return VerificationResult {
                is_valid: false,
                valid_proofs: vec![],
                invalid_proofs: signed.proofs.clone(),
            };
        }
    };
    let hash = hash_bytes(&bytes);

    let mut valid_proofs = Vec::new();
    let mut invalid_proofs = Vec::new();

    for proof in &signed.proofs {
        match verify_hash(&hash.value, &proof.signature, &proof.id) {
            Ok(true) => valid_proofs.push(proof.clone()),
            Ok(false) | Err(_) => invalid_proofs.push(proof.clone()),
        }
    }

    VerificationResult {
        is_valid: invalid_proofs.is_empty() && !valid_proofs.is_empty(),
        valid_proofs,
        invalid_proofs,
    }
}

/// Verify a signature against a SHA-256 hash
///
/// Protocol:
/// 1. Treat hash hex as UTF-8 bytes (NOT hex decode)
/// 2. SHA-512 hash
/// 3. Truncate to 32 bytes
/// 4. Verify ECDSA signature
///
/// # Arguments
/// * `hash_hex` - SHA-256 hash as 64-character hex string
/// * `signature` - DER-encoded signature in hex format
/// * `public_key_id` - Public key in hex (with or without 04 prefix)
///
/// # Returns
/// true if signature is valid
pub fn verify_hash(hash_hex: &str, signature: &str, public_key_id: &str) -> Result<bool> {
    let secp = Secp256k1::new();

    // Normalize and parse public key
    let full_public_key = normalize_public_key(public_key_id);
    let public_key_bytes = hex::decode(&full_public_key)?;
    let public_key = PublicKey::from_slice(&public_key_bytes)?;

    // Parse signature
    let signature_bytes = hex::decode(signature)?;
    let mut sig = Signature::from_der(&signature_bytes)?;

    // Normalize to low-S form for verification compatibility
    // Some signing implementations produce high-S signatures which are mathematically
    // valid but rejected by strict BIP 62/146 implementations
    sig.normalize_s();

    // Compute signing digest
    let digest = compute_digest_from_hash(hash_hex);

    // Create message from digest
    let message = Message::from_digest_slice(&digest)?;

    // Verify signature
    Ok(secp.verify_ecdsa(&message, &sig, &public_key).is_ok())
}

/// Verify a single signature proof against data
///
/// # Arguments
/// * `data` - The original data that was signed
/// * `proof` - The signature proof to verify
/// * `is_data_update` - Whether data was signed as DataUpdate
///
/// # Returns
/// true if signature is valid
pub fn verify_signature<T: Serialize>(
    data: &T,
    proof: &SignatureProof,
    is_data_update: bool,
) -> Result<bool> {
    let bytes = to_bytes(data, is_data_update)?;
    let hash = hash_bytes(&bytes);
    verify_hash(&hash.value, &proof.signature, &proof.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{sign, sign_data_update};
    use crate::wallet::generate_key_pair;
    use serde_json::json;

    #[test]
    fn test_verify_signed_object() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test", "value": 42});
        let proof = sign(&data, &key_pair.private_key).unwrap();

        let signed = Signed {
            value: data,
            proofs: vec![proof],
        };

        let result = verify(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 1);
        assert!(result.invalid_proofs.is_empty());
    }

    #[test]
    fn test_verify_data_update() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});
        let proof = sign_data_update(&data, &key_pair.private_key).unwrap();

        let signed = Signed {
            value: data,
            proofs: vec![proof],
        };

        let result = verify(&signed, true);
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_tampered_data() {
        let key_pair = generate_key_pair();
        let original_data = json!({"id": "test", "value": 42});
        let proof = sign(&original_data, &key_pair.private_key).unwrap();

        // Tamper with data
        let tampered_data = json!({"id": "test", "value": 999});
        let signed = Signed {
            value: tampered_data,
            proofs: vec![proof],
        };

        let result = verify(&signed, false);
        assert!(!result.is_valid);
        assert!(result.valid_proofs.is_empty());
        assert_eq!(result.invalid_proofs.len(), 1);
    }

    #[test]
    fn test_verify_hash() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});
        let proof = sign(&data, &key_pair.private_key).unwrap();

        let bytes = to_bytes(&data, false).unwrap();
        let hash = hash_bytes(&bytes);

        let is_valid = verify_hash(&hash.value, &proof.signature, &proof.id).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_signature_single() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});
        let proof = sign(&data, &key_pair.private_key).unwrap();

        let is_valid = verify_signature(&data, &proof, false).unwrap();
        assert!(is_valid);
    }
}
