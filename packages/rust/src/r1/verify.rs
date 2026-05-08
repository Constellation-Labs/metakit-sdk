//! P-256 (secp256r1) verification functions.
//!
//! Mirrors `crate::verify` (K1) but uses the NIST P-256 curve.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Serialize;

use crate::binary::to_bytes;
use crate::hash::{compute_digest_from_hash, hash_bytes};
use crate::r1::wallet::id_to_public_key;
use crate::types::{Result, SdkError, SignatureProof, Signed, VerificationResult};

/// Verify a signed object using P-256.
///
/// # Arguments
/// * `signed` - Signed object with value and proofs
/// * `is_data_update` - Whether the value was signed as a DataUpdate
///
/// # Returns
/// VerificationResult with valid/invalid proof lists
pub fn verify<T: Serialize>(signed: &Signed<T>, is_data_update: bool) -> VerificationResult {
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

/// Verify a P-256 signature against a SHA-256 hash.
///
/// # Arguments
/// * `hash_hex` - SHA-256 hash as 64-character hex string
/// * `signature_hex` - DER-encoded signature in hex format
/// * `public_key_id` - P-256 public key in hex (128 chars without 04, or 130 with)
///
/// # Returns
/// true if signature is valid
pub fn verify_hash(hash_hex: &str, signature_hex: &str, public_key_id: &str) -> Result<bool> {
    let public_key = id_to_public_key(public_key_id)?;
    let verifying_key = VerifyingKey::from(&public_key);

    let signature_bytes = hex::decode(signature_hex)?;
    let signature = Signature::from_der(&signature_bytes)
        .map_err(|e| SdkError::InvalidSignature(e.to_string()))?;

    let digest = compute_digest_from_hash(hash_hex);

    Ok(verifying_key.verify(&digest, &signature).is_ok())
}

/// Verify a single P-256 signature proof against data.
///
/// # Arguments
/// * `data` - The original data that was signed
/// * `proof` - The signature proof to verify
/// * `is_data_update` - Whether data was signed as DataUpdate
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
    use crate::r1::sign::{sign, sign_data_update};
    use crate::r1::wallet::generate_key_pair;
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
    fn test_verify_wrong_key() {
        let key_pair1 = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let data = json!({"id": "test"});

        // Sign with key1
        let mut proof = sign(&data, &key_pair1.private_key).unwrap();
        // Replace id with key2's id
        let id2 = crate::r1::wallet::get_public_key_id(&key_pair2.private_key).unwrap();
        proof.id = id2;

        let is_valid = verify_hash(
            &crate::hash::hash_bytes(&crate::binary::to_bytes(&data, false).unwrap()).value,
            &proof.signature,
            &proof.id,
        )
        .unwrap();
        assert!(!is_valid);
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
