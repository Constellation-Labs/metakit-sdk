//! Signature Verification for secp256r1 (P-256)
//!
//! Verify ECDSA signatures using the NIST P-256 curve.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Serialize;

use crate::binary::to_bytes;
use crate::hash::{compute_digest_from_hash, hash_bytes};
use crate::types::{Result, SdkError, SignatureProof, Signed, VerificationResult};
use crate::wallet_r1::id_to_public_key_r1;

/// Verify a signed object using P-256
///
/// # Arguments
/// * `signed` - Signed object with value and proofs
/// * `is_data_update` - Whether the value was signed as a DataUpdate
///
/// # Returns
/// VerificationResult with valid/invalid proof lists
pub fn verify_r1<T: Serialize>(signed: &Signed<T>, is_data_update: bool) -> VerificationResult {
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
        match verify_hash_r1(&hash.value, &proof.signature, &proof.id) {
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

/// Verify a P-256 signature against a SHA-256 hash
///
/// # Arguments
/// * `hash_hex` - SHA-256 hash as 64-character hex string
/// * `signature_hex` - DER-encoded signature in hex format
/// * `public_key_id` - P-256 public key in hex (128 chars without 04, or 130 with)
///
/// # Returns
/// true if signature is valid
pub fn verify_hash_r1(hash_hex: &str, signature_hex: &str, public_key_id: &str) -> Result<bool> {
    let public_key = id_to_public_key_r1(public_key_id)?;
    let verifying_key = VerifyingKey::from(&public_key);

    let signature_bytes = hex::decode(signature_hex)?;
    let signature = Signature::from_der(&signature_bytes)
        .map_err(|e| SdkError::InvalidSignature(e.to_string()))?;

    let digest = compute_digest_from_hash(hash_hex);

    Ok(verifying_key.verify(&digest, &signature).is_ok())
}

/// Verify a single P-256 signature proof against data
///
/// # Arguments
/// * `data` - The original data that was signed
/// * `proof` - The signature proof to verify
/// * `is_data_update` - Whether data was signed as DataUpdate
pub fn verify_signature_r1<T: Serialize>(
    data: &T,
    proof: &SignatureProof,
    is_data_update: bool,
) -> Result<bool> {
    let bytes = to_bytes(data, is_data_update)?;
    let hash = hash_bytes(&bytes);
    verify_hash_r1(&hash.value, &proof.signature, &proof.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_r1::{sign_r1, sign_data_update_r1};
    use crate::wallet_r1::generate_key_pair_r1;
    use serde_json::json;

    #[test]
    fn test_verify_signed_object_r1() {
        let key_pair = generate_key_pair_r1();
        let data = json!({"id": "test", "value": 42});
        let proof = sign_r1(&data, &key_pair.private_key).unwrap();

        let signed = Signed {
            value: data,
            proofs: vec![proof],
        };

        let result = verify_r1(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 1);
        assert!(result.invalid_proofs.is_empty());
    }

    #[test]
    fn test_verify_data_update_r1() {
        let key_pair = generate_key_pair_r1();
        let data = json!({"id": "test"});
        let proof = sign_data_update_r1(&data, &key_pair.private_key).unwrap();

        let signed = Signed {
            value: data,
            proofs: vec![proof],
        };

        let result = verify_r1(&signed, true);
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_tampered_data_r1() {
        let key_pair = generate_key_pair_r1();
        let original_data = json!({"id": "test", "value": 42});
        let proof = sign_r1(&original_data, &key_pair.private_key).unwrap();

        let tampered_data = json!({"id": "test", "value": 999});
        let signed = Signed {
            value: tampered_data,
            proofs: vec![proof],
        };

        let result = verify_r1(&signed, false);
        assert!(!result.is_valid);
        assert!(result.valid_proofs.is_empty());
        assert_eq!(result.invalid_proofs.len(), 1);
    }

    #[test]
    fn test_verify_wrong_key_r1() {
        let key_pair1 = generate_key_pair_r1();
        let key_pair2 = generate_key_pair_r1();
        let data = json!({"id": "test"});

        // Sign with key1
        let mut proof = sign_r1(&data, &key_pair1.private_key).unwrap();
        // Replace id with key2's id
        let id2 = crate::wallet_r1::get_public_key_id_r1(&key_pair2.private_key).unwrap();
        proof.id = id2;

        let is_valid = verify_hash_r1(
            &crate::hash::hash_bytes(&crate::binary::to_bytes(&data, false).unwrap()).value,
            &proof.signature,
            &proof.id,
        )
        .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_signature_single_r1() {
        let key_pair = generate_key_pair_r1();
        let data = json!({"id": "test"});
        let proof = sign_r1(&data, &key_pair.private_key).unwrap();

        let is_valid = verify_signature_r1(&data, &proof, false).unwrap();
        assert!(is_valid);
    }
}
