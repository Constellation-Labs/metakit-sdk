//! P-256 (secp256r1) signing functions.
//!
//! Mirrors `crate::sign` (K1) but uses the NIST P-256 curve. Function
//! names are unsuffixed inside this `r1::` namespace; the crate root
//! re-exports them under the old `*_r1` names for backwards compat.

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::Serialize;

use crate::binary::to_bytes;
use crate::hash::{compute_digest_from_hash, hash_bytes};
use crate::r1::wallet::get_public_key_id;
use crate::types::{Result, SignatureProof};

/// Sign data using P-256 with the regular Constellation protocol (non-DataUpdate).
///
/// # Arguments
/// * `data` - Any serializable data
/// * `private_key` - P-256 private key in hex format
///
/// # Returns
/// SignatureProof with public key ID and DER-encoded signature
pub fn sign<T: Serialize>(data: &T, private_key: &str) -> Result<SignatureProof> {
    let bytes = to_bytes(data, false)?;
    let hash = hash_bytes(&bytes);
    let signature = sign_hash(&hash.value, private_key)?;
    let id = get_public_key_id(private_key)?;

    Ok(SignatureProof { id, signature })
}

/// Sign data as a DataUpdate using P-256.
///
/// # Arguments
/// * `data` - Any serializable data
/// * `private_key` - P-256 private key in hex format
pub fn sign_data_update<T: Serialize>(data: &T, private_key: &str) -> Result<SignatureProof> {
    let bytes = to_bytes(data, true)?;
    let hash = hash_bytes(&bytes);
    let signature = sign_hash(&hash.value, private_key)?;
    let id = get_public_key_id(private_key)?;

    Ok(SignatureProof { id, signature })
}

/// Sign a pre-computed SHA-256 hash using P-256.
///
/// The signing digest pipeline matches metakit's Scala implementation:
/// hash hex → UTF-8 bytes → SHA-512 → truncate to 32 bytes → ECDSA sign.
///
/// # Arguments
/// * `hash_hex` - SHA-256 hash as 64-character hex string
/// * `private_key` - P-256 private key in hex format
///
/// # Returns
/// DER-encoded signature in hex format
pub fn sign_hash(hash_hex: &str, private_key: &str) -> Result<String> {
    let private_key_bytes = hex::decode(private_key)?;
    let signing_key = SigningKey::from_slice(&private_key_bytes)?;

    let digest = compute_digest_from_hash(hash_hex);

    // NOTE: `signing_key.sign(&digest)` (the `Signer` trait impl)
    // applies a SHA-256 prefix to `digest` before signing —
    // documented as `SHA256withECDSA` semantics. The doc comment on
    // the original `sign_hash_r1` claimed `sign_prehash` semantics
    // which would have been a different (no extra hash) pipeline.
    // Sign and verify are self-consistent (both go through this
    // path), but a Scala-side R1 verifier following the literal
    // metakit-Scala "no extra hash" pipeline would reject these
    // signatures. Fixing this requires coordinated changes across
    // every existing on-chain proof; tracked separately.
    let signature: Signature = signing_key.sign(&digest);

    Ok(hex::encode(signature.to_der().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1::wallet::generate_key_pair;
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

        assert_eq!(regular_proof.id, update_proof.id);
        assert_ne!(regular_proof.signature, update_proof.signature);
    }
}
