//! P-256 (secp256r1) wallet and key management.
//!
//! Mirrors `crate::wallet` (K1) but uses the NIST P-256 curve. The
//! address derivation differs only in the DER PKCS prefix.

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::PublicKey;
use sha2::{Digest, Sha256};

use crate::types::{KeyPair, Result, SdkError};

/// DER SubjectPublicKeyInfo prefix for secp256r1 uncompressed public keys.
/// Stripped when creating an Id, prepended when reconstructing.
const PKCS_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";

/// Generate a new random P-256 key pair.
///
/// # Example
/// ```
/// use constellation_sdk::r1::wallet::generate_key_pair;
///
/// let key_pair = generate_key_pair();
/// println!("Address: {}", key_pair.address);
/// println!("Private key: {}", key_pair.private_key);
/// println!("Public key: {}", key_pair.public_key);
/// ```
pub fn generate_key_pair() -> KeyPair {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let private_key_hex = hex::encode(signing_key.to_bytes());

    let public_key = signing_key.verifying_key();
    let point = public_key.to_encoded_point(false);
    let public_key_hex = hex::encode(point.as_bytes());

    let address = get_address(&public_key_hex);

    KeyPair {
        private_key: private_key_hex,
        public_key: public_key_hex,
        address,
    }
}

/// Derive a P-256 key pair from an existing private key.
pub fn key_pair_from_private_key(private_key: &str) -> Result<KeyPair> {
    if !is_valid_private_key(private_key) {
        return Err(SdkError::InvalidPrivateKey(
            "Invalid P-256 private key format".to_string(),
        ));
    }

    let private_key_bytes = hex::decode(private_key)?;
    let signing_key = SigningKey::from_slice(&private_key_bytes)?;
    let public_key = signing_key.verifying_key();
    let point = public_key.to_encoded_point(false);
    let public_key_hex = hex::encode(point.as_bytes());
    let address = get_address(&public_key_hex);

    Ok(KeyPair {
        private_key: private_key.to_string(),
        public_key: public_key_hex,
        address,
    })
}

/// Get the public key ID (without 04 prefix) from a P-256 private key.
///
/// Format matches metakit's `Secp256r1.publicKeyToId` — the raw 64-byte
/// EC point as hex (128 chars).
pub fn get_public_key_id(private_key: &str) -> Result<String> {
    let public_key = get_public_key_hex(private_key, false)?;
    Ok(normalize_public_key_to_id(&public_key))
}

/// Get the public key hex from a P-256 private key.
///
/// # Arguments
/// * `private_key` - Private key in hex format
/// * `compressed` - If true, returns compressed public key (33 bytes)
pub fn get_public_key_hex(private_key: &str, compressed: bool) -> Result<String> {
    let private_key_bytes = hex::decode(private_key)?;
    let signing_key = SigningKey::from_slice(&private_key_bytes)?;
    let public_key = signing_key.verifying_key();
    let point = public_key.to_encoded_point(compressed);
    Ok(hex::encode(point.as_bytes()))
}

/// Get DAG address from a P-256 public key.
///
/// Uses the same Constellation address derivation as secp256k1 but
/// with the P-256 PKCS prefix.
pub fn get_address(public_key: &str) -> String {
    let normalized_key = normalize_public_key(public_key);
    let pkcs_encoded = format!("{PKCS_PREFIX}{normalized_key}");

    let pkcs_bytes = hex::decode(&pkcs_encoded).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&pkcs_bytes);
    let hash = hasher.finalize();

    let encoded = bs58::encode(&hash).into_string();

    let last36 = if encoded.len() > 36 {
        &encoded[encoded.len() - 36..]
    } else {
        &encoded
    };

    let digit_sum: u32 = last36
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap_or(0))
        .sum();
    let parity = digit_sum % 9;

    format!("DAG{parity}{last36}")
}

/// Parse a public key ID (128 hex chars) back into a P-256 PublicKey.
pub fn id_to_public_key(public_key_id: &str) -> Result<PublicKey> {
    let full_hex = normalize_public_key(public_key_id);
    let bytes = hex::decode(&full_hex)?;
    let point = p256::EncodedPoint::from_bytes(&bytes)
        .map_err(|e| SdkError::InvalidPublicKey(e.to_string()))?;
    PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| SdkError::InvalidPublicKey("Invalid P-256 point".to_string()))
}

/// Validate that a P-256 private key is correctly formatted.
pub fn is_valid_private_key(private_key: &str) -> bool {
    if private_key.len() != 64 {
        return false;
    }
    private_key.chars().all(|c| c.is_ascii_hexdigit())
}

/// Normalize P-256 public key to include 04 prefix.
pub fn normalize_public_key(public_key: &str) -> String {
    if public_key.len() == 128 {
        format!("04{public_key}")
    } else {
        public_key.to_string()
    }
}

/// Normalize P-256 public key to ID format (without 04 prefix).
pub fn normalize_public_key_to_id(public_key: &str) -> String {
    if public_key.len() == 130 && public_key.starts_with("04") {
        public_key[2..].to_string()
    } else {
        public_key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn test_generate_key_pair() {
        let key_pair = generate_key_pair();
        assert_eq!(key_pair.private_key.len(), 64);
        assert_eq!(key_pair.public_key.len(), 130); // 04 + 128
        assert!(key_pair.address.starts_with("DAG"));
    }

    #[test]
    fn test_key_pair_from_private_key() {
        let key_pair = generate_key_pair();
        let derived = key_pair_from_private_key(&key_pair.private_key).unwrap();
        assert_eq!(derived.public_key, key_pair.public_key);
        assert_eq!(derived.address, key_pair.address);
    }

    #[test]
    fn test_public_key_id_is_128_chars() {
        let key_pair = generate_key_pair();
        let id = get_public_key_id(&key_pair.private_key).unwrap();
        assert_eq!(id.len(), 128);
    }

    #[test]
    fn test_id_to_public_key_round_trip() {
        let key_pair = generate_key_pair();
        let id = get_public_key_id(&key_pair.private_key).unwrap();
        let recovered = id_to_public_key(&id).unwrap();
        let point = recovered.to_encoded_point(false);
        let recovered_hex = hex::encode(point.as_bytes());
        assert_eq!(recovered_hex, key_pair.public_key);
    }

    #[test]
    fn test_is_valid_private_key() {
        assert!(is_valid_private_key(&"a".repeat(64)));
        assert!(!is_valid_private_key(&"a".repeat(63)));
        assert!(!is_valid_private_key(&"g".repeat(64)));
    }
}
