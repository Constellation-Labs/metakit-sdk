//! Wallet and Key Management Utilities
//!
//! Functions for generating and managing cryptographic keys.

use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::types::{KeyPair, Result, SdkError};

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Generate a new random key pair
///
/// # Example
/// ```
/// use constellation_sdk::wallet::generate_key_pair;
///
/// let key_pair = generate_key_pair();
/// println!("Address: {}", key_pair.address);
/// println!("Private key: {}", key_pair.private_key);
/// println!("Public key: {}", key_pair.public_key);
/// ```
pub fn generate_key_pair() -> KeyPair {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    let private_key_hex = hex::encode(secret_key.secret_bytes());
    let public_key_hex = hex::encode(public_key.serialize_uncompressed());
    let address = get_address(&public_key_hex);

    KeyPair {
        private_key: private_key_hex,
        public_key: public_key_hex,
        address,
    }
}

/// Derive a key pair from an existing private key
///
/// # Arguments
/// * `private_key` - Private key in hex format (64 characters)
///
/// # Example
/// ```
/// use constellation_sdk::wallet::{generate_key_pair, key_pair_from_private_key};
///
/// let original = generate_key_pair();
/// let derived = key_pair_from_private_key(&original.private_key).unwrap();
/// assert_eq!(original.public_key, derived.public_key);
/// ```
pub fn key_pair_from_private_key(private_key: &str) -> Result<KeyPair> {
    if !is_valid_private_key(private_key) {
        return Err(SdkError::InvalidPrivateKey(
            "Invalid private key format".to_string(),
        ));
    }

    let secp = Secp256k1::new();
    let private_key_bytes = hex::decode(private_key)?;
    let secret_key = SecretKey::from_slice(&private_key_bytes)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let public_key_hex = hex::encode(public_key.serialize_uncompressed());
    let address = get_address(&public_key_hex);

    Ok(KeyPair {
        private_key: private_key.to_string(),
        public_key: public_key_hex,
        address,
    })
}

/// Get the public key hex from a private key
///
/// # Arguments
/// * `private_key` - Private key in hex format
/// * `compressed` - If true, returns compressed public key (33 bytes)
pub fn get_public_key_hex(private_key: &str, compressed: bool) -> Result<String> {
    let private_key_bytes = hex::decode(private_key)?;
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    if compressed {
        Ok(hex::encode(public_key.serialize()))
    } else {
        Ok(hex::encode(public_key.serialize_uncompressed()))
    }
}

/// Get the public key ID (without 04 prefix) from a private key
///
/// This format is used in SignatureProof.id
///
/// # Arguments
/// * `private_key` - Private key in hex format
///
/// # Returns
/// Public key ID (128 characters, no 04 prefix)
pub fn get_public_key_id(private_key: &str) -> Result<String> {
    let public_key = get_public_key_hex(private_key, false)?;
    Ok(normalize_public_key_to_id(&public_key))
}

/// Get DAG address from a public key
///
/// Uses Constellation's address derivation:
/// 1. Normalize public key to include 04 prefix
/// 2. Prepend PKCS prefix (X.509 DER encoding header)
/// 3. SHA-256 hash
/// 4. Base58 encode
/// 5. Take last 36 characters
/// 6. Calculate parity digit (sum of numeric characters mod 9)
/// 7. Result: DAG + parity + last36
///
/// # Arguments
/// * `public_key` - Public key in hex format (with or without 04 prefix)
pub fn get_address(public_key: &str) -> String {
    // PKCS prefix for X.509 DER encoding (secp256k1)
    const PKCS_PREFIX: &str = "3056301006072a8648ce3d020106052b8104000a034200";

    // Normalize public key to include 04 prefix
    let normalized_key = normalize_public_key(public_key);

    // Prepend PKCS prefix
    let pkcs_encoded = format!("{PKCS_PREFIX}{normalized_key}");

    // SHA-256 hash
    let pkcs_bytes = hex::decode(&pkcs_encoded).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&pkcs_bytes);
    let hash = hasher.finalize();

    // Base58 encode
    let encoded = base58_encode(&hash);

    // Take last 36 characters
    let last36 = if encoded.len() > 36 {
        &encoded[encoded.len() - 36..]
    } else {
        &encoded
    };

    // Calculate parity digit (sum of numeric characters mod 9)
    let digit_sum: u32 = last36
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap_or(0))
        .sum();
    let parity = digit_sum % 9;

    // Return with DAG prefix, parity, and last36
    format!("DAG{parity}{last36}")
}

/// Validate that a private key is correctly formatted
///
/// # Arguments
/// * `private_key` - Private key to validate
///
/// # Returns
/// true if valid hex string of correct length
pub fn is_valid_private_key(private_key: &str) -> bool {
    if private_key.len() != 64 {
        return false;
    }
    private_key.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate that a public key is correctly formatted
///
/// # Arguments
/// * `public_key` - Public key to validate
///
/// # Returns
/// true if valid hex string of correct length
pub fn is_valid_public_key(public_key: &str) -> bool {
    // With 04 prefix: 130 chars, without: 128 chars
    if public_key.len() != 128 && public_key.len() != 130 {
        return false;
    }
    public_key.chars().all(|c| c.is_ascii_hexdigit())
}

/// Normalize public key to include 04 prefix
pub fn normalize_public_key(public_key: &str) -> String {
    if public_key.len() == 128 {
        format!("04{public_key}")
    } else {
        public_key.to_string()
    }
}

/// Normalize public key to ID format (without 04 prefix)
pub fn normalize_public_key_to_id(public_key: &str) -> String {
    if public_key.len() == 130 && public_key.starts_with("04") {
        public_key[2..].to_string()
    } else {
        public_key.to_string()
    }
}

/// Base58 encode bytes using Bitcoin/Constellation alphabet
fn base58_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to big integer representation
    let mut num: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in data {
        let mut carry = byte as u32;
        for digit in num.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            num.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // Build result string
    let mut result = String::with_capacity(leading_zeros + num.len());

    // Add '1' for each leading zero byte
    for _ in 0..leading_zeros {
        result.push('1');
    }

    // Convert digits to characters
    for &digit in num.iter().rev() {
        result.push(BASE58_ALPHABET[digit as usize] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let key_pair = generate_key_pair();
        assert_eq!(key_pair.private_key.len(), 64);
        assert_eq!(key_pair.public_key.len(), 130);
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
    fn test_is_valid_private_key() {
        assert!(is_valid_private_key(&"a".repeat(64)));
        assert!(!is_valid_private_key(&"a".repeat(63)));
        assert!(!is_valid_private_key(&"g".repeat(64)));
    }

    #[test]
    fn test_is_valid_public_key() {
        assert!(is_valid_public_key(&"a".repeat(128)));
        assert!(is_valid_public_key(&"a".repeat(130)));
        assert!(!is_valid_public_key(&"a".repeat(127)));
    }
}
