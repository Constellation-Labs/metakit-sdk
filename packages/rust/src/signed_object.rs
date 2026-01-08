//! High-Level Signed Object API
//!
//! Convenience functions for creating and managing signed objects.

use serde::Serialize;

use crate::sign::{sign, sign_data_update};
use crate::types::{Result, SdkError, Signed};

/// Create a signed object with a single signature
///
/// # Arguments
/// * `value` - Any serializable object
/// * `private_key` - Private key in hex format
/// * `is_data_update` - Whether to sign as DataUpdate
///
/// # Returns
/// Signed object ready for submission
///
/// # Example
/// ```
/// use constellation_sdk::signed_object::create_signed_object;
/// use constellation_sdk::wallet::generate_key_pair;
/// use serde_json::json;
///
/// let key_pair = generate_key_pair();
///
/// // Sign a regular data object
/// let signed = create_signed_object(&json!({"id": "test"}), &key_pair.private_key, false).unwrap();
///
/// // Sign as DataUpdate for L1 submission
/// let signed_update = create_signed_object(&json!({"id": "test"}), &key_pair.private_key, true).unwrap();
/// ```
pub fn create_signed_object<T: Serialize + Clone>(
    value: &T,
    private_key: &str,
    is_data_update: bool,
) -> Result<Signed<T>> {
    let proof = if is_data_update {
        sign_data_update(value, private_key)?
    } else {
        sign(value, private_key)?
    };

    Ok(Signed {
        value: value.clone(),
        proofs: vec![proof],
    })
}

/// Add an additional signature to an existing signed object
///
/// This allows building multi-signature objects where multiple parties
/// need to sign the same data.
///
/// # Arguments
/// * `signed` - Existing signed object
/// * `private_key` - Private key in hex format
/// * `is_data_update` - Whether to sign as DataUpdate (must match original signing)
///
/// # Returns
/// New signed object with additional proof
///
/// # Example
/// ```
/// use constellation_sdk::signed_object::{create_signed_object, add_signature};
/// use constellation_sdk::wallet::generate_key_pair;
/// use serde_json::json;
///
/// let key1 = generate_key_pair();
/// let key2 = generate_key_pair();
///
/// // First party signs
/// let mut signed = create_signed_object(&json!({"id": "test"}), &key1.private_key, false).unwrap();
///
/// // Second party adds signature
/// signed = add_signature(signed, &key2.private_key, false).unwrap();
///
/// // Now has 2 proofs
/// assert_eq!(signed.proofs.len(), 2);
/// ```
pub fn add_signature<T: Serialize + Clone>(
    signed: Signed<T>,
    private_key: &str,
    is_data_update: bool,
) -> Result<Signed<T>> {
    let new_proof = if is_data_update {
        sign_data_update(&signed.value, private_key)?
    } else {
        sign(&signed.value, private_key)?
    };

    let mut proofs = signed.proofs;
    proofs.push(new_proof);

    Ok(Signed {
        value: signed.value,
        proofs,
    })
}

/// Create a signed object with multiple signatures at once
///
/// Useful when you have access to multiple private keys and want
/// to create a multi-sig object in one operation.
///
/// # Arguments
/// * `value` - Any serializable object
/// * `private_keys` - Array of private keys in hex format
/// * `is_data_update` - Whether to sign as DataUpdate
///
/// # Returns
/// Signed object with multiple proofs
///
/// # Example
/// ```
/// use constellation_sdk::signed_object::batch_sign;
/// use constellation_sdk::wallet::generate_key_pair;
/// use serde_json::json;
///
/// let key1 = generate_key_pair();
/// let key2 = generate_key_pair();
/// let key3 = generate_key_pair();
///
/// let signed = batch_sign(
///     &json!({"id": "test"}),
///     &[&key1.private_key, &key2.private_key, &key3.private_key],
///     false
/// ).unwrap();
///
/// assert_eq!(signed.proofs.len(), 3);
/// ```
pub fn batch_sign<T: Serialize + Clone>(
    value: &T,
    private_keys: &[&str],
    is_data_update: bool,
) -> Result<Signed<T>> {
    if private_keys.is_empty() {
        return Err(SdkError::NoPrivateKeys);
    }

    let proofs: Result<Vec<_>> = private_keys
        .iter()
        .map(|key| {
            if is_data_update {
                sign_data_update(value, key)
            } else {
                sign(value, key)
            }
        })
        .collect();

    Ok(Signed {
        value: value.clone(),
        proofs: proofs?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verify;
    use crate::wallet::generate_key_pair;
    use serde_json::json;

    #[test]
    fn test_create_signed_object() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test", "value": 42});

        let signed = create_signed_object(&data, &key_pair.private_key, false).unwrap();
        assert_eq!(signed.proofs.len(), 1);

        let result = verify(&signed, false);
        assert!(result.is_valid);
    }

    #[test]
    fn test_create_signed_object_data_update() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});

        let signed = create_signed_object(&data, &key_pair.private_key, true).unwrap();
        assert_eq!(signed.proofs.len(), 1);

        let result = verify(&signed, true);
        assert!(result.is_valid);
    }

    #[test]
    fn test_add_signature() {
        let key1 = generate_key_pair();
        let key2 = generate_key_pair();
        let data = json!({"id": "test"});

        let signed = create_signed_object(&data, &key1.private_key, false).unwrap();
        let signed = add_signature(signed, &key2.private_key, false).unwrap();

        assert_eq!(signed.proofs.len(), 2);

        let result = verify(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 2);
    }

    #[test]
    fn test_batch_sign() {
        let key1 = generate_key_pair();
        let key2 = generate_key_pair();
        let key3 = generate_key_pair();
        let data = json!({"id": "test"});

        let signed = batch_sign(
            &data,
            &[&key1.private_key, &key2.private_key, &key3.private_key],
            false,
        )
        .unwrap();

        assert_eq!(signed.proofs.len(), 3);

        let result = verify(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 3);
    }

    #[test]
    fn test_batch_sign_empty_keys() {
        let data = json!({"id": "test"});
        let result = batch_sign::<serde_json::Value>(&data, &[], false);
        assert!(result.is_err());
    }
}
