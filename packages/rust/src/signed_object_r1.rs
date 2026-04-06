//! High-Level Signed Object API for secp256r1 (P-256)
//!
//! Convenience functions for creating and managing signed objects using P-256.

use serde::Serialize;

use crate::sign_r1::{sign_data_update_r1, sign_r1};
use crate::types::{Result, SdkError, Signed};

/// Create a signed object with a single P-256 signature
///
/// # Arguments
/// * `value` - Any serializable object
/// * `private_key` - P-256 private key in hex format
/// * `is_data_update` - Whether to sign as DataUpdate
pub fn create_signed_object_r1<T: Serialize + Clone>(
    value: &T,
    private_key: &str,
    is_data_update: bool,
) -> Result<Signed<T>> {
    let proof = if is_data_update {
        sign_data_update_r1(value, private_key)?
    } else {
        sign_r1(value, private_key)?
    };

    Ok(Signed {
        value: value.clone(),
        proofs: vec![proof],
    })
}

/// Add an additional P-256 signature to an existing signed object
pub fn add_signature_r1<T: Serialize + Clone>(
    signed: Signed<T>,
    private_key: &str,
    is_data_update: bool,
) -> Result<Signed<T>> {
    let new_proof = if is_data_update {
        sign_data_update_r1(&signed.value, private_key)?
    } else {
        sign_r1(&signed.value, private_key)?
    };

    let mut proofs = signed.proofs;
    proofs.push(new_proof);

    Ok(Signed {
        value: signed.value,
        proofs,
    })
}

/// Create a signed object with multiple P-256 signatures at once
pub fn batch_sign_r1<T: Serialize + Clone>(
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
                sign_data_update_r1(value, key)
            } else {
                sign_r1(value, key)
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
    use crate::verify_r1::verify_r1;
    use crate::wallet_r1::generate_key_pair_r1;
    use serde_json::json;

    #[test]
    fn test_create_signed_object_r1() {
        let key_pair = generate_key_pair_r1();
        let data = json!({"id": "test", "value": 42});

        let signed = create_signed_object_r1(&data, &key_pair.private_key, false).unwrap();
        assert_eq!(signed.proofs.len(), 1);

        let result = verify_r1(&signed, false);
        assert!(result.is_valid);
    }

    #[test]
    fn test_add_signature_r1() {
        let key1 = generate_key_pair_r1();
        let key2 = generate_key_pair_r1();
        let data = json!({"id": "test"});

        let signed = create_signed_object_r1(&data, &key1.private_key, false).unwrap();
        let signed = add_signature_r1(signed, &key2.private_key, false).unwrap();

        assert_eq!(signed.proofs.len(), 2);

        let result = verify_r1(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 2);
    }

    #[test]
    fn test_batch_sign_r1() {
        let key1 = generate_key_pair_r1();
        let key2 = generate_key_pair_r1();
        let key3 = generate_key_pair_r1();
        let data = json!({"id": "test"});

        let signed = batch_sign_r1(
            &data,
            &[&key1.private_key, &key2.private_key, &key3.private_key],
            false,
        )
        .unwrap();

        assert_eq!(signed.proofs.len(), 3);

        let result = verify_r1(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 3);
    }

    #[test]
    fn test_batch_sign_empty_keys_r1() {
        let data = json!({"id": "test"});
        let result = batch_sign_r1::<serde_json::Value>(&data, &[], false);
        assert!(result.is_err());
    }
}
