//! High-level signed-object API for P-256 (secp256r1).
//!
//! Mirrors `crate::signed_object` (K1) but produces R1 proofs.

use serde::Serialize;

use crate::r1::sign::{sign, sign_data_update};
use crate::types::{Result, SdkError, Signed};

/// Create a signed object with a single P-256 signature.
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

/// Add an additional P-256 signature to an existing signed object.
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

/// Create a signed object with multiple P-256 signatures at once.
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
    use crate::r1::verify::verify;
    use crate::r1::wallet::generate_key_pair;
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
