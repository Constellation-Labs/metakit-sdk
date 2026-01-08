//! Binary Encoding
//!
//! Functions for encoding data to binary format for signing.

use base64::Engine;
use serde::Serialize;

use crate::canonicalize::canonicalize_bytes;
use crate::types::{Result, CONSTELLATION_PREFIX};

/// Convert data to bytes for signing
///
/// # Arguments
/// * `data` - Any serializable data
/// * `is_data_update` - Whether to encode as a DataUpdate (with Constellation prefix)
///
/// # Returns
/// UTF-8 bytes ready for hashing
///
/// # Example
/// ```
/// use constellation_sdk::binary::to_bytes;
/// use serde_json::json;
///
/// let data = json!({"id": "test"});
/// let bytes = to_bytes(&data, false).unwrap();
/// ```
pub fn to_bytes<T: Serialize>(data: &T, is_data_update: bool) -> Result<Vec<u8>> {
    let canonical_json = canonicalize_bytes(data)?;

    if is_data_update {
        // Add Constellation prefix for DataUpdate
        let base64_string = base64::engine::general_purpose::STANDARD.encode(&canonical_json);
        let wrapped_string = format!(
            "{}{}\n{}",
            CONSTELLATION_PREFIX,
            base64_string.len(),
            base64_string
        );
        Ok(wrapped_string.into_bytes())
    } else {
        Ok(canonical_json)
    }
}

/// Encode data as a DataUpdate (convenience wrapper)
///
/// This is equivalent to `to_bytes(data, true)`.
///
/// # Arguments
/// * `data` - Any serializable data
///
/// # Returns
/// UTF-8 bytes with Constellation prefix
pub fn encode_data_update<T: Serialize>(data: &T) -> Result<Vec<u8>> {
    to_bytes(data, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_to_bytes_regular() {
        let data = json!({"id": "test", "value": 42});
        let bytes = to_bytes(&data, false).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"id":"test","value":42}"#);
    }

    #[test]
    fn test_to_bytes_data_update() {
        let data = json!({"id": "test"});
        let bytes = to_bytes(&data, true).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("\x19Constellation Signed Data:\n"));
        assert!(s.contains('\n'));
    }

    #[test]
    fn test_encode_data_update() {
        let data = json!({"id": "test"});
        let bytes = encode_data_update(&data).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("\x19Constellation Signed Data:\n"));
    }
}
