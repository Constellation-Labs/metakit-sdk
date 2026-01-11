//! Codec Utilities
//!
//! Encoding and decoding functions for Constellation data formats.

use base64::Engine;
use serde::de::DeserializeOwned;

use crate::types::{Result, SdkError, CONSTELLATION_PREFIX};

// Re-export binary encoding functions
pub use crate::binary::{encode_data_update, to_bytes};

/// Decode a DataUpdate back to JSON
///
/// # Arguments
/// * `data` - UTF-8 bytes with Constellation prefix
///
/// # Returns
/// Decoded data
///
/// # Example
/// ```
/// use constellation_sdk::codec::{encode_data_update, decode_data_update};
/// use serde_json::{json, Value};
///
/// let data = json!({"id": "test"});
/// let encoded = encode_data_update(&data).unwrap();
/// let decoded: Value = decode_data_update(&encoded).unwrap();
/// assert_eq!(decoded, data);
/// ```
pub fn decode_data_update<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    let s = String::from_utf8(data.to_vec())
        .map_err(|e| SdkError::SerializationError(e.to_string()))?;

    // Check for Constellation prefix
    if !s.starts_with(CONSTELLATION_PREFIX) {
        return Err(SdkError::SerializationError(
            "Invalid DataUpdate format: missing Constellation prefix".to_string(),
        ));
    }

    // Remove prefix and parse
    let rest = &s[CONSTELLATION_PREFIX.len()..];

    // Find the length line
    let parts: Vec<&str> = rest.splitn(2, '\n').collect();
    if parts.len() != 2 {
        return Err(SdkError::SerializationError(
            "Invalid DataUpdate format: missing length separator".to_string(),
        ));
    }

    let _length: usize = parts[0]
        .parse()
        .map_err(|_| SdkError::SerializationError("Invalid length in DataUpdate".to_string()))?;

    let base64_data = parts[1];

    // Decode base64
    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| SdkError::SerializationError(format!("Invalid base64: {e}")))?;

    // Parse JSON
    serde_json::from_slice(&decoded_bytes).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn test_roundtrip() {
        let data = json!({"id": "test", "value": 42});
        let encoded = encode_data_update(&data).unwrap();
        let decoded: Value = decode_data_update(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_invalid_prefix() {
        let data = b"invalid data";
        let result: Result<Value> = decode_data_update(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_format() {
        let data = format!("{CONSTELLATION_PREFIX}invalid");
        let result: Result<Value> = decode_data_update(data.as_bytes());
        assert!(result.is_err());
    }
}
