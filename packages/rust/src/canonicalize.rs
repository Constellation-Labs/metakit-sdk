//! JSON Canonicalization (RFC 8785)
//!
//! Provides deterministic JSON serialization according to RFC 8785.

use serde::Serialize;
use serde_json_canonicalizer::to_vec as canonicalize_to_vec;

use crate::types::{Result, SdkError};

/// Canonicalize data to a JSON string according to RFC 8785
///
/// # Arguments
/// * `data` - Any serializable data
///
/// # Returns
/// Canonical JSON string
///
/// # Example
/// ```
/// use constellation_sdk::canonicalize::canonicalize;
/// use serde_json::json;
///
/// let data = json!({"b": 2, "a": 1});
/// let canonical = canonicalize(&data).unwrap();
/// assert_eq!(canonical, r#"{"a":1,"b":2}"#);
/// ```
pub fn canonicalize<T: Serialize>(data: &T) -> Result<String> {
    let bytes = canonicalize_to_vec(data).map_err(|e| SdkError::SerializationError(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| SdkError::SerializationError(e.to_string()))
}

/// Canonicalize data to UTF-8 bytes according to RFC 8785
///
/// # Arguments
/// * `data` - Any serializable data
///
/// # Returns
/// Canonical JSON as UTF-8 bytes
pub fn canonicalize_bytes<T: Serialize>(data: &T) -> Result<Vec<u8>> {
    canonicalize_to_vec(data).map_err(|e| SdkError::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonicalize_sorts_keys() {
        let data = json!({"c": 3, "a": 1, "b": 2});
        let canonical = canonicalize(&data).unwrap();
        assert_eq!(canonical, r#"{"a":1,"b":2,"c":3}"#);
    }

    #[test]
    fn test_canonicalize_removes_whitespace() {
        let data = json!({
            "name": "test",
            "value": 42
        });
        let canonical = canonicalize(&data).unwrap();
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
    }

    #[test]
    fn test_canonicalize_nested_objects() {
        let data = json!({
            "outer": {
                "b": 2,
                "a": 1
            }
        });
        let canonical = canonicalize(&data).unwrap();
        assert_eq!(canonical, r#"{"outer":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_canonicalize_arrays() {
        let data = json!([3, 1, 2]);
        let canonical = canonicalize(&data).unwrap();
        // Arrays maintain order
        assert_eq!(canonical, "[3,1,2]");
    }

    #[test]
    fn test_canonicalize_bytes() {
        let data = json!({"id": "test"});
        let bytes = canonicalize_bytes(&data).unwrap();
        assert_eq!(bytes, br#"{"id":"test"}"#);
    }
}
