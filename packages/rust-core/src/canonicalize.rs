//! JSON Canonicalization (RFC 8785) with server-aligned null dropping
//!
//! Provides deterministic JSON serialization according to RFC 8785, preceded
//! by the normative content-hash transformation: null-valued OBJECT fields are
//! recursively dropped (array nulls are preserved) before canonicalizing, so
//! the bytes produced for signing/verification agree with what the
//! authoritative Scala server (metakit `JsonBinaryCodec.dropNulls`) and the
//! TypeScript SDK (`dropNullFields`) re-derive. See metakit
//! `docs/content-hash.md` for the full rule.

use serde::Serialize;
use serde_json::Value;
use serde_json_canonicalizer::to_vec as canonicalize_to_vec;

use crate::types::{Result, SdkError};

/// Recursively drop null-valued object fields (server-aligned)
///
/// Behavior — byte-for-byte matched to metakit's `JsonBinaryCodec.dropNulls`
/// and the TypeScript SDK's `dropNullFields`:
/// * Object members whose value is `null` are removed, at every nesting level.
/// * `null` ELEMENTS inside arrays are preserved (removing them would shift
///   indices and change positional meaning).
/// * Scalars pass through untouched.
///
/// This makes `Option::None` (serialized as an explicit `null`) byte-identical
/// to an absent field, so adding optional fields to a schema never changes the
/// hashes or signatures of previously produced data.
///
/// # Example
/// ```
/// use constellation_sdk_core::canonicalize::drop_null_fields;
/// use serde_json::json;
///
/// let cleaned = drop_null_fields(json!({"a": 1, "b": null, "c": [1, null]}));
/// assert_eq!(cleaned, json!({"a": 1, "c": [1, null]}));
/// ```
pub fn drop_null_fields(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(drop_null_fields).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, drop_null_fields(v)))
                .collect(),
        ),
        other => other,
    }
}

/// Canonicalize data to a JSON string according to RFC 8785
///
/// Null-valued object fields are dropped before canonicalization to match the
/// authoritative Scala server (see [`drop_null_fields`]). This makes the bytes
/// produced for signing/verification here agree with what the chain
/// re-derives.
///
/// # Arguments
/// * `data` - Any serializable data
///
/// # Returns
/// Canonical JSON string
///
/// # Example
/// ```
/// use constellation_sdk_core::canonicalize::canonicalize;
/// use serde_json::json;
///
/// let data = json!({"b": 2, "a": 1});
/// let canonical = canonicalize(&data).unwrap();
/// assert_eq!(canonical, r#"{"a":1,"b":2}"#);
///
/// // Null object-fields are dropped (server-aligned):
/// let canonical = canonicalize(&json!({"a": null, "b": 1})).unwrap();
/// assert_eq!(canonical, r#"{"b":1}"#);
/// ```
pub fn canonicalize<T: Serialize>(data: &T) -> Result<String> {
    let bytes = canonicalize_bytes(data)?;
    String::from_utf8(bytes).map_err(|e| SdkError::SerializationError(e.to_string()))
}

/// Canonicalize data to UTF-8 bytes according to RFC 8785
///
/// Null-valued object fields are dropped before canonicalization
/// (see [`drop_null_fields`]).
///
/// # Arguments
/// * `data` - Any serializable data
///
/// # Returns
/// Canonical JSON as UTF-8 bytes
pub fn canonicalize_bytes<T: Serialize>(data: &T) -> Result<Vec<u8>> {
    let value =
        serde_json::to_value(data).map_err(|e| SdkError::SerializationError(e.to_string()))?;
    let cleaned = drop_null_fields(value);
    canonicalize_to_vec(&cleaned).map_err(|e| SdkError::SerializationError(e.to_string()))
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

    #[test]
    fn test_drop_null_fields_recursive() {
        let data = json!({"a": 1, "b": null, "c": {"d": null, "e": 2}});
        assert_eq!(drop_null_fields(data), json!({"a": 1, "c": {"e": 2}}));
    }

    #[test]
    fn test_drop_null_fields_preserves_array_nulls() {
        let data = json!({"xs": [1, null, 3]});
        assert_eq!(drop_null_fields(data), json!({"xs": [1, null, 3]}));
    }

    #[test]
    fn test_drop_null_fields_inside_array_elements() {
        let data = json!([{"a": null, "b": 1}, null]);
        assert_eq!(drop_null_fields(data), json!([{"b": 1}, null]));
    }

    #[test]
    fn test_canonicalize_drops_null_object_fields() {
        let data = json!({"a": null, "b": 1});
        assert_eq!(canonicalize(&data).unwrap(), r#"{"b":1}"#);
    }

    #[test]
    fn test_canonicalize_absent_equals_explicit_null() {
        let with_null = json!({"id": "test", "value": 42, "nested": null});
        let absent = json!({"id": "test", "value": 42});
        assert_eq!(
            canonicalize(&with_null).unwrap(),
            canonicalize(&absent).unwrap()
        );
    }
}
