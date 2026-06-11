//! Content-hash primitive for TYPED CONTENT (the wasm/mobile signer surface).
//!
//! Implements the normative content-hash rule from metakit
//! `docs/content-hash.md`:
//!
//! ```text
//! bytes = utf8( RFC8785( dropNulls( encode(content) ) ) )
//! digest = sha256( bytes )
//! ```
//!
//! ## TWO LAYERS — do not confuse them
//!
//! * **TYPED-CONTENT layer (this module).** Data updates, on-chain /
//!   calculated state, MPT leaf values — anything whose digest or signature
//!   another party recomputes from a *decoded* value. Here `null` and
//!   *absent* are the same thing (circe encodes `Option = None` as an
//!   explicit `null`; the server's `JsonBinaryCodec.dropNulls` strips it
//!   before hashing), so null OBJECT fields are recursively dropped and
//!   array nulls are preserved. This matches metakit
//!   `JsonBinaryCodec.dropNulls`, the TypeScript SDK's `dropNullFields`, and
//!   the Rust SDK's `drop_null_fields` (`packages/rust`).
//!
//! * **JLVM VALUE layer ([`crate::canonical`]).** Inside the VM, `null` is a
//!   real first-class value: `{"var":"x"}` on a missing key yields `Null`,
//!   `{"==":[null, ...]}` compares it, and the evaluator's canonical result
//!   bytes ([`crate::canonical::canonicalize`]) MUST keep nulls so evaluation
//!   results stay byte-identical with the Scala evaluator. NEVER route VM
//!   evaluation results through this module.
//!
//! The canonicalization internals (UTF-16 key sort, JCS escaping, f64 number
//! boundary) are shared with [`crate::canonical`] via
//! [`crate::canonical::canonicalize_json`] — this module only adds the
//! drop-nulls preprocessing and the sha256 digest.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Recursively drop null-valued OBJECT fields; PRESERVE array nulls.
///
/// Byte-for-byte matched to metakit's `JsonBinaryCodec.dropNulls`, the
/// TypeScript SDK's `dropNullFields`, and the Rust SDK's `drop_null_fields`:
///
/// * Object fields whose value is null are removed, recursively.
/// * Array elements are NEVER removed — null elements are positional and
///   preserved; nested objects inside arrays are still cleaned.
/// * Primitives (including a top-level null) pass through unchanged.
///
/// # Example
/// ```
/// use jlvm_core::content_hash::drop_nulls;
/// use serde_json::json;
///
/// let cleaned = drop_nulls(json!({"a": 1, "b": null, "c": [1, null]}));
/// assert_eq!(cleaned, json!({"a": 1, "c": [1, null]}));
/// ```
pub fn drop_nulls(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(drop_nulls).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, drop_nulls(v)))
                .collect(),
        ),
        other => other,
    }
}

/// The content-hash pre-image: `utf8( RFC8785( dropNulls(value) ) )`.
///
/// These are the exact bytes the server hashes/signs for typed content, so a
/// signer (wasm/mobile) can feed them straight into the signature protocol.
///
/// Errors only if a number fails the f64 canonical boundary (unreachable for
/// `serde_json::Value` without `arbitrary_precision` — see
/// [`crate::canonical::canonicalize_json`]).
pub fn content_hash_bytes(value: &Value) -> Result<Vec<u8>, String> {
    crate::canonical::canonicalize_json(&drop_nulls(value.clone()))
}

/// The content hash: `sha256( content_hash_bytes(value) )`.
///
/// This is the digest metakit's `JsonBinaryHasher` pins for typed content
/// (e.g. the `arrays.json` fixture in `JsonBinaryHasherSuite`).
pub fn content_hash(value: &Value) -> Result<[u8; 32], String> {
    Ok(sha256(&content_hash_bytes(value)?))
}

/// SHA-256 digest helper over raw bytes.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn drop_nulls_recursive() {
        let data = json!({"a": 1, "b": null, "c": {"d": null, "e": 2}});
        assert_eq!(drop_nulls(data), json!({"a": 1, "c": {"e": 2}}));
    }

    #[test]
    fn drop_nulls_preserves_array_nulls() {
        let data = json!({"xs": [1, null, 3]});
        assert_eq!(drop_nulls(data), json!({"xs": [1, null, 3]}));
    }

    #[test]
    fn drop_nulls_cleans_objects_inside_arrays() {
        let data = json!([{"a": null, "b": 1}, null]);
        assert_eq!(drop_nulls(data), json!([{"b": 1}, null]));
    }

    #[test]
    fn drop_nulls_passes_primitives_through() {
        assert_eq!(drop_nulls(json!(null)), json!(null));
        assert_eq!(drop_nulls(json!(42)), json!(42));
        assert_eq!(drop_nulls(json!("x")), json!("x"));
    }

    #[test]
    fn absent_equals_explicit_null() {
        let with_null = json!({"a": 1, "b": null, "c": {"d": null, "e": 2}, "f": [1, null, 3]});
        let absent = json!({"a": 1, "c": {"e": 2}, "f": [1, null, 3]});
        assert_eq!(
            content_hash_bytes(&with_null).unwrap(),
            content_hash_bytes(&absent).unwrap()
        );
        assert_eq!(
            content_hash(&with_null).unwrap(),
            content_hash(&absent).unwrap()
        );
    }

    #[test]
    fn array_nulls_change_the_hash() {
        let a = content_hash(&json!({"xs": [1, null, 3]})).unwrap();
        let b = content_hash(&json!({"xs": [1, 3]})).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn matches_scala_arrays_fixture_hash() {
        // metakit src/test/resources/input/arrays.json
        let data = json!([56, {"d": true, "10": null, "1": []}]);

        // null "10" dropped, keys sorted — identical to metakit's canonical form
        let bytes = content_hash_bytes(&data).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"[56,{"1":[],"d":true}]"#
        );

        // sha256 over the canonical bytes — pinned in metakit
        // JsonBinaryHasherSuite: "arrays.json should produce a known hash"
        assert_eq!(
            hex(&content_hash(&data).unwrap()),
            "060ba9d4be65e7b773f67328b6fd6a5360f8f66ef88d57351dbc6e39b46f2ea9"
        );
    }
}
