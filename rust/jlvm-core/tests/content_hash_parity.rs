//! Parity: `jlvm_core::content_hash` vs the Rust SDK (`packages/rust`).
//!
//! The SDK's `drop_null_fields` + `canonicalize_bytes` + `hash_data` are the
//! reference client implementation of the metakit content-hash rule
//! (docs/content-hash.md), already cross-pinned against the TypeScript SDK and
//! the Scala server. `content_hash` (the wasm/mobile signer primitive in this
//! crate) must agree with them on every input.

use constellation_sdk::canonicalize::{canonicalize_bytes, drop_null_fields};
use constellation_sdk::hash::hash_bytes;
use jlvm_core::content_hash::{content_hash, content_hash_bytes, drop_nulls};
use serde_json::{json, Value};

fn fixtures() -> Vec<Value> {
    vec![
        json!(null),
        json!(42),
        json!(-7.25),
        json!("héllo \"world\"\n"),
        json!({"a": 1, "b": null, "c": {"d": null, "e": 2}}),
        json!({"xs": [1, null, 3], "ys": []}),
        json!([{"a": null, "b": 1}, null, [null, {"z": null}]]),
        json!({"": null, "k": {"": [null]}}),
        // UTF-16 key-order stressor: BMP vs surrogate-pair keys
        json!({"\u{ff}": 1, "\u{1d11e}": 2, "A": null, "a": 3}),
        // metakit src/test/resources/input/arrays.json
        json!([56, {"d": true, "10": null, "1": []}]),
        json!({"deep": {"deeper": {"deepest": null, "kept": [null, {"x": null, "y": 0}]}}}),
    ]
}

#[test]
fn drop_nulls_matches_sdk_drop_null_fields() {
    for fixture in fixtures() {
        assert_eq!(
            drop_nulls(fixture.clone()),
            drop_null_fields(fixture.clone()),
            "drop-nulls divergence on {fixture}"
        );
    }
}

#[test]
fn content_hash_bytes_match_sdk_canonical_bytes() {
    for fixture in fixtures() {
        assert_eq!(
            content_hash_bytes(&fixture).unwrap(),
            canonicalize_bytes(&fixture).unwrap(),
            "canonical-bytes divergence on {fixture}"
        );
    }
}

#[test]
fn content_hash_matches_sdk_hash() {
    for fixture in fixtures() {
        let ours = content_hash(&fixture).unwrap();
        let sdk = hash_bytes(&canonicalize_bytes(&fixture).unwrap());
        assert_eq!(
            hex(&ours),
            sdk.value,
            "content-hash divergence on {fixture}"
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
