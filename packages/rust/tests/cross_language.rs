//! Cross-language compatibility tests
//!
//! Verifies that the Rust implementation produces identical results to
//! TypeScript, Python, and Go implementations.

use constellation_sdk::{canonicalize, hash_bytes, to_bytes, verify_hash};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
struct TestVector {
    source: String,
    #[serde(rename = "type")]
    test_type: String,
    data: serde_json::Value,
    canonical_json: String,
    utf8_bytes_hex: String,
    sha256_hash_hex: String,
    signature_hex: String,
    public_key_hex: String,
}

fn load_test_vectors() -> Vec<TestVector> {
    let vectors_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("shared")
        .join("test_vectors.json");

    let content = fs::read_to_string(&vectors_path)
        .unwrap_or_else(|_| panic!("Failed to read test vectors from {vectors_path:?}"));

    serde_json::from_str(&content).expect("Failed to parse test vectors")
}

#[test]
fn canonicalization_matches_all_vectors() {
    let vectors = load_test_vectors();

    for vector in &vectors {
        let canonical = canonicalize(&vector.data).unwrap();
        assert_eq!(
            canonical, vector.canonical_json,
            "Canonicalization mismatch for {} vector: {:?}",
            vector.source, vector.data
        );
    }
}

#[test]
fn binary_encoding_matches_all_vectors() {
    let vectors = load_test_vectors();

    for vector in &vectors {
        let is_data_update = vector.test_type == "TestDataUpdate";
        let bytes = to_bytes(&vector.data, is_data_update).unwrap();
        let bytes_hex = hex::encode(&bytes);

        assert_eq!(
            bytes_hex, vector.utf8_bytes_hex,
            "Binary encoding mismatch for {} {} vector",
            vector.source, vector.test_type
        );
    }
}

#[test]
fn hashing_matches_all_vectors() {
    let vectors = load_test_vectors();

    for vector in &vectors {
        let is_data_update = vector.test_type == "TestDataUpdate";
        let bytes = to_bytes(&vector.data, is_data_update).unwrap();
        let hash = hash_bytes(&bytes);

        assert_eq!(
            hash.value, vector.sha256_hash_hex,
            "Hash mismatch for {} {} vector",
            vector.source, vector.test_type
        );
    }
}

#[test]
fn verifies_signatures_from_all_vectors() {
    let vectors = load_test_vectors();

    for vector in &vectors {
        let result = verify_hash(
            &vector.sha256_hash_hex,
            &vector.signature_hex,
            &vector.public_key_hex,
        );

        match result {
            Ok(is_valid) => {
                assert!(
                    is_valid,
                    "Failed to verify {} {} signature (valid=false)\nHash: {}\nSig: {}\nPubKey: {}",
                    vector.source,
                    vector.test_type,
                    vector.sha256_hash_hex,
                    vector.signature_hex,
                    vector.public_key_hex
                );
            }
            Err(e) => {
                panic!(
                    "Error verifying {} {} signature: {:?}\nHash: {}\nSig: {}\nPubKey: {}",
                    vector.source,
                    vector.test_type,
                    e,
                    vector.sha256_hash_hex,
                    vector.signature_hex,
                    vector.public_key_hex
                );
            }
        }
    }
}

#[test]
fn rejects_tampered_signatures() {
    let vectors = load_test_vectors();
    let vector = &vectors[0];

    // Tamper with the hash
    let tampered_hash = vector.sha256_hash_hex.replace("0", "1");
    let is_valid = verify_hash(
        &tampered_hash,
        &vector.signature_hex,
        &vector.public_key_hex,
    )
    .unwrap();

    assert!(!is_valid, "Should reject signature with tampered hash");
}

mod by_source_language {
    use super::*;

    fn test_language_vectors(language: &str) {
        let vectors = load_test_vectors();
        let lang_vectors: Vec<_> = vectors.iter().filter(|v| v.source == language).collect();

        assert!(
            !lang_vectors.is_empty(),
            "No test vectors found for {language}"
        );

        for vector in lang_vectors {
            // Test regular data
            if vector.test_type == "TestData" {
                let bytes = to_bytes(&vector.data, false).unwrap();
                let hash = hash_bytes(&bytes);

                assert_eq!(
                    hash.value, vector.sha256_hash_hex,
                    "{language} TestData hash mismatch"
                );

                let is_valid = verify_hash(
                    &vector.sha256_hash_hex,
                    &vector.signature_hex,
                    &vector.public_key_hex,
                )
                .unwrap();

                assert!(
                    is_valid,
                    "{language} TestData signature verification failed"
                );
            }

            // Test data update
            if vector.test_type == "TestDataUpdate" {
                let bytes = to_bytes(&vector.data, true).unwrap();
                let hash = hash_bytes(&bytes);

                assert_eq!(
                    hash.value, vector.sha256_hash_hex,
                    "{language} TestDataUpdate hash mismatch"
                );

                let is_valid = verify_hash(
                    &vector.sha256_hash_hex,
                    &vector.signature_hex,
                    &vector.public_key_hex,
                )
                .unwrap();

                assert!(
                    is_valid,
                    "{language} TestDataUpdate signature verification failed"
                );
            }
        }
    }

    #[test]
    fn verifies_python_vectors() {
        test_language_vectors("python");
    }

    #[test]
    fn verifies_javascript_vectors() {
        test_language_vectors("javascript");
    }

    #[test]
    fn verifies_rust_vectors() {
        test_language_vectors("rust");
    }

    #[test]
    fn verifies_go_vectors() {
        test_language_vectors("go");
    }
}

mod content_hash_rule {
    //! Pins the normative content-hash rule (metakit docs/content-hash.md):
    //! drop null OBJECT fields recursively, PRESERVE array nulls, then RFC 8785.
    //! The expected hash below is the exact value pinned by metakit's
    //! JsonBinaryHasherSuite for the same fixture (arrays.json), so Rust bytes
    //! are cross-checked against the Scala suite.

    use constellation_sdk::{canonicalize, hash_bytes};
    use serde_json::json;

    #[test]
    fn null_dropping_matches_scala_arrays_fixture() {
        // metakit src/test/resources/input/arrays.json
        let data = json!([56, {"d": true, "10": null, "1": []}]);
        let canonical = canonicalize(&data).unwrap();
        // null "10" dropped, keys sorted — identical to metakit's canonical form
        assert_eq!(canonical, r#"[56,{"1":[],"d":true}]"#);

        // sha256 over the canonical bytes — pinned in metakit JsonBinaryHasherSuite:
        // "arrays.json should produce a known hash"
        let hash = hash_bytes(canonical.as_bytes());
        assert_eq!(
            hash.value,
            "060ba9d4be65e7b773f67328b6fd6a5360f8f66ef88d57351dbc6e39b46f2ea9"
        );
    }

    #[test]
    fn absent_equals_explicit_null_for_signing_bytes() {
        use constellation_sdk::to_bytes;

        let with_null = json!({"a": 1, "b": null, "c": {"d": null, "e": 2}, "f": [1, null, 3]});
        let absent = json!({"a": 1, "c": {"e": 2}, "f": [1, null, 3]});

        assert_eq!(
            to_bytes(&with_null, true).unwrap(),
            to_bytes(&absent, true).unwrap()
        );
        assert_eq!(
            to_bytes(&with_null, false).unwrap(),
            to_bytes(&absent, false).unwrap()
        );
    }
}
