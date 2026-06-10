//! RFC 8785 canonicalizer conformance.
//!
//! Validates the canonical serializer against:
//!   * The ECMAScript `Number.toString` ground truth (the format the Scala
//!     DoubleSerializerImpl with `ecmaMode = true` produces, via `ryu-js`).
//!   * The cross-language `shared/test_vectors.json` `canonical_json` fields (real
//!     RFC 8785 objects with integers and strings, produced by the Scala/other SDKs).
//!   * UTF-16 code-unit key ordering and JCS string escaping.

use jlvm_core::canonical::canonicalize_string as canonicalize_string_result;
use jlvm_core::ratio::Ratio;
use jlvm_core::value::{decode_value, Value};
use num_bigint::BigInt;
use std::path::PathBuf;

/// Test shim: the canonicalizer is fallible (NaN/Infinity at the f64 boundary
/// -> Err); every vector in this file is canonicalizable.
fn canonicalize_string(v: &Value) -> String {
    canonicalize_string_result(v).expect("canonicalizable test value")
}

fn int(n: i64) -> Value {
    Value::Int(BigInt::from(n))
}

/// Build a Float value from a decimal string (exact rational), as the decoder would.
fn float(s: &str) -> Value {
    Value::Float(Ratio::parse_decimal(s).unwrap())
}

#[test]
fn numbers_match_ecmascript_tostring() {
    // Integers go through f64 then ryu-js, matching the Scala canonicalizer.
    assert_eq!(canonicalize_string(&int(42)), "42");
    assert_eq!(canonicalize_string(&int(0)), "0");
    assert_eq!(canonicalize_string(&int(5)), "5");
    assert_eq!(canonicalize_string(&int(-7)), "-7");

    // Floats (exact rationals) -> f64 -> ECMAScript shortest.
    assert_eq!(canonicalize_string(&float("3.14")), "3.14");
    assert_eq!(canonicalize_string(&float("3.5")), "3.5");
    assert_eq!(canonicalize_string(&float("0.1")), "0.1");
    assert_eq!(canonicalize_string(&float("123456.789")), "123456.789");

    // Scientific-notation thresholds (ECMAScript: exp >= 21 or <= -7 uses e-notation).
    assert_eq!(canonicalize_string(&float("0.0000001")), "1e-7");
    assert_eq!(canonicalize_string(&float("1e21")), "1e+21");
}

#[test]
fn negative_zero_renders_as_zero() {
    // Scala special-cases value == 0.0 -> "0" (covers -0.0 too).
    assert_eq!(canonicalize_string(&float("-0")), "0");
}

#[test]
fn keys_sorted_by_utf16_code_unit() {
    let v = Value::Map(vec![
        ("c".into(), int(3)),
        ("a".into(), int(1)),
        ("b".into(), int(2)),
    ]);
    assert_eq!(canonicalize_string(&v), "{\"a\":1,\"b\":2,\"c\":3}");
}

#[test]
fn nested_objects_and_arrays() {
    let v = Value::Map(vec![(
        "outer".into(),
        Value::Map(vec![("b".into(), int(2)), ("a".into(), int(1))]),
    )]);
    assert_eq!(canonicalize_string(&v), "{\"outer\":{\"a\":1,\"b\":2}}");

    let arr = Value::Array(vec![int(3), int(1), int(2)]);
    assert_eq!(canonicalize_string(&arr), "[3,1,2]");
}

#[test]
fn string_escaping_matches_jcs() {
    let v = Value::Str("a\"b\\c\n\t\r\u{0008}\u{000C}\u{0001}".into());
    // C0 controls without a short escape use lowercase \u00XX, matching Scala's
    // `\\u${c.toInt}%04x`. Short escapes: \" \\ \n \t \r \b \f.
    assert_eq!(
        canonicalize_string(&v),
        "\"a\\\"b\\\\c\\n\\t\\r\\b\\f\\u0001\""
    );
}

#[test]
fn non_finite_f64_boundary_is_err_not_abort() {
    // Int(10^999) (reachable via {"pow":[10,999]}) overflows the f64 boundary;
    // the canonicalizer must return a normal Err, not panic/abort.
    let huge = Value::Int(BigInt::from(10).pow(999));
    let err = canonicalize_string_result(&huge).unwrap_err();
    assert!(err.contains("NaN/Infinity"), "unexpected error: {err}");
    // Nested inside containers too (no panic mid-encode).
    let nested = Value::Map(vec![("x".into(), Value::Array(vec![huge]))]);
    assert!(canonicalize_string_result(&nested).is_err());
}

#[test]
fn matches_shared_canonical_vectors() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("shared/test_vectors.json");
    let text = std::fs::read_to_string(&path).expect("read test_vectors.json");
    let arr: Vec<serde_json::Value> = serde_json::from_str(&text).expect("valid JSON");

    let mut checked = 0;
    for entry in &arr {
        let data = decode_value(&entry["data"]);
        let expected = entry["canonical_json"]
            .as_str()
            .expect("canonical_json string");
        let got = canonicalize_string(&data);
        assert_eq!(
            got, expected,
            "canonicalization mismatch for {:?}",
            entry["data"]
        );
        checked += 1;
    }
    assert!(checked > 0, "no canonical vectors checked");
    eprintln!("canonicalizer matched {} shared RFC 8785 vectors", checked);
}
