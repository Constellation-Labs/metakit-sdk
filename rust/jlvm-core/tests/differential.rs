//! Differential conformance harness.
//!
//! Loads `shared/json_logic_test_vectors.json` (the cross-language oracle), evaluates
//! each case with this Rust JLVM, and compares the result to the `expected` value in
//! two ways:
//!   1. STRUCTURAL: parse `expected` as JSON and the evaluated result (encoded back to
//!      JSON) and compare for deep equality with numeric tolerance for int-vs-int and
//!      float-vs-float. This is exactly how the TypeScript reference harness compares.
//!   2. CANONICAL: RFC 8785 canonical bytes of the result vs. canonical bytes of the
//!      decoded `expected` value. This is the byte-for-byte interop requirement.
//!
//! The test prints a full report (pass rate + every divergence) and then asserts that
//! every case passes structurally.

use jlvm_core::canonical::canonicalize_string;
use jlvm_core::value::{decode_value, encode_value};
use jlvm_core::{decode_expression, evaluate};
use std::path::PathBuf;

#[derive(Debug)]
struct Case {
    category: String,
    expr: String,
    data: String,
    expected: String,
    note: Option<String>,
}

fn load_cases() -> Vec<Case> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // rust/jlvm-core -> repo root -> shared/...
    path.pop();
    path.pop();
    path.push("shared/json_logic_test_vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let root: serde_json::Value = serde_json::from_str(&text).expect("vectors are valid JSON");
    let mut out = Vec::new();
    for cat in root["tests"].as_array().expect("tests array") {
        let category = cat["category"].as_str().unwrap_or("?").to_string();
        for c in cat["cases"].as_array().expect("cases array") {
            out.push(Case {
                category: category.clone(),
                expr: c["expr"].as_str().expect("expr string").to_string(),
                data: c["data"].as_str().expect("data string").to_string(),
                expected: c["expected"].as_str().expect("expected string").to_string(),
                note: c
                    .get("note")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }
    out
}

/// Structural comparison with the same leniency as the TS harness's `toEqual`: numbers
/// compare by value (so `5` == `5.0` is *not* asserted here because the expected JSON
/// already encodes the intended type; we compare the JSON tokens structurally but treat
/// numeric equality by parsed f64 to tolerate integer-vs-decimal textual forms).
fn json_struct_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value::*;
    match (a, b) {
        (Null, Null) => true,
        (Bool(x), Bool(y)) => x == y,
        (Number(x), Number(y)) => {
            // Compare by f64 value (matches JS Number semantics used by the oracle).
            match (x.as_f64(), y.as_f64()) {
                (Some(xf), Some(yf)) => xf == yf,
                _ => x.to_string() == y.to_string(),
            }
        }
        (String(x), String(y)) => x == y,
        (Array(x), Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_struct_eq(p, q))
        }
        (Object(x), Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| json_struct_eq(v, w)))
        }
        _ => false,
    }
}

#[test]
fn differential_against_shared_vectors() {
    let cases = load_cases();
    let total = cases.len();
    let mut struct_pass = 0usize;
    let mut canon_pass = 0usize;
    let mut struct_failures: Vec<String> = Vec::new();
    let mut canon_only_failures: Vec<String> = Vec::new();

    for c in &cases {
        let label = match &c.note {
            Some(n) => format!("[{}] {}  ({})", c.category, c.expr, n),
            None => format!("[{}] {}", c.category, c.expr),
        };

        // Decode expression and data.
        let expr_json: serde_json::Value = match serde_json::from_str(&c.expr) {
            Ok(v) => v,
            Err(e) => {
                struct_failures.push(format!("{}\n    EXPR-JSON-PARSE-ERR: {}", label, e));
                continue;
            }
        };
        let data_json: serde_json::Value = match serde_json::from_str(&c.data) {
            Ok(v) => v,
            Err(e) => {
                struct_failures.push(format!("{}\n    DATA-JSON-PARSE-ERR: {}", label, e));
                continue;
            }
        };
        let expr = match decode_expression(&expr_json) {
            Ok(e) => e,
            Err(e) => {
                struct_failures.push(format!("{}\n    DECODE-ERR: {}", label, e));
                continue;
            }
        };
        let data = decode_value(&data_json);

        let result = match evaluate(&expr, &data) {
            Ok(v) => v,
            Err(e) => {
                struct_failures.push(format!("{}\n    EVAL-ERR: {}", label, e));
                continue;
            }
        };

        // Expected JSON value and JLVM value.
        let expected_json: serde_json::Value =
            serde_json::from_str(&c.expected).expect("expected is valid JSON");
        let expected_val = decode_value(&expected_json);

        // 1) Structural comparison.
        let result_json = encode_value(&result);
        let s_ok = json_struct_eq(&result_json, &expected_json);
        if s_ok {
            struct_pass += 1;
        } else {
            struct_failures.push(format!(
                "{}\n    data     = {}\n    expected = {}\n    got      = {}",
                label,
                c.data,
                serde_json::to_string(&expected_json).unwrap(),
                serde_json::to_string(&result_json).unwrap(),
            ));
        }

        // 2) Canonical byte comparison.
        let result_canon = canonicalize_string(&result);
        let expected_canon = canonicalize_string(&expected_val);
        let c_ok = result_canon == expected_canon;
        if c_ok {
            canon_pass += 1;
        } else if s_ok {
            // Only report canonical-only divergences (structural already reported above).
            canon_only_failures.push(format!(
                "{}\n    canon(expected) = {}\n    canon(got)      = {}",
                label, expected_canon, result_canon
            ));
        }
    }

    eprintln!("\n================ JLVM differential report ================");
    eprintln!("total cases:            {}", total);
    eprintln!(
        "structural pass:        {}/{}  ({:.1}%)",
        struct_pass,
        total,
        100.0 * struct_pass as f64 / total as f64
    );
    eprintln!(
        "canonical-bytes pass:   {}/{}  ({:.1}%)",
        canon_pass,
        total,
        100.0 * canon_pass as f64 / total as f64
    );

    if !struct_failures.is_empty() {
        eprintln!(
            "\n---- structural failures ({}) ----",
            struct_failures.len()
        );
        for f in &struct_failures {
            eprintln!("  {}", f);
        }
    }
    if !canon_only_failures.is_empty() {
        eprintln!(
            "\n---- canonical-only divergences ({}) ----",
            canon_only_failures.len()
        );
        for f in &canon_only_failures {
            eprintln!("  {}", f);
        }
    }
    eprintln!("=========================================================\n");

    assert!(
        struct_failures.is_empty(),
        "{} structural divergences against the shared vectors (see report above)",
        struct_failures.len()
    );
}
