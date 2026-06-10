//! ZK / crypto opcode differential conformance harness.
//!
//! Loads `shared/zk_opcode_test_vectors.json` (Scala metakit is the reference;
//! the `known_answer` category carries independent ground truth) and runs the
//! TIER-1 categories implemented by this Rust JLVM:
//!   - `poseidon`
//!   - `pmt_verify`
//!   - `schnorr_verify`
//!
//! There are two kinds of case:
//!   - VALUE cases carry `expected`. The result must be BYTE-IDENTICAL to it:
//!       1. STRUCTURAL: encoded-result JSON deep-equals the decoded `expected`.
//!       2. CANONICAL: RFC 8785 canonical bytes of result == canonical bytes of
//!          `expected`. This is the byte-for-byte interop requirement.
//!   - ERROR cases carry `"error": true` and NO `expected` (the shared error
//!     convention). Evaluation MUST FAIL here (a Scala `JsonLogicException` /
//!     thrown error maps to a Rust `Err`). If Rust instead returns a value, that
//!     is a genuine Scala↔Rust parity bug and is reported loudly.
//!
//! Symmetrically, if a VALUE case's Scala-produced `expected` cannot be
//! reproduced by Rust because Rust ERRORS, that too is surfaced as a parity bug
//! rather than silently swallowed. The whole point is to EXPOSE divergence.
//!
//! EVERY Tier-1 vector MUST pass. Categories not yet implemented in the Rust
//! core (smt/mpt/bn254/ecvrf/groth16, and the deferred bls ops) are skipped with
//! a report line, so the harness stays green as later waves land.

use jlvm_core::canonical::canonicalize_string;
use jlvm_core::value::{decode_value, encode_value};
use jlvm_core::{decode_expression, evaluate};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The Tier-1 categories this Rust JLVM implements and must pass.
const TIER1_CATEGORIES: &[&str] = &["poseidon", "pmt_verify", "schnorr_verify"];

/// Tier-1 opcode tags. Any `known_answer` case whose top-level operator is one
/// of these is ALSO a Tier-1 cross-check (the `known_answer` poseidon vector is
/// independent circomlib ground truth) and must pass.
const TIER1_OPS: &[&str] = &["poseidon", "pmt_verify", "schnorr_verify"];

/// The single top-level operator tag of an expression, if it is an
/// `{"op": ...}` object. Used to pull Tier-1 ops out of the `known_answer` mix.
fn top_op(expr: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(expr).ok()?;
    let obj = v.as_object()?;
    if obj.len() == 1 {
        obj.keys().next().cloned()
    } else {
        None
    }
}

#[derive(Debug)]
struct Case {
    category: String,
    expr: String,
    data: String,
    /// `Some(json)` for a value/false case; `None` for an error case.
    expected: Option<String>,
    /// Error convention: `true` ⇒ evaluation MUST fail in this impl (no `expected`).
    error: bool,
    note: Option<String>,
}

fn load_cases() -> Vec<Case> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // rust/jlvm-core -> repo root -> shared/...
    path.pop();
    path.pop();
    path.push("shared/zk_opcode_test_vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let root: serde_json::Value = serde_json::from_str(&text).expect("vectors are valid JSON");
    let mut out = Vec::new();
    for cat in root["tests"].as_array().expect("tests array") {
        let category = cat["category"].as_str().unwrap_or("?").to_string();
        for c in cat["cases"].as_array().expect("cases array") {
            let error = c.get("error").and_then(|e| e.as_bool()).unwrap_or(false);
            let expected = c
                .get("expected")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string());
            // Convention guard: a case is EITHER an error case (error:true, no expected)
            // OR a value case (expected present, no error) — never both, never neither.
            assert!(
                error != expected.is_some(),
                "[{category}] case must have exactly one of `expected` / `error:true`: {}",
                c
            );
            out.push(Case {
                category: category.clone(),
                expr: c["expr"].as_str().expect("expr string").to_string(),
                data: c["data"].as_str().expect("data string").to_string(),
                expected,
                error,
                note: c
                    .get("note")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }
    out
}

fn json_struct_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value::*;
    match (a, b) {
        (Null, Null) => true,
        (Bool(x), Bool(y)) => x == y,
        (Number(x), Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(xf), Some(yf)) => xf == yf,
            _ => x.to_string() == y.to_string(),
        },
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
fn tier1_zk_differential_against_shared_vectors() {
    let cases = load_cases();
    let tier1: BTreeSet<&str> = TIER1_CATEGORIES.iter().copied().collect();

    let mut tier1_total = 0usize;
    let mut struct_pass = 0usize;
    let mut canon_pass = 0usize;
    let mut error_cases = 0usize; // cases marked `error:true` (Scala fails ⇒ Rust must fail)
    let mut error_pass = 0usize; // of those, the ones where Rust also failed
    let mut failures: Vec<String> = Vec::new();
    let mut skipped: BTreeSet<String> = BTreeSet::new();

    let tier1_ops: BTreeSet<&str> = TIER1_OPS.iter().copied().collect();

    for c in &cases {
        // Run a case if it is in a Tier-1 category, OR if it is a known_answer
        // (independent ground truth) case whose top-level operator is Tier-1.
        let is_tier1_cat = tier1.contains(c.category.as_str());
        let is_tier1_ka = c.category == "known_answer"
            && top_op(&c.expr).is_some_and(|op| tier1_ops.contains(op.as_str()));
        if !is_tier1_cat && !is_tier1_ka {
            skipped.insert(c.category.clone());
            continue;
        }
        tier1_total += 1;

        let label = match &c.note {
            Some(n) => format!("[{}] {}  ({})", c.category, c.expr, n),
            None => format!("[{}] {}", c.category, c.expr),
        };

        let expr_json: serde_json::Value = match serde_json::from_str(&c.expr) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{label}\n    EXPR-JSON-PARSE-ERR: {e}"));
                continue;
            }
        };
        let data_json: serde_json::Value = match serde_json::from_str(&c.data) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{label}\n    DATA-JSON-PARSE-ERR: {e}"));
                continue;
            }
        };
        let data = decode_value(&data_json);

        // Evaluate: decode + evaluate. Either step failing means "evaluation failed"
        // for the purpose of the error convention (a JsonLogicException on the Scala
        // side maps to an Err here).
        let eval_result: Result<jlvm_core::value::Value, String> = decode_expression(&expr_json)
            .map_err(|e| format!("DECODE-ERR: {e}"))
            .and_then(|expr| evaluate(&expr, &data).map_err(|e| format!("EVAL-ERR: {e}")));

        // ---- ERROR CASE: Scala errors here; Rust MUST also error. -------------
        if c.error {
            error_cases += 1;
            match eval_result {
                Err(_) => {
                    // Rust errored as required → both structural and canonical "pass".
                    struct_pass += 1;
                    canon_pass += 1;
                    error_pass += 1;
                }
                Ok(v) => {
                    // DIVERGENCE: Scala errors but Rust produced a value. Surface loudly.
                    let got = encode_value(&v);
                    failures.push(format!(
                        "{label}\n    PARITY BUG: Scala ERRORS but Rust returned a value\n    got = {}",
                        serde_json::to_string(&got).unwrap(),
                    ));
                }
            }
            continue;
        }

        // ---- VALUE CASE: Scala produced `expected`; Rust must reproduce it. ----
        let result = match eval_result {
            Ok(v) => v,
            Err(e) => {
                // DIVERGENCE: Scala produced a value/false but Rust errored.
                failures.push(format!(
                    "{label}\n    PARITY BUG: Scala produced a value but Rust ERRORED\n    {e}\n    expected = {}",
                    c.expected.as_deref().unwrap_or("<none>"),
                ));
                continue;
            }
        };

        let expected_str = c.expected.as_deref().expect("value case has expected");
        let expected_json: serde_json::Value =
            serde_json::from_str(expected_str).expect("expected is valid JSON");
        let expected_val = decode_value(&expected_json);

        // 1) Structural comparison.
        let result_json = encode_value(&result);
        let s_ok = json_struct_eq(&result_json, &expected_json);
        if s_ok {
            struct_pass += 1;
        }

        // 2) Canonical byte comparison.
        let result_canon = canonicalize_string(&result);
        let expected_canon = canonicalize_string(&expected_val);
        let c_ok = result_canon == expected_canon;
        if c_ok {
            canon_pass += 1;
        }

        if !(s_ok && c_ok) {
            failures.push(format!(
                "{label}\n    expected      = {}\n    got           = {}\n    canon(expected) = {}\n    canon(got)      = {}",
                serde_json::to_string(&expected_json).unwrap(),
                serde_json::to_string(&result_json).unwrap(),
                expected_canon,
                result_canon,
            ));
        }
    }

    eprintln!("\n============ JLVM Tier-1 ZK differential report ============");
    eprintln!("tier-1 categories:      {:?}", TIER1_CATEGORIES);
    eprintln!("tier-1 cases:           {tier1_total}");
    eprintln!(
        "error-convention cases: {error_pass}/{error_cases}  (Rust errors where Scala errors)"
    );
    eprintln!(
        "structural pass:        {struct_pass}/{tier1_total}  ({:.1}%)",
        100.0 * struct_pass as f64 / tier1_total.max(1) as f64
    );
    eprintln!(
        "canonical-bytes pass:   {canon_pass}/{tier1_total}  ({:.1}%)",
        100.0 * canon_pass as f64 / tier1_total.max(1) as f64
    );
    if !skipped.is_empty() {
        eprintln!("skipped (not Tier 1):   {skipped:?}");
    }
    if !failures.is_empty() {
        eprintln!("\n---- failures ({}) ----", failures.len());
        for f in &failures {
            eprintln!("  {f}");
        }
    }
    eprintln!("===========================================================\n");

    assert!(
        failures.is_empty(),
        "{} Tier-1 ZK vector divergence(s) against the shared vectors (see report above)",
        failures.len()
    );
    assert_eq!(
        struct_pass, tier1_total,
        "every Tier-1 vector must pass structurally"
    );
    assert_eq!(
        canon_pass, tier1_total,
        "every Tier-1 vector must pass canonical-byte comparison"
    );
}
