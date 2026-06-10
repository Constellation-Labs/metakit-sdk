//! ZK / crypto opcode differential conformance harness.
//!
//! Loads `shared/zk_opcode_test_vectors.json` (Scala metakit is the reference;
//! the `known_answer` category carries independent ground truth) and runs the
//! categories implemented by this Rust JLVM, split per tier:
//!   - TIER-1 (pure crypto): `poseidon`, `pmt_verify`, `schnorr_verify`.
//!   - TIER-2a (auth-DB verifiers): `smt_verify`, `mpt_verify`,
//!     `mpt_prefix_verify` -- SMT + MPT inclusion/absence/prefix proofs whose
//!     JSON proofs are hashed through the metakit canonical-bytes SHA-256 seam.
//!   - TIER-2b (BN254 curve + ECVRF): `bn254_add`, `bn254_mul`,
//!     `bn254_pairing` (EIP-196/197 ecAdd/ecMul/ecPairing) and `ecvrf_verify`
//!     (ECVRF-EDWARDS25519-SHA512-TAI, RFC 9381 suite 0x03). The `bn254_pairing`
//!     identity and the RFC 9381 ecvrf vector are HARD ANCHORS.
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
//! EVERY Tier-1, Tier-2a and Tier-2b vector MUST pass. Categories not yet
//! implemented in the Rust core (groth16 and the bls ops) are skipped with a
//! report line, so the harness stays green as later waves land.

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

/// The Tier-2a auth-DB categories this Rust JLVM implements and must pass:
/// the SMT verifier and the MPT single / prefix verifiers.
const TIER2A_CATEGORIES: &[&str] = &["smt_verify", "mpt_verify", "mpt_prefix_verify"];

/// Tier-2a opcode tags (for any `known_answer` cross-check that lands later).
const TIER2A_OPS: &[&str] = &["smt_verify", "mpt_verify", "mpt_prefix_verify"];

/// The Tier-2b BN254 curve + ECVRF categories this Rust JLVM implements and must
/// pass: ecAdd / ecMul / ecPairing (EIP-196/197) and ECVRF (RFC 9381 TAI).
const TIER2B_CATEGORIES: &[&str] = &["bn254_add", "bn254_mul", "bn254_pairing", "ecvrf_verify"];

/// Tier-2b opcode tags (for any `known_answer` cross-check that lands later).
const TIER2B_OPS: &[&str] = &["bn254_add", "bn254_mul", "bn254_pairing", "ecvrf_verify"];

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

/// Outcome counters for a differential run over one tier's categories.
struct RunReport {
    total: usize,
    struct_pass: usize,
    canon_pass: usize,
    error_cases: usize,
    error_pass: usize,
    failures: Vec<String>,
    skipped: BTreeSet<String>,
}

/// Run every case whose category is in `categories`, OR which is a `known_answer`
/// case whose top-level operator is in `ops`. Shared body for the per-tier
/// differential tests: VALUE cases must reproduce `expected` byte-for-byte
/// (structural + canonical); ERROR cases (`error:true`) must FAIL in Rust where
/// Scala fails. Any divergence (incl. error-vs-value) is recorded as a failure.
fn run_differential(categories: &[&str], ops: &[&str]) -> RunReport {
    let cases = load_cases();
    let cat_set: BTreeSet<&str> = categories.iter().copied().collect();

    let mut total = 0usize;
    let mut struct_pass = 0usize;
    let mut canon_pass = 0usize;
    let mut error_cases = 0usize; // cases marked `error:true` (Scala fails ⇒ Rust must fail)
    let mut error_pass = 0usize; // of those, the ones where Rust also failed
    let mut failures: Vec<String> = Vec::new();
    let mut skipped: BTreeSet<String> = BTreeSet::new();

    let op_set: BTreeSet<&str> = ops.iter().copied().collect();

    for c in &cases {
        // Run a case if it is in one of this tier's categories, OR if it is a
        // known_answer (independent ground truth) case whose top-level operator
        // is in this tier.
        let is_cat = cat_set.contains(c.category.as_str());
        let is_ka = c.category == "known_answer"
            && top_op(&c.expr).is_some_and(|op| op_set.contains(op.as_str()));
        if !is_cat && !is_ka {
            skipped.insert(c.category.clone());
            continue;
        }
        total += 1;

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

    RunReport {
        total,
        struct_pass,
        canon_pass,
        error_cases,
        error_pass,
        failures,
        skipped,
    }
}

/// Print a per-tier report and assert every case passed (structural + canonical).
fn report_and_assert(tier: &str, categories: &[&str], r: &RunReport) {
    eprintln!("\n============ JLVM {tier} ZK differential report ============");
    eprintln!("{tier} categories:       {categories:?}");
    eprintln!("{tier} cases:            {}", r.total);
    eprintln!(
        "error-convention cases: {}/{}  (Rust errors where Scala errors)",
        r.error_pass, r.error_cases
    );
    eprintln!(
        "structural pass:        {}/{}  ({:.1}%)",
        r.struct_pass,
        r.total,
        100.0 * r.struct_pass as f64 / r.total.max(1) as f64
    );
    eprintln!(
        "canonical-bytes pass:   {}/{}  ({:.1}%)",
        r.canon_pass,
        r.total,
        100.0 * r.canon_pass as f64 / r.total.max(1) as f64
    );
    if !r.skipped.is_empty() {
        eprintln!("skipped (other tiers):  {:?}", r.skipped);
    }
    if !r.failures.is_empty() {
        eprintln!("\n---- failures ({}) ----", r.failures.len());
        for f in &r.failures {
            eprintln!("  {f}");
        }
    }
    eprintln!("===========================================================\n");

    assert!(
        r.failures.is_empty(),
        "{} {tier} ZK vector divergence(s) against the shared vectors (see report above)",
        r.failures.len()
    );
    assert_eq!(
        r.struct_pass, r.total,
        "every {tier} vector must pass structurally"
    );
    assert_eq!(
        r.canon_pass, r.total,
        "every {tier} vector must pass canonical-byte comparison"
    );
}

#[test]
fn tier1_zk_differential_against_shared_vectors() {
    let r = run_differential(TIER1_CATEGORIES, TIER1_OPS);
    report_and_assert("Tier-1", TIER1_CATEGORIES, &r);
}

#[test]
fn tier2a_zk_differential_against_shared_vectors() {
    let r = run_differential(TIER2A_CATEGORIES, TIER2A_OPS);
    report_and_assert("Tier-2a", TIER2A_CATEGORIES, &r);
}

#[test]
fn tier2b_zk_differential_against_shared_vectors() {
    let r = run_differential(TIER2B_CATEGORIES, TIER2B_OPS);
    report_and_assert("Tier-2b", TIER2B_CATEGORIES, &r);
}
