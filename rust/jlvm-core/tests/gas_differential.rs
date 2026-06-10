//! Gas-metering differential conformance harness.
//!
//! Loads `shared/gas_test_vectors.json` (the cross-language gas oracle, synced
//! byte-exactly from metakit `src/test/resources/conformance/gas_test_vectors.json`;
//! every `expected` value was PRODUCED BY RUNNING the Scala reference meter) and
//! runs each case through `evaluate_with_gas` under the declared `gasLimit`,
//! asserting EXACT equivalence:
//!
//!   - integer `expected`: evaluation must succeed and report exactly that
//!     `gasUsed` (the gas-counter delta);
//!   - `"OOG"` `expected`: evaluation must fail with the DISTINCT
//!     `GasError::Exhausted` (an ordinary `GasError::Eval` is a conformance bug).
//!
//! The charging contract under test is normative per metakit PR #37 (charge-once;
//! base + depthPenalty + inputScaledCost pre-charged atomically before the
//! primitive; output-scaled residual only for split/merge/flatten/slice/substr;
//! var lookups charge varAccess + #pathSegments at lookup; if/let charge no base
//! cost; gasUsed = gas-counter delta).

use jlvm_core::{decode_expression, evaluate_with_gas, GasError};
use std::path::PathBuf;

#[derive(Debug)]
enum Expected {
    Gas(u64),
    Oog,
}

#[derive(Debug)]
struct Case {
    category: String,
    expr: String,
    data: String,
    gas_limit: u64,
    expected: Expected,
    note: Option<String>,
}

fn load_cases() -> Vec<Case> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // rust/jlvm-core -> repo root -> shared/...
    path.pop();
    path.pop();
    path.push("shared/gas_test_vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let root: serde_json::Value = serde_json::from_str(&text).expect("vectors are valid JSON");
    let mut out = Vec::new();
    for cat in root["tests"].as_array().expect("tests array") {
        let category = cat["category"].as_str().unwrap_or("?").to_string();
        for c in cat["cases"].as_array().expect("cases array") {
            let expected = match &c["expected"] {
                serde_json::Value::String(s) if s == "OOG" => Expected::Oog,
                serde_json::Value::Number(n) => {
                    Expected::Gas(n.as_u64().expect("expected gas fits u64"))
                }
                other => panic!("malformed expected: {}", other),
            };
            out.push(Case {
                category: category.clone(),
                expr: c["expr"].as_str().expect("expr string").to_string(),
                data: c["data"].as_str().expect("data string").to_string(),
                gas_limit: c["gasLimit"].as_u64().expect("gasLimit u64"),
                expected,
                note: c
                    .get("note")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }
    out
}

#[test]
fn gas_differential_against_shared_vectors() {
    let cases = load_cases();
    let total = cases.len();
    let mut passed = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for c in &cases {
        let label = match &c.note {
            Some(n) => format!("[{}] {}  ({})", c.category, c.expr, n),
            None => format!("[{}] {}", c.category, c.expr),
        };

        let expr_json: serde_json::Value = match serde_json::from_str(&c.expr) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{}\n    EXPR-JSON-PARSE-ERR: {}", label, e));
                continue;
            }
        };
        let data_json: serde_json::Value = match serde_json::from_str(&c.data) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{}\n    DATA-JSON-PARSE-ERR: {}", label, e));
                continue;
            }
        };
        let expr = match decode_expression(&expr_json) {
            Ok(e) => e,
            Err(e) => {
                failures.push(format!("{}\n    DECODE-ERR: {}", label, e));
                continue;
            }
        };
        let data = jlvm_core::decode_value(&data_json);

        let outcome = evaluate_with_gas(&expr, &data, c.gas_limit);
        match (&c.expected, outcome) {
            (Expected::Gas(want), Ok((_value, used))) => {
                if used == *want {
                    passed += 1;
                } else {
                    failures.push(format!(
                        "{}\n    gasLimit={} expected gasUsed={} got={}",
                        label, c.gas_limit, want, used
                    ));
                }
            }
            (Expected::Gas(want), Err(e)) => {
                failures.push(format!(
                    "{}\n    expected gasUsed={} but evaluation FAILED: {}",
                    label, want, e
                ));
            }
            (Expected::Oog, Err(GasError::Exhausted { .. })) => {
                passed += 1;
            }
            (Expected::Oog, Err(GasError::Eval(msg))) => {
                failures.push(format!(
                    "{}\n    expected OOG but got NON-GAS eval error: {}",
                    label, msg
                ));
            }
            (Expected::Oog, Ok((_value, used))) => {
                failures.push(format!(
                    "{}\n    expected OOG but evaluation succeeded with gasUsed={}",
                    label, used
                ));
            }
        }
    }

    println!("gas differential: {}/{} cases passed", passed, total);
    for f in &failures {
        println!("FAIL {}", f);
    }
    assert!(
        failures.is_empty(),
        "{} of {} gas vector cases failed:\n{}",
        failures.len(),
        total,
        failures.join("\n")
    );
}
