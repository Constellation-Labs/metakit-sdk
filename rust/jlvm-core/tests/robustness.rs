//! Robustness regression tests for the 2026-06-10 review findings.
//!
//! 1. `parse_decimal` memory bomb: huge decimal exponents are a fast `Err`,
//!    never a multi-GB `10^scale` allocation (bound: `Ratio::MAX_DECIMAL_SCALE`).
//! 2. Canonicalizer NaN/Infinity: `{"pow":[10,999]}` canonicalizes to a normal
//!    `Err`, not a `panic!`/process abort.
//! 3. Recursion depth guard: both evaluators return `Err` at
//!    `MAX_EVAL_DEPTH`, independent of serde's parse depth (expressions are
//!    built programmatically here).
//! 4. (Cargo.toml) release overflow-checks — not testable here.
//! 5. `substr`/`slice` i64 index extremes: checked/saturating arithmetic, no
//!    debug-panic/release-wrap divergence.

use jlvm_core::eval::MAX_EVAL_DEPTH;
use jlvm_core::gas_eval::{evaluate_with_gas, GasError};
use jlvm_core::{evaluate, evaluate_json_str, Expression, Value};
use num_bigint::BigInt;

fn eval(expr_json: &str) -> Result<Value, String> {
    evaluate_json_str(expr_json, "{}")
}

fn eval_str_result(expr_json: &str) -> String {
    match eval(expr_json) {
        Ok(Value::Str(s)) => s,
        other => panic!("expected string result, got {:?}", other),
    }
}

// --- 1. parse_decimal memory bomb -------------------------------------------

#[test]
fn decimal_exponent_bomb_is_fast_error() {
    let start = std::time::Instant::now();
    // String -> number coercion path (promote_to_numeric).
    let err = eval(r#"{"+":["1e-2000000000"]}"#).unwrap_err();
    assert!(
        err.contains("Cannot convert string"),
        "unexpected error: {err}"
    );
    // Positive-exponent direction too.
    assert!(eval(r#"{"+":["1e2000000000"]}"#).is_err());
    // Beyond 2^32 (the old `scale as u32` truncation hazard).
    assert!(eval(r#"{"+":["1e-9000000000"]}"#).is_err());
    // "Fast": no multi-GB BigInt was materialized.
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "bomb guard too slow: {:?}",
        start.elapsed()
    );
}

#[test]
fn decimal_exponent_at_bound_still_exact() {
    // |scale| == 10_000 is accepted and stays exact rational.
    let v = eval(r#"{"==":[{"*":["1e-10000","1e10000"]},1]}"#).unwrap();
    assert!(v.deep_eq(&Value::Bool(true)), "got {:?}", v);
}

// --- 2. canonicalizer NaN/Infinity ------------------------------------------

#[test]
fn pow_overflowing_f64_canonicalizes_to_err_not_abort() {
    // Evaluation itself succeeds exactly (Int(10^999))...
    let v = eval(r#"{"pow":[10,999]}"#).unwrap();
    assert!(matches!(v, Value::Int(_)));
    // ...and the canonical boundary reports a normal Err.
    let err = jlvm_core::evaluate_to_canonical(r#"{"pow":[10,999]}"#, "{}").unwrap_err();
    assert!(err.contains("NaN/Infinity"), "unexpected error: {err}");
}

// --- 3. recursion depth guard ------------------------------------------------

/// `{"+":[1,{"+":[1,...]}]}` nested `n` ops deep, built programmatically so the
/// guard is exercised independently of serde_json's parse-depth limit (128).
fn nested_add(n: usize) -> Expression {
    let mut expr = Expression::Const(Value::int_from_i64(1));
    for _ in 0..n {
        expr = Expression::Apply {
            op: "+".to_string(),
            args: vec![Expression::Const(Value::int_from_i64(1)), expr],
        };
    }
    expr
}

#[test]
fn depth_guard_unmetered_triggers_at_limit() {
    let data = Value::Map(Vec::new());
    // A chain of k applies needs depth k+1 (innermost constant); the deepest
    // accepted chain is MAX_EVAL_DEPTH - 1 ops.
    let ok_n = (MAX_EVAL_DEPTH - 1) as usize;
    let v = evaluate(&nested_add(ok_n), &data).unwrap();
    assert!(v.deep_eq(&Value::Int(BigInt::from(ok_n as i64 + 1))));

    let err = evaluate(&nested_add(ok_n + 1), &data).unwrap_err();
    assert!(
        err.contains("Recursion depth limit exceeded"),
        "unexpected error: {err}"
    );
}

#[test]
fn depth_guard_metered_triggers_at_limit_identically() {
    let data = Value::Map(Vec::new());
    let ok_n = (MAX_EVAL_DEPTH - 1) as usize;
    let (v, _gas) = evaluate_with_gas(&nested_add(ok_n), &data, u64::MAX).unwrap();
    assert!(v.deep_eq(&Value::Int(BigInt::from(ok_n as i64 + 1))));

    match evaluate_with_gas(&nested_add(ok_n + 1), &data, u64::MAX) {
        Err(GasError::Eval(msg)) => {
            assert!(
                msg.contains("Recursion depth limit exceeded"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected Eval depth error, got {:?}", other),
    }
}

#[test]
fn depth_guard_counts_callback_runs() {
    // A deep chain split across a callback boundary: ~200 levels outside plus
    // ~200 inside a map callback must trip the guard even though neither part
    // alone exceeds it.
    let inner = nested_add(200);
    let map_expr = Expression::Apply {
        op: "map".to_string(),
        args: vec![
            Expression::Const(Value::Array(vec![Value::int_from_i64(0)])),
            inner,
        ],
    };
    let mut expr = map_expr;
    for _ in 0..200 {
        expr = Expression::Apply {
            op: "merge".to_string(),
            args: vec![expr],
        };
    }
    let err = evaluate(&expr, &Value::Map(Vec::new())).unwrap_err();
    assert!(
        err.contains("Recursion depth limit exceeded"),
        "unexpected error: {err}"
    );
}

// --- 5. substr / slice i64 extremes ------------------------------------------

#[test]
fn substr_extreme_indices_saturate() {
    // length = i64::MAX: start_idx + length must not overflow.
    assert_eq!(
        eval_str_result(r#"{"substr":["hello",1,9223372036854775807]}"#),
        "ello"
    );
    // start = i64::MIN: str_len + start must not overflow; clamps to 0.
    assert_eq!(
        eval_str_result(r#"{"substr":["hello",-9223372036854775808]}"#),
        "hello"
    );
    // Both extremes together.
    assert_eq!(
        eval_str_result(r#"{"substr":["hello",-9223372036854775808,9223372036854775807]}"#),
        "hello"
    );
    // length = i64::MIN: str_len + length clamps to 0 -> empty.
    assert_eq!(
        eval_str_result(r#"{"substr":["hello",0,-9223372036854775808]}"#),
        ""
    );
    // Beyond i64 remains a normal Err (unchanged behavior).
    assert!(eval(r#"{"substr":["hello",9223372036854775808]}"#).is_err());
}

#[test]
fn slice_extreme_indices_saturate() {
    let v = eval(r#"{"slice":[[1,2,3],-9223372036854775808]}"#).unwrap();
    assert!(v.deep_eq(&Value::Array(vec![
        Value::int_from_i64(1),
        Value::int_from_i64(2),
        Value::int_from_i64(3),
    ])));
    let v = eval(r#"{"slice":[[1,2,3],-9223372036854775808,9223372036854775807]}"#).unwrap();
    assert!(v.deep_eq(&Value::Array(vec![
        Value::int_from_i64(1),
        Value::int_from_i64(2),
        Value::int_from_i64(3),
    ])));
    let v = eval(r#"{"slice":[[1,2,3],0,-9223372036854775808]}"#).unwrap();
    assert!(v.deep_eq(&Value::Array(Vec::new())));
}
