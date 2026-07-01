//! # jlvm-core
//!
//! A Rust recreation of the metakit JSON Logic VM (JLVM), built to be byte-compatible
//! with the authoritative Scala evaluator in `io.constellationnetwork.metagraph_sdk`.
//! This is the client-side recreation of the server-side evaluator and the
//! evaluator compiled into the zk-jlvm / zk-jlvm-shielded (M5) SP1 guests.
//!
//! ## zk fixture impact (read before changing opcodes)
//!
//! This crate is the JLVM evaluator baked into the M5 SP1 guest ELF, so changing
//! the opcode set or any opcode's semantics/gas — even adding an opcode the M5
//! scenario never calls — rotates that guest's VKEY and makes the committed
//! groth16 fixture STALE. Regenerate it (GPU): see
//! `rust/zk-jlvm-shielded/script/fixtures/README.md`.
//!
//! ## Design invariants (matching the Scala spec)
//!
//! * The JLVM "float" is an **exact rational** ([`ratio::Ratio`]), gcd-reduced with a
//!   strictly positive denominator. All arithmetic is exact.
//! * A numeric result is `Int` only when neither operand was a float and the result is
//!   integral; otherwise `Float`.
//! * `pow` is integer-exponent only; `/` is exact; `round`/`floor`/`ceil` always return
//!   `Int`.
//! * The single rounding point is RFC 8785 canonical serialization
//!   ([`canonical::canonicalize`]), where numbers are emitted as the ECMAScript
//!   shortest double (via `ryu-js`). Even integers go through `f64` there, matching the
//!   Scala canonicalizer.

pub mod auth_db;
pub mod canonical;
pub mod coercion;
pub mod content_hash;
pub mod crypto;
pub mod ecvrf;
pub mod eval;
pub mod expression;
pub mod gas;
pub mod gas_eval;
pub mod hex;
pub mod hex_bytes;
pub mod numeric;
pub mod ops;
pub mod ordinal_catalog;
pub mod ratio;
pub mod value;

pub use eval::evaluate;
pub use expression::{decode_expression, Expression};
pub use gas_eval::{evaluate_with_gas, evaluate_with_gas_config, GasError, GasUsed};
pub use ordinal_catalog::{
    verify_ordinal_catalog_proof, OrdinalAttestation, OrdinalCatalogError, OrdinalCatalogResult,
};
pub use value::{decode_value, encode_value, Value};

/// Convenience: parse an expression and data from JSON strings, evaluate, and return the
/// resulting JLVM [`Value`].
pub fn evaluate_json_str(expr_json: &str, data_json: &str) -> Result<Value, String> {
    let expr_v: serde_json::Value =
        serde_json::from_str(expr_json).map_err(|e| format!("expr parse error: {}", e))?;
    let data_v: serde_json::Value =
        serde_json::from_str(data_json).map_err(|e| format!("data parse error: {}", e))?;
    let expr = decode_expression(&expr_v)?;
    let data = decode_value(&data_v);
    evaluate(&expr, &data)
}

/// Convenience: evaluate then canonicalize the result to RFC 8785 bytes.
pub fn evaluate_to_canonical(expr_json: &str, data_json: &str) -> Result<Vec<u8>, String> {
    let v = evaluate_json_str(expr_json, data_json)?;
    canonical::canonicalize(&v)
}
