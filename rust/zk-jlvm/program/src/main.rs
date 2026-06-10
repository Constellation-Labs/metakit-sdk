//! The JLVM zkVM guest program.
//!
//! Reads a JSON Logic expression and its data (as JSON strings) from the prover, evaluates them
//! with `jlvm-core` (the byte-compatible Rust JLVM), canonicalizes the result to RFC 8785 bytes,
//! and commits keccak256 hashes of the expression, data, and output as the public values.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{keccak256, B256};
use alloy_sol_types::SolType;
use zk_jlvm_lib::JlvmPublicValues;

pub fn main() {
    // Read the JSON Logic program and its data as JSON strings.
    let expr_json = sp1_zkvm::io::read::<String>();
    let data_json = sp1_zkvm::io::read::<String>();

    let expr_hash = keccak256(expr_json.as_bytes());
    let data_hash = keccak256(data_json.as_bytes());

    // Evaluate inside the zkVM and canonicalize (RFC 8785) the result.
    let (ok, output_hash) = match jlvm_core::evaluate_to_canonical(&expr_json, &data_json) {
        Ok(bytes) => (true, keccak256(bytes.as_slice())),
        Err(_) => (false, B256::ZERO),
    };

    let pv = JlvmPublicValues {
        exprHash: expr_hash,
        dataHash: data_hash,
        outputHash: output_hash,
        ok,
    };
    sp1_zkvm::io::commit_slice(&JlvmPublicValues::abi_encode(&pv));
}
