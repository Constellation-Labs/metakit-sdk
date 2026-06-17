//! Pins the first shielded-transfer NATIVE conformance vector (`tests/vectors/shielded_transfer_v1.json`)
//! to the constraint semantics in `verify_transfer`. Prover-independent: it asserts the exact public
//! statement the canonical witness produces (anchor, input-order nullifiers, output commitments, fee,
//! feeAsset), so a change to a Poseidon field order, the per-asset conservation rule, the nullifier
//! reveal order, or the public-values shape fails HERE before it can silently change what the on-chain
//! Groth16 proof attests. The byte-level Groth16 fixture pins the proof of this same statement.

use alloy_sol_types::SolType;
use num_bigint::BigUint;
use serde_json::Value;
use std::fs;
use zk_shielded_lib::pub_values::ShieldedTransferPublicValues;
use zk_shielded_lib::wire::WireWitness;
use zk_shielded_lib::{verify_transfer, TransferPublic, TransferWitness};

/// 32-byte big-endian field element as `0x`-prefixed lowercase hex (the public-values encoding).
fn fr_hex(x: &BigUint) -> String {
    format!("0x{x:064x}")
}

#[test]
fn native_vector_v1_matches() {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/shielded_transfer_v1.json"
    ))
    .expect("read shielded_transfer_v1.json");
    let v: Value = serde_json::from_str(&raw).expect("parse vector json");

    // Rebuild the witness from its wire form and run the real constraint system.
    let wire: WireWitness =
        serde_json::from_value(v["witness"].clone()).expect("deserialize wire witness");
    let witness: TransferWitness = (&wire).into();
    let public = verify_transfer(&witness).expect("vector witness must verify");

    // Field-level public-statement pin.
    let exp = &v["expectedPublic"];
    let strs = |arr: &Value| -> Vec<String> {
        arr.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
    };
    assert_eq!(fr_hex(&public.anchor), exp["anchor"].as_str().unwrap(), "anchor");
    assert_eq!(public.nullifiers.iter().map(fr_hex).collect::<Vec<_>>(), strs(&exp["nullifiers"]), "nullifiers (input order)");
    assert_eq!(public.output_cms.iter().map(fr_hex).collect::<Vec<_>>(), strs(&exp["outputCms"]), "output commitments");
    assert_eq!(public.fee, exp["fee"].as_u64().unwrap(), "fee");
    assert_eq!(fr_hex(&public.fee_asset), exp["feeAsset"].as_str().unwrap(), "feeAsset");

    // ABI pin: the sol-encoded public values decode back to the identical statement.
    let pv = ShieldedTransferPublicValues::from(&public);
    let bytes = ShieldedTransferPublicValues::abi_encode(&pv);
    let pv_back = ShieldedTransferPublicValues::abi_decode(&bytes).expect("abi_decode");
    let public_back: TransferPublic = (&pv_back).into();
    assert_eq!(public, public_back, "abi round-trip");
}
