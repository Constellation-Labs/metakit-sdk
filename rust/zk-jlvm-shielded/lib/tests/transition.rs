//! Native-execution tests for the general private state-transition constraint system. These run
//! the EXACT `verify_transition` the zkVM guest runs, on a valid 1-in/1-out transition (an app
//! effect over hidden state) and on every invalid case (each must be rejected). They also
//! round-trip the witness through the JSON wire form and the public values through sol codec.

use num_bigint::BigUint;
use poseidon_bn254::merkle::PoseidonMerkleTree;
use zk_jlvm_shielded_lib::pub_values::JlvmTransitionPublicValues;
use zk_jlvm_shielded_lib::wire::WireWitness;
use zk_jlvm_shielded_lib::{
    note_commitment, nullifier, owner_from_nsk, verify_transition, TransitionError,
    TransitionPublic, TransitionWitness,
};

const DEPTH: usize = 8;

fn fr(n: u64) -> BigUint {
    BigUint::from(n)
}

/// A valid private transition: an old shielded note holding `{"balance":100,"bids":[]}` is spent
/// to apply the effect "deduct event.amount from balance", producing a new note.
fn valid_witness() -> TransitionWitness {
    let nsk = fr(111);
    let owner = owner_from_nsk(&nsk);
    let rho = fr(7001);
    let old_state = r#"{"balance":100,"bids":[]}"#;

    let cm = note_commitment(old_state, &owner, &rho).unwrap();
    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(5), &cm);
    let anchor = tree.root();
    let proof = tree.inclusion_proof(&fr(5));

    TransitionWitness {
        anchor,
        old_state_json: old_state.to_string(),
        owner,
        nsk,
        rho,
        merkle_proof: proof,
        effect_expr_json:
            r#"{"merge":[{"var":"state"},{"balance":{"-":[{"var":"state.balance"},{"var":"event.amount"}]}}]}"#
                .to_string(),
        event_json: r#"{"amount":30}"#.to_string(),
        new_owner: owner_from_nsk(&fr(222)),
        new_rho: fr(8001),
    }
}

/// Recompute the expected new commitment independently by running the same effect and committing
/// its output — this binds verify_transition's `new_commitment` to a real jlvm-core evaluation.
fn expected_new_commitment(w: &TransitionWitness) -> BigUint {
    let ctx = format!(
        r#"{{"state":{},"event":{}}}"#,
        w.old_state_json, w.event_json
    );
    let new_state_bytes = jlvm_core::evaluate_to_canonical(&w.effect_expr_json, &ctx).unwrap();
    let new_state_str = String::from_utf8(new_state_bytes).unwrap();
    note_commitment(&new_state_str, &w.new_owner, &w.new_rho).unwrap()
}

#[test]
fn valid_transition_passes() {
    let w = valid_witness();
    let public = verify_transition(&w).expect("valid transition must pass");
    assert_eq!(public.anchor, w.anchor);
    assert_eq!(public.nullifier, nullifier(&w.rho, &w.nsk));
    assert_eq!(
        public.new_commitment,
        expected_new_commitment(&w),
        "new commitment binds the effect output"
    );
    // exprHash pins the effect logic.
    assert_eq!(
        public.expr_hash,
        alloy_primitives::keccak256(w.effect_expr_json.as_bytes()).0
    );
}

#[test]
fn wrong_nsk_owner_mismatch_rejected() {
    let mut w = valid_witness();
    w.nsk = fr(999); // owner no longer == Poseidon([nsk])
    assert_eq!(verify_transition(&w), Err(TransitionError::OwnerMismatch));
}

#[test]
fn wrong_anchor_rejected() {
    let mut w = valid_witness();
    w.anchor += 1u32; // membership can no longer verify
    assert_eq!(verify_transition(&w), Err(TransitionError::NotMember));
}

#[test]
fn tampered_merkle_path_rejected() {
    let mut w = valid_witness();
    let s = &mut w.merkle_proof.siblings[0];
    *s = poseidon_bn254::reduce(&(&*s + 1u32));
    assert_eq!(verify_transition(&w), Err(TransitionError::NotMember));
}

#[test]
fn wrong_old_state_rejected() {
    // Spending the right note's path but claiming a DIFFERENT old state changes the leaf, so
    // membership fails — you cannot lie about the hidden state behind a commitment.
    let mut w = valid_witness();
    w.old_state_json = r#"{"balance":999,"bids":[]}"#.to_string();
    assert_eq!(verify_transition(&w), Err(TransitionError::NotMember));
}

#[test]
fn bad_effect_rejected() {
    // An effect that errors in jlvm-core (modulo by zero) must abort the transition.
    let mut w = valid_witness();
    w.effect_expr_json = r#"{"%":[{"var":"state.balance"},0]}"#.to_string();
    match verify_transition(&w) {
        Err(TransitionError::EffectFailed(_)) => {}
        other => panic!("expected EffectFailed, got {other:?}"),
    }
}

#[test]
fn malformed_state_json_rejected() {
    let mut w = valid_witness();
    w.old_state_json = "{not valid json".to_string();
    assert_eq!(
        verify_transition(&w),
        Err(TransitionError::BadJson("state"))
    );
}

#[test]
fn non_canonical_field_rejected() {
    let mut w = valid_witness();
    w.rho = poseidon_bn254::modulus().clone(); // == R, not canonical
    assert!(matches!(
        verify_transition(&w),
        Err(TransitionError::NonCanonical(_))
    ));
}

#[test]
fn wire_round_trip_and_pub_values_codec() {
    let w = valid_witness();

    // Witness -> wire JSON -> witness, then verify the reconstructed witness.
    let wire: WireWitness = (&w).into();
    let json = serde_json::to_string(&wire).unwrap();
    let wire_back: WireWitness = serde_json::from_str(&json).unwrap();
    let w_back: TransitionWitness = (&wire_back).into();
    let public = verify_transition(&w_back).expect("round-tripped witness must pass");

    // Public values -> sol bytes -> public values.
    use alloy_sol_types::SolType;
    let pv = JlvmTransitionPublicValues::from(&public);
    let bytes = JlvmTransitionPublicValues::abi_encode(&pv);
    let pv_back = JlvmTransitionPublicValues::abi_decode(&bytes).unwrap();
    let public_back: TransitionPublic = (&pv_back).into();
    assert_eq!(public, public_back);
}
