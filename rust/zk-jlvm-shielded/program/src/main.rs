//! The general private state-transition zkVM guest program (M5).
//!
//! Reads a transition witness (JSON wire form) from the prover, runs the FULL constraint
//! system with `zk-jlvm-shielded-lib::verify_transition` (the same code the native tests run —
//! membership ∧ authorization ∧ nullifier ∧ a `jlvm-core` effect ∧ new commitment), and commits
//! the sol-encoded public values. An INVALID witness makes `verify_transition` return `Err`,
//! which this program turns into a panic — aborting the proof. A SUCCESSFUL proof therefore
//! exists only for a real, authorised transition whose new state is exactly the app effect
//! applied to a committed old state.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use zk_jlvm_shielded_lib::pub_values::JlvmTransitionPublicValues;
use zk_jlvm_shielded_lib::wire::WireWitness;
use zk_jlvm_shielded_lib::{verify_transition, TransitionWitness};

pub fn main() {
    // Read the witness as a JSON string (portable, exact decimal Fr + readable app JSON).
    let witness_json = sp1_zkvm::io::read::<String>();
    let wire: WireWitness =
        serde_json::from_str(&witness_json).expect("malformed transition witness JSON");
    let witness: TransitionWitness = (&wire).into();

    // Run the constraint system. Any violation panics -> no proof.
    let public = verify_transition(&witness).expect("private transition witness is invalid");

    // Commit the public statement (anchor, nullifier, newCommitment, exprHash).
    let pv = JlvmTransitionPublicValues::from(&public);
    sp1_zkvm::io::commit_slice(&JlvmTransitionPublicValues::abi_encode(&pv));
}
