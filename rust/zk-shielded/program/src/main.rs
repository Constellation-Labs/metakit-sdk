//! The shielded-transfer zkVM guest program (M4).
//!
//! Reads a transfer witness (JSON wire form) from the prover, runs the FULL transfer
//! constraint system with `zk-shielded-lib::verify_transfer` (the same code the native
//! tests run), and commits the sol-encoded public values. An INVALID witness makes
//! `verify_transfer` return `Err`, which this program turns into a panic — aborting the
//! proof. That is precisely what makes a SUCCESSFUL proof meaningful: it can only exist
//! for a witness that satisfies membership, authorization, nullifier derivation, value
//! conservation, and range.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use zk_shielded_lib::pub_values::ShieldedTransferPublicValues;
use zk_shielded_lib::wire::WireWitness;
use zk_shielded_lib::{verify_transfer, TransferWitness};

pub fn main() {
    // Read the witness as a JSON string (portable, exact decimal Fr encoding).
    let witness_json = sp1_zkvm::io::read::<String>();
    let wire: WireWitness =
        serde_json::from_str(&witness_json).expect("malformed transfer witness JSON");
    let witness: TransferWitness = (&wire).into();

    // Run the constraint system. Any violation panics -> no proof.
    let public = verify_transfer(&witness).expect("shielded transfer witness is invalid");

    // Commit the public statement (anchor, nullifiers, output commitments, fee).
    let pv = ShieldedTransferPublicValues::from(&public);
    sp1_zkvm::io::commit_slice(&ShieldedTransferPublicValues::abi_encode(&pv));
}
