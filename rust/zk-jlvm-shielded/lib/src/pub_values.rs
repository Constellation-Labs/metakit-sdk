//! Sol-encoded PUBLIC VALUES for the private state-transition proof, mirroring `zk-shielded`
//! and `zk-jlvm`. Fr elements (`anchor`, `nullifier`, `newCommitment`) are `bytes32` big-endian,
//! left-zero-padded — the same layout metakit's JVM Groth16 / Fr machinery uses. `exprHash` is the
//! raw `keccak256(effectExpr)`.

use crate::TransitionPublic;
use alloy_sol_types::sol;
use num_bigint::BigUint;

sol! {
    /// Public values committed by the private state-transition zkVM program.
    ///
    /// The proof attests: "there is an old note (member of `anchor`, authorised by knowledge of
    /// its nsk) whose state, under the app effect with `keccak256(effectExpr) == exprHash` and
    /// some event, transitions to a new state committed as `newCommitment`; `nullifier` is the
    /// old note's correct nullifier."
    struct JlvmTransitionPublicValues {
        bytes32 anchor;
        bytes32 nullifier;
        bytes32 newCommitment;
        bytes32 exprHash;
    }
}

/// Encode an Fr element as a big-endian, left-zero-padded 32-byte array.
pub fn fr_to_bytes32(x: &BigUint) -> [u8; 32] {
    let be = x.to_bytes_be();
    assert!(be.len() <= 32, "Fr element does not fit in 32 bytes");
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// Decode a big-endian 32-byte array back into an Fr element.
pub fn bytes32_to_fr(b: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(b)
}

impl From<&TransitionPublic> for JlvmTransitionPublicValues {
    fn from(p: &TransitionPublic) -> Self {
        JlvmTransitionPublicValues {
            anchor: fr_to_bytes32(&p.anchor).into(),
            nullifier: fr_to_bytes32(&p.nullifier).into(),
            newCommitment: fr_to_bytes32(&p.new_commitment).into(),
            exprHash: p.expr_hash.into(),
        }
    }
}

impl From<&JlvmTransitionPublicValues> for TransitionPublic {
    fn from(p: &JlvmTransitionPublicValues) -> Self {
        TransitionPublic {
            anchor: bytes32_to_fr(&p.anchor.0),
            nullifier: bytes32_to_fr(&p.nullifier.0),
            new_commitment: bytes32_to_fr(&p.newCommitment.0),
            expr_hash: p.exprHash.0,
        }
    }
}
