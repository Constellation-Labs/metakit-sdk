//! Sol-encoded PUBLIC VALUES for the shielded-transfer proof, mirroring M2's
//! `JlvmPublicValues` pattern. These are the on-chain-/JVM-verifiable statement.
//!
//! Fr elements (`anchor`, each nullifier, each output commitment) are encoded as
//! `bytes32` in BIG-ENDIAN, left-zero-padded — the natural 32-byte field encoding,
//! and the same byte layout metakit's JVM Groth16 / Fr machinery uses. `fee` is `uint64`.

use crate::TransferPublic;
use alloy_sol_types::sol;
use num_bigint::BigUint;

sol! {
    /// Public values committed by the shielded-transfer zkVM program.
    ///
    /// The proof attests: "there exist input notes (with valid Merkle inclusion under
    /// `anchor`), authorised by knowledge of their nullifier secret keys, and output notes,
    /// such that value is conserved (`sum(inputs) == sum(outputs) + fee`); the revealed
    /// `nullifiers` are their correct derivations and `outputCms` their correct commitments."
    struct ShieldedTransferPublicValues {
        bytes32 anchor;
        bytes32[] nullifiers;
        bytes32[] outputCms;
        uint64 fee;
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

impl From<&TransferPublic> for ShieldedTransferPublicValues {
    fn from(p: &TransferPublic) -> Self {
        ShieldedTransferPublicValues {
            anchor: fr_to_bytes32(&p.anchor).into(),
            nullifiers: p.nullifiers.iter().map(|n| fr_to_bytes32(n).into()).collect(),
            outputCms: p.output_cms.iter().map(|c| fr_to_bytes32(c).into()).collect(),
            fee: p.fee,
        }
    }
}

impl From<&ShieldedTransferPublicValues> for TransferPublic {
    fn from(p: &ShieldedTransferPublicValues) -> Self {
        TransferPublic {
            anchor: bytes32_to_fr(&p.anchor.0),
            nullifiers: p.nullifiers.iter().map(|n| bytes32_to_fr(&n.0)).collect(),
            output_cms: p.outputCms.iter().map(|c| bytes32_to_fr(&c.0)).collect(),
            fee: p.fee,
        }
    }
}
