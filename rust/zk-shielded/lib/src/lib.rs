//! Shared types + constraint logic for the Poseidon-based shielded value transfer
//! (M4), proven in the SP1 zkVM.
//!
//! This is the analogue of M2's `zk-jlvm-lib`: it defines the sol-encoded PUBLIC
//! VALUES the guest commits, AND — crucially — factors the entire transfer
//! constraint system into a single [`verify_transfer`] function that runs IDENTICALLY
//! natively and inside the zkVM (just like `jlvm-core::evaluate_to_canonical`). The
//! guest program is then a thin wrapper: read witness, call [`verify_transfer`], commit
//! the public values. Native tests exercise the exact same code path.
//!
//! All field arithmetic is Poseidon over BN254 Fr (see `poseidon-bn254`), byte-compatible
//! with metakit's Scala Poseidon + Poseidon Merkle tree.
//!
//! # Scheme (Sapling/Orchard-style, Poseidon-based) — FIELD ORDERS ARE FIXED HERE
//!
//! A Note is `{ value: u64, owner: Fr, asset: Fr, rho: Fr }`.
//!
//! - Commitment:   `cm = Poseidon([value_as_fr, owner, asset, rho])`   (4 inputs, width t=5)
//! - Owner key:    `owner = Poseidon([nsk])`                            (1 input,  width t=2)
//! - Nullifier:    `nf = Poseidon([rho, nsk])`                          (2 inputs, width t=3)
//!
//! `value_as_fr` is the u64 `value` zero-extended into Fr (always `< 2^64 ≪ R`, so it embeds
//! without wraparound — the RANGE constraint).
//!
//! # What the proof attests (for N inputs / M outputs)
//!
//! (a) MEMBERSHIP   — each input `cm` is a leaf under the public `anchor` Merkle root.
//! (b) NULLIFIER    — each `nf` is correctly derived from `(rho, nsk)`; revealed publicly.
//! (c) AUTHORIZATION— the spender knows `nsk` for each input (`owner == Poseidon([nsk])`).
//! (d) CONSERVATION — `sum(inputs.value) == sum(outputs.value) + fee`, all u64, no overflow.
//! (e) RANGE        — every value is a u64 (`< 2^64`), so it embeds in Fr.
//! (f) OUTPUTS      — each output `cm` is computed and revealed publicly.
//!
//! Public values: `{ anchor: Fr, nullifiers[N], output_cms[M], fee: u64 }`.
//! Private witness: input notes + nsk + Merkle paths + output note openings.
//! An INVALID witness makes [`verify_transfer`] return `Err`; the guest turns that into a
//! panic (an aborted proof), which is what makes a successful proof meaningful.

use num_bigint::BigUint;
use poseidon_bn254::merkle::{verify_inclusion, PoseidonMerkleProof};
use poseidon_bn254::{hash, is_canonical};

pub mod pub_values;
pub mod wire;

pub use pub_values::ShieldedTransferPublicValues;

/// Default Merkle depth for the commitment tree (matches the Scala tree default).
pub const DEFAULT_DEPTH: usize = poseidon_bn254::merkle::DEFAULT_DEPTH;

/// A shielded note. Field order here is the source of truth for the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// The (u64) value of the note.
    pub value: u64,
    /// The owner address = `Poseidon([nsk])`.
    pub owner: BigUint,
    /// The asset type identifier (an Fr label).
    pub asset: BigUint,
    /// A per-note randomness / serial (an Fr).
    pub rho: BigUint,
}

impl Note {
    pub fn new(value: u64, owner: BigUint, asset: BigUint, rho: BigUint) -> Self {
        Note { value, owner, asset, rho }
    }

    /// `cm = Poseidon([value_as_fr, owner, asset, rho])` (width t = 5).
    /// The field order is FIXED: value, owner, asset, rho.
    pub fn commitment(&self) -> BigUint {
        hash(&[BigUint::from(self.value), self.owner.clone(), self.asset.clone(), self.rho.clone()])
    }
}

/// `owner = Poseidon([nsk])`. Binds an owner address to a nullifier secret key.
pub fn owner_from_nsk(nsk: &BigUint) -> BigUint {
    hash(&[nsk.clone()])
}

/// `nf = Poseidon([rho, nsk])`. The field order is FIXED: rho, nsk.
pub fn nullifier(rho: &BigUint, nsk: &BigUint) -> BigUint {
    hash(&[rho.clone(), nsk.clone()])
}

/// A spent input: the note, the secret key authorising the spend, and the Merkle
/// inclusion proof of its commitment under the anchor.
#[derive(Clone, Debug)]
pub struct SpendInput {
    pub note: Note,
    /// The nullifier secret key. `note.owner` MUST equal `Poseidon([nsk])`.
    pub nsk: BigUint,
    /// Inclusion proof of `note.commitment()` at `anchor` (root-first siblings).
    pub merkle_proof: PoseidonMerkleProof,
}

/// A created output: simply the new note (its opening). Its commitment is revealed.
#[derive(Clone, Debug)]
pub struct OutputNote {
    pub note: Note,
}

/// The full private witness for an N-in / M-out transfer plus the public fee.
#[derive(Clone, Debug)]
pub struct TransferWitness {
    /// The public anchor (commitment-tree root) the inputs are proven against.
    pub anchor: BigUint,
    pub inputs: Vec<SpendInput>,
    pub outputs: Vec<OutputNote>,
    /// The (public) transparent fee, in the same u64 value units.
    pub fee: u64,
}

/// The public statement the proof attests to (the sol-encoded `bytes` of this are the
/// program's public values). Order/shape mirrors the sol struct in the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPublic {
    pub anchor: BigUint,
    /// One nullifier per input, in input order.
    pub nullifiers: Vec<BigUint>,
    /// One commitment per output, in output order.
    pub output_cms: Vec<BigUint>,
    pub fee: u64,
}

/// Reasons a witness can fail to satisfy the transfer constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    /// No inputs (a spend must consume at least one note).
    NoInputs,
    /// No outputs (a transfer must create at least one note).
    NoOutputs,
    /// A field element (owner/asset/rho/nsk/anchor) was not canonical (`>= R`).
    NonCanonical(&'static str),
    /// AUTHORIZATION: `note.owner != Poseidon([nsk])` for input `i`.
    OwnerMismatch(usize),
    /// MEMBERSHIP: input `i`'s commitment is not included under `anchor`.
    NotMember(usize),
    /// CONSERVATION: `sum(inputs) != sum(outputs) + fee`.
    ValueNotConserved { inputs: u128, outputs_plus_fee: u128 },
    /// Arithmetic would overflow even in u128 accumulation (astronomically unlikely with u64s).
    SumOverflow,
}

impl core::fmt::Display for TransferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransferError::NoInputs => write!(f, "transfer has no inputs"),
            TransferError::NoOutputs => write!(f, "transfer has no outputs"),
            TransferError::NonCanonical(role) => write!(f, "non-canonical field element: {role}"),
            TransferError::OwnerMismatch(i) => {
                write!(f, "authorization failed: input[{i}].owner != Poseidon([nsk])")
            }
            TransferError::NotMember(i) => {
                write!(f, "membership failed: input[{i}].cm not under anchor")
            }
            TransferError::ValueNotConserved { inputs, outputs_plus_fee } => write!(
                f,
                "value not conserved: sum(inputs)={inputs} != sum(outputs)+fee={outputs_plus_fee}"
            ),
            TransferError::SumOverflow => write!(f, "value sum overflow"),
        }
    }
}

fn require_canonical(x: &BigUint, role: &'static str) -> Result<(), TransferError> {
    if is_canonical(x) {
        Ok(())
    } else {
        Err(TransferError::NonCanonical(role))
    }
}

/// Verify the FULL transfer constraint system over `witness` and, on success, return the
/// public statement to be revealed. This is the single source of truth shared by the
/// native tests and the zkVM guest.
///
/// Checks, in order: well-formedness, per-input AUTHORIZATION (c) + MEMBERSHIP (a) +
/// NULLIFIER derivation (b), per-output commitment (f), and VALUE CONSERVATION (d).
/// RANGE (e) is structural: `value: u64` cannot exceed `2^64`, so it always embeds in Fr.
pub fn verify_transfer(witness: &TransferWitness) -> Result<TransferPublic, TransferError> {
    if witness.inputs.is_empty() {
        return Err(TransferError::NoInputs);
    }
    if witness.outputs.is_empty() {
        return Err(TransferError::NoOutputs);
    }
    require_canonical(&witness.anchor, "anchor")?;

    // --- inputs: authorization, membership, nullifier ---
    let mut nullifiers = Vec::with_capacity(witness.inputs.len());
    // u128 accumulator: N * (2^64 - 1) for realistic N never overflows u128.
    let mut sum_in: u128 = 0;
    for (i, inp) in witness.inputs.iter().enumerate() {
        require_canonical(&inp.note.owner, "input.owner")?;
        require_canonical(&inp.note.asset, "input.asset")?;
        require_canonical(&inp.note.rho, "input.rho")?;
        require_canonical(&inp.nsk, "input.nsk")?;

        // (c) AUTHORIZATION: prove knowledge of nsk binding to owner.
        if owner_from_nsk(&inp.nsk) != inp.note.owner {
            return Err(TransferError::OwnerMismatch(i));
        }

        // (a) MEMBERSHIP: cm is a leaf under the anchor.
        let cm = inp.note.commitment();
        if !verify_inclusion(&cm, &inp.merkle_proof, &witness.anchor) {
            return Err(TransferError::NotMember(i));
        }

        // (b) NULLIFIER: derive and reveal (double-spend prevention).
        // SECURITY TODO (known gap, deferred): no INTRA-transfer nullifier-uniqueness check.
        // The same input note can be listed twice and double-counted into sum_in unless every
        // downstream consumer dedups the revealed nullifier vec. Fix in-circuit: enforce the
        // nullifiers are pairwise-distinct (require strictly-ascending order, or collect into a
        // set and assert set.len() == inputs.len()) instead of relying on the on-chain
        // nullifier-set checker. Not yet enforced.
        nullifiers.push(nullifier(&inp.note.rho, &inp.nsk));

        sum_in = sum_in.checked_add(inp.note.value as u128).ok_or(TransferError::SumOverflow)?;
    }

    // --- outputs: compute + reveal commitments ---
    let mut output_cms = Vec::with_capacity(witness.outputs.len());
    let mut sum_out: u128 = 0;
    for out in &witness.outputs {
        require_canonical(&out.note.owner, "output.owner")?;
        require_canonical(&out.note.asset, "output.asset")?;
        require_canonical(&out.note.rho, "output.rho")?;
        // (f) OUTPUTS: commitment computed in-guest and revealed.
        output_cms.push(out.note.commitment());
        sum_out = sum_out.checked_add(out.note.value as u128).ok_or(TransferError::SumOverflow)?;
    }

    // (d) VALUE CONSERVATION: sum(inputs) == sum(outputs) + fee.
    // SECURITY TODO (known gap, deferred — assumes a SINGLE asset per transfer for now):
    // this sums values across ALL asset types with no per-asset partition, so a multi-asset
    // transfer can MINT across assets (e.g. burn 100 of asset A, create 100 of asset B).
    // `asset` IS bound in each commitment, so the fix is to conserve PER asset: group inputs
    // and outputs by `note.asset` and require sum_in[asset] == sum_out[asset] (with `fee`
    // charged to one designated fee-asset), or constrain every input/output to one shared
    // asset and reject mixed-asset witnesses. Not yet enforced.
    let outputs_plus_fee =
        sum_out.checked_add(witness.fee as u128).ok_or(TransferError::SumOverflow)?;
    if sum_in != outputs_plus_fee {
        return Err(TransferError::ValueNotConserved {
            inputs: sum_in,
            outputs_plus_fee,
        });
    }

    Ok(TransferPublic {
        anchor: witness.anchor.clone(),
        nullifiers,
        output_cms,
        fee: witness.fee,
    })
}
