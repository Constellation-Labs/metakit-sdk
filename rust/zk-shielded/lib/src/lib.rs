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
//! (d) CONSERVATION — value is conserved PER ASSET: for every asset label `a`,
//!     `sum(inputs[a].value) == sum(outputs[a].value) + (fee if a == fee_asset else 0)`,
//!     all u64, no overflow. A transfer therefore CANNOT mint across assets (burn asset A
//!     to create asset B), and the transparent `fee` is charged in exactly one declared
//!     `fee_asset` — which must itself be funded by the inputs.
//! (e) RANGE        — every value is a u64 (`< 2^64`), so it embeds in Fr.
//! (f) OUTPUTS      — each output `cm` is computed and revealed publicly.
//! (g) UNIQUENESS   — the input nullifiers are pairwise-distinct WITHIN the transfer, so the
//!     same note cannot be listed twice and double-counted (intra-transfer double-spend).
//!     The on-chain nullifier set still guards INTER-transfer double-spends; this guards the
//!     one case that set can't see — a single transfer self-colliding.
//!
//! Public values: `{ anchor: Fr, nullifiers[N], output_cms[M], fee: u64, fee_asset: Fr }`.
//! Private witness: input notes + nsk + Merkle paths + output note openings + fee_asset.
//! An INVALID witness makes [`verify_transfer`] return `Err`; the guest turns that into a
//! panic (an aborted proof), which is what makes a successful proof meaningful.

use num_bigint::BigUint;
use poseidon_bn254::merkle::{verify_inclusion, PoseidonMerkleProof};
use poseidon_bn254::{hash, is_canonical};
use std::collections::{BTreeMap, BTreeSet};

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
    /// The (public) asset label the transparent `fee` is denominated in. Per-asset
    /// conservation charges `fee` against this asset only; it must be a real, funded asset
    /// of the transfer whenever `fee > 0`. (When `fee == 0` it is unconstrained but must
    /// still be canonical; use any canonical value, e.g. `0` or the transfer's asset.)
    pub fee_asset: BigUint,
}

/// The public statement the proof attests to (the sol-encoded `bytes` of this are the
/// program's public values). Order/shape mirrors the sol struct in the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPublic {
    pub anchor: BigUint,
    /// One nullifier per input, in input order. Guaranteed pairwise-distinct (see UNIQUENESS).
    pub nullifiers: Vec<BigUint>,
    /// One commitment per output, in output order.
    pub output_cms: Vec<BigUint>,
    pub fee: u64,
    /// The asset the transparent `fee` is denominated in (revealed so the chain can credit
    /// the fee to the right asset).
    pub fee_asset: BigUint,
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
    /// UNIQUENESS: input `i`'s nullifier duplicates an earlier input's (intra-transfer double-spend).
    DuplicateNullifier(usize),
    /// CONSERVATION: for `asset`, `sum(inputs[asset]) != sum(outputs[asset]) + fee_for_asset`.
    AssetNotConserved { asset: BigUint, inputs: u128, outputs_plus_fee: u128 },
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
            TransferError::DuplicateNullifier(i) => {
                write!(f, "uniqueness failed: input[{i}] reuses an earlier input's nullifier")
            }
            TransferError::AssetNotConserved { asset, inputs, outputs_plus_fee } => write!(
                f,
                "value not conserved for asset {asset}: sum(inputs)={inputs} != sum(outputs)+fee={outputs_plus_fee}"
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
/// NULLIFIER derivation (b) + intra-transfer UNIQUENESS (g), per-output commitment (f), and
/// PER-ASSET VALUE CONSERVATION (d). RANGE (e) is structural: `value: u64` cannot exceed
/// `2^64`, so it always embeds in Fr.
pub fn verify_transfer(witness: &TransferWitness) -> Result<TransferPublic, TransferError> {
    if witness.inputs.is_empty() {
        return Err(TransferError::NoInputs);
    }
    if witness.outputs.is_empty() {
        return Err(TransferError::NoOutputs);
    }
    require_canonical(&witness.anchor, "anchor")?;
    require_canonical(&witness.fee_asset, "fee_asset")?;

    // --- inputs: authorization, membership, nullifier (unique), per-asset value sum ---
    let mut nullifiers = Vec::with_capacity(witness.inputs.len());
    // Distinct-nullifier guard (g): every revealed nullifier must be unique within the transfer.
    let mut seen_nullifiers: BTreeSet<BigUint> = BTreeSet::new();
    // Per-asset u128 input sums: N * (2^64 - 1) for realistic N never overflows u128.
    let mut sum_in: BTreeMap<BigUint, u128> = BTreeMap::new();
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
        // (g) UNIQUENESS: reject if this nullifier already appeared in THIS transfer, so the
        // same note cannot be listed twice and double-counted into its asset's input sum. The
        // revealed `nullifiers` vec stays in INPUT ORDER (the reveal contract) — distinctness is
        // enforced via a side set, not by reordering. The on-chain nullifier set guards the
        // INTER-transfer case; this guards the one it can't see (a transfer self-colliding).
        let nf = nullifier(&inp.note.rho, &inp.nsk);
        if !seen_nullifiers.insert(nf.clone()) {
            return Err(TransferError::DuplicateNullifier(i));
        }
        nullifiers.push(nf);

        let acc = sum_in.entry(inp.note.asset.clone()).or_insert(0u128);
        *acc = acc.checked_add(inp.note.value as u128).ok_or(TransferError::SumOverflow)?;
    }

    // --- outputs: compute + reveal commitments, per-asset value sum ---
    let mut output_cms = Vec::with_capacity(witness.outputs.len());
    let mut sum_out: BTreeMap<BigUint, u128> = BTreeMap::new();
    for out in &witness.outputs {
        require_canonical(&out.note.owner, "output.owner")?;
        require_canonical(&out.note.asset, "output.asset")?;
        require_canonical(&out.note.rho, "output.rho")?;
        // (f) OUTPUTS: commitment computed in-guest and revealed.
        output_cms.push(out.note.commitment());
        let acc = sum_out.entry(out.note.asset.clone()).or_insert(0u128);
        *acc = acc.checked_add(out.note.value as u128).ok_or(TransferError::SumOverflow)?;
    }

    // (d) PER-ASSET VALUE CONSERVATION: for every asset, sum(inputs) == sum(outputs) + fee,
    // where `fee` is charged to `fee_asset` only. `asset` is bound in each commitment, so this
    // closes the cross-asset MINT hole (burn asset A, create asset B). We check every asset that
    // appears on either side; when `fee > 0` we also force `fee_asset` into the checked set, so a
    // fee declared in an asset with NO notes is caught (0 != fee) rather than silently skipped.
    let mut assets: BTreeSet<BigUint> = BTreeSet::new();
    assets.extend(sum_in.keys().cloned());
    assets.extend(sum_out.keys().cloned());
    if witness.fee > 0 {
        assets.insert(witness.fee_asset.clone());
    }
    for asset in &assets {
        let in_amt = sum_in.get(asset).copied().unwrap_or(0);
        let out_amt = sum_out.get(asset).copied().unwrap_or(0);
        let fee_for_asset = if *asset == witness.fee_asset { witness.fee as u128 } else { 0 };
        let outputs_plus_fee = out_amt.checked_add(fee_for_asset).ok_or(TransferError::SumOverflow)?;
        if in_amt != outputs_plus_fee {
            return Err(TransferError::AssetNotConserved {
                asset: asset.clone(),
                inputs: in_amt,
                outputs_plus_fee,
            });
        }
    }

    Ok(TransferPublic {
        anchor: witness.anchor.clone(),
        nullifiers,
        output_cms,
        fee: witness.fee,
        fee_asset: witness.fee_asset.clone(),
    })
}
