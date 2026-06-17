//! Shared types + constraint logic for a GENERAL private state transition (M5), proven in
//! the SP1 zkVM. This is the fused realization of the "private contract state" RFC: it binds
//! *"this state was a committed member"* to *"this app effect ran on it"* in ONE statement.
//!
//! It is the generalization of `zk-shielded`: the note commits to an ARBITRARY app state
//! (`stateHash = keccak(canonical(state))`) instead of a `{value, owner, asset, rho}` value
//! note, and the conservation check is replaced by an ARBITRARY `jlvm-core` effect
//! (`new_state = effect(old_state, event)`) — the same byte-compatible JLVM the chain runs.
//!
//! Like `zk-shielded`/`zk-jlvm`, the entire constraint system is factored into a single
//! [`verify_transition`] that runs IDENTICALLY natively and inside the zkVM; the guest is a
//! thin wrapper (read witness → `verify_transition` → commit public values), and the native
//! tests exercise the exact same code path.
//!
//! # Scheme (1-in / 1-out private state transition) — HASH/FIELD ORDERS ARE FIXED HERE
//!
//! A note commits to app state: `cm = Poseidon([stateHi, stateLo, owner, rho])` where
//! `(stateHi, stateLo)` are the two 128-bit big-endian limbs of `keccak256(canonical(state))`
//! (RFC 8785 canonical JSON, the same canonicalization `jlvm-core` uses). `owner`, `rho` are
//! Fr. Two limbs bind the full 256-bit hash; each limb is `< 2^128 ≪ R`, so both are canonical.
//!
//! - Commitment:  `cm = Poseidon([stateHi, stateLo, owner, rho])`  (4 inputs, width t=5)
//! - Owner key:   `owner = Poseidon([nsk])`                        (1 input,  width t=2)
//! - Nullifier:   `nf = Poseidon([rho, nsk])`                      (2 inputs, width t=3)
//!
//! # What the proof attests
//!
//! (a) MEMBERSHIP   — the old note `cm` is a leaf under the public `anchor` (Poseidon-Merkle).
//! (b) AUTHORIZATION— the spender knows `nsk` for the old note (`owner == Poseidon([nsk])`).
//! (c) NULLIFIER    — `nf = Poseidon([rho, nsk])` of the spent note; revealed publicly.
//! (d) TRANSITION   — `canonical(new_state) == jlvm_core::evaluate(effectExpr, {state, event})`,
//!     i.e. the new state is exactly the app's effect applied to the old state + event.
//! (e) NEW COMMIT   — the new note `cm'` is computed over `keccak(canonical(new_state))` and revealed.
//! (f) LOGIC BIND   — `exprHash = keccak(effectExpr)` is revealed, pinning WHICH app logic ran.
//!
//! Public values: `{ anchor: Fr, nullifier: Fr, new_commitment: Fr, expr_hash: bytes32 }`.
//! Private witness: old state, event, effect expression, nsk, rho, Merkle path, new note opening.
//! An INVALID witness makes [`verify_transition`] return `Err`; the guest turns that into a
//! panic (an aborted proof), which is what makes a successful proof meaningful.

use alloy_primitives::keccak256;
use num_bigint::BigUint;
use poseidon_bn254::merkle::{verify_inclusion, PoseidonMerkleProof};
use poseidon_bn254::{hash, is_canonical};
use serde_json::Value;

pub mod pub_values;
pub mod wire;

pub use pub_values::JlvmTransitionPublicValues;

/// Default Merkle depth for the commitment tree (matches the Scala / zk-shielded default).
pub const DEFAULT_DEPTH: usize = poseidon_bn254::merkle::DEFAULT_DEPTH;

/// `owner = Poseidon([nsk])`. Binds an owner address to a nullifier secret key.
pub fn owner_from_nsk(nsk: &BigUint) -> BigUint {
    hash(&[nsk.clone()])
}

/// `nf = Poseidon([rho, nsk])`. The field order is FIXED: rho, nsk.
pub fn nullifier(rho: &BigUint, nsk: &BigUint) -> BigUint {
    hash(&[rho.clone(), nsk.clone()])
}

/// The two 128-bit big-endian limbs `(hi, lo)` of `keccak256(bytes)`. Each `< 2^128 ≪ R`.
fn keccak_limbs(bytes: &[u8]) -> (BigUint, BigUint) {
    let k = keccak256(bytes).0;
    (
        BigUint::from_bytes_be(&k[..16]),
        BigUint::from_bytes_be(&k[16..]),
    )
}

/// `cm = Poseidon([stateHi, stateLo, owner, rho])`. The input order is FIXED.
fn commit(state_hi: &BigUint, state_lo: &BigUint, owner: &BigUint, rho: &BigUint) -> BigUint {
    hash(&[
        state_hi.clone(),
        state_lo.clone(),
        owner.clone(),
        rho.clone(),
    ])
}

/// Canonicalize an app-state JSON string to RFC 8785 bytes (the hash pre-image), erroring on bad JSON.
fn canonical_state_bytes(state_json: &str) -> Result<Vec<u8>, TransitionError> {
    let v: Value =
        serde_json::from_str(state_json).map_err(|_| TransitionError::BadJson("state"))?;
    jlvm_core::canonical::canonicalize_json(&v)
        .map_err(|_| TransitionError::BadJson("state-canonical"))
}

/// The commitment of a note over `state_json` (canonicalized) with the given `owner`/`rho`.
/// Use this to compute the leaf to place in the commitment tree.
pub fn note_commitment(
    state_json: &str,
    owner: &BigUint,
    rho: &BigUint,
) -> Result<BigUint, TransitionError> {
    let bytes = canonical_state_bytes(state_json)?;
    let (hi, lo) = keccak_limbs(&bytes);
    Ok(commit(&hi, &lo, owner, rho))
}

/// The full private witness for a 1-in / 1-out private state transition.
#[derive(Clone, Debug)]
pub struct TransitionWitness {
    /// The public anchor (commitment-tree root) the old note is proven against.
    pub anchor: BigUint,
    /// The old (spent) note's app state, as a JSON string. Canonicalized before hashing.
    pub old_state_json: String,
    /// `owner` of the old note. MUST equal `Poseidon([nsk])`.
    pub owner: BigUint,
    /// The nullifier secret key authorising the spend.
    pub nsk: BigUint,
    /// The old note's per-note randomness / serial.
    pub rho: BigUint,
    /// Inclusion proof of the old note's commitment at `anchor`.
    pub merkle_proof: PoseidonMerkleProof,
    /// The app's effect expression (JSON-Logic), as a JSON string. `exprHash` pins it.
    pub effect_expr_json: String,
    /// The event/input driving the transition, as a JSON string.
    pub event_json: String,
    /// `owner` of the new note.
    pub new_owner: BigUint,
    /// The new note's per-note randomness / serial.
    pub new_rho: BigUint,
}

/// The public statement the proof attests to (the sol-encoded `bytes` of this are the
/// program's public values). Order/shape mirrors the sol struct in [`pub_values`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionPublic {
    pub anchor: BigUint,
    /// The spent note's nullifier (double-spend prevention; checked against the on-chain set).
    pub nullifier: BigUint,
    /// The new note's commitment (the post-transition state, committed).
    pub new_commitment: BigUint,
    /// `keccak256(effectExpr)` — pins WHICH app logic produced the new state.
    pub expr_hash: [u8; 32],
}

/// Reasons a witness can fail to satisfy the transition constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// A field element (owner/nsk/rho/anchor/new_owner/new_rho) was not canonical (`>= R`).
    NonCanonical(&'static str),
    /// AUTHORIZATION: `owner != Poseidon([nsk])`.
    OwnerMismatch,
    /// MEMBERSHIP: the old note's commitment is not included under `anchor`.
    NotMember,
    /// A JSON input (old state / event / effect expr) was malformed or non-canonicalizable.
    BadJson(&'static str),
    /// TRANSITION: the `jlvm-core` effect errored (bad op, type error, gas, ...).
    EffectFailed(String),
}

impl core::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransitionError::NonCanonical(role) => write!(f, "non-canonical field element: {role}"),
            TransitionError::OwnerMismatch => {
                write!(f, "authorization failed: owner != Poseidon([nsk])")
            }
            TransitionError::NotMember => write!(f, "membership failed: old note not under anchor"),
            TransitionError::BadJson(role) => write!(f, "malformed JSON input: {role}"),
            TransitionError::EffectFailed(e) => write!(f, "effect evaluation failed: {e}"),
        }
    }
}

fn require_canonical(x: &BigUint, role: &'static str) -> Result<(), TransitionError> {
    if is_canonical(x) {
        Ok(())
    } else {
        Err(TransitionError::NonCanonical(role))
    }
}

/// Build the JLVM evaluation context `{ "state": <old_state>, "event": <event> }` as a JSON string.
fn build_context(old_state_json: &str, event_json: &str) -> Result<String, TransitionError> {
    let state: Value =
        serde_json::from_str(old_state_json).map_err(|_| TransitionError::BadJson("state"))?;
    let event: Value =
        serde_json::from_str(event_json).map_err(|_| TransitionError::BadJson("event"))?;
    Ok(serde_json::json!({ "state": state, "event": event }).to_string())
}

/// Verify the FULL transition constraint system over `witness` and, on success, return the
/// public statement to be revealed. This is the single source of truth shared by the native
/// tests and the zkVM guest.
///
/// Checks, in order: well-formedness, AUTHORIZATION (b), MEMBERSHIP (a), NULLIFIER (c),
/// TRANSITION via `jlvm-core` (d), NEW COMMITMENT (e), and LOGIC BINDING (f).
pub fn verify_transition(witness: &TransitionWitness) -> Result<TransitionPublic, TransitionError> {
    require_canonical(&witness.anchor, "anchor")?;
    require_canonical(&witness.owner, "owner")?;
    require_canonical(&witness.nsk, "nsk")?;
    require_canonical(&witness.rho, "rho")?;
    require_canonical(&witness.new_owner, "new_owner")?;
    require_canonical(&witness.new_rho, "new_rho")?;

    // (b) AUTHORIZATION: prove knowledge of nsk binding to owner.
    if owner_from_nsk(&witness.nsk) != witness.owner {
        return Err(TransitionError::OwnerMismatch);
    }

    // (a) MEMBERSHIP: the old note's commitment is a leaf under the anchor.
    let old_bytes = canonical_state_bytes(&witness.old_state_json)?;
    let (old_hi, old_lo) = keccak_limbs(&old_bytes);
    let old_cm = commit(&old_hi, &old_lo, &witness.owner, &witness.rho);
    if !verify_inclusion(&old_cm, &witness.merkle_proof, &witness.anchor) {
        return Err(TransitionError::NotMember);
    }

    // (c) NULLIFIER: derive and reveal (double-spend prevention).
    let nf = nullifier(&witness.rho, &witness.nsk);

    // (d) TRANSITION: run the app effect in jlvm-core over { state, event }. The output IS the
    // canonical new state; any evaluation error aborts the proof.
    let context = build_context(&witness.old_state_json, &witness.event_json)?;
    let new_state_bytes = jlvm_core::evaluate_to_canonical(&witness.effect_expr_json, &context)
        .map_err(TransitionError::EffectFailed)?;

    // (e) NEW COMMITMENT: commit the post-transition state and reveal it.
    let (new_hi, new_lo) = keccak_limbs(&new_state_bytes);
    let new_cm = commit(&new_hi, &new_lo, &witness.new_owner, &witness.new_rho);

    // (f) LOGIC BINDING: which effect produced this transition.
    let expr_hash = keccak256(witness.effect_expr_json.as_bytes()).0;

    Ok(TransitionPublic {
        anchor: witness.anchor.clone(),
        nullifier: nf,
        new_commitment: new_cm,
        expr_hash,
    })
}
