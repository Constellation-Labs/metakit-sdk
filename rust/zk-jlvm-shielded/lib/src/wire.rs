//! Serde-serialisable WIRE format for the transition witness, so the host can hand a witness
//! to the SP1 guest over stdin (and tests can round-trip it). Fr elements travel as decimal
//! strings; app JSON (state / event / effect expr) travels as native JSON values so the witness
//! file is human-readable.

use crate::TransitionWitness;
use num_bigint::BigUint;
use poseidon_bn254::merkle::PoseidonMerkleProof;
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn fr_to_str(x: &BigUint) -> String {
    x.to_str_radix(10)
}
fn str_to_fr(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).expect("valid decimal Fr in witness")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireProof {
    pub position: String,
    pub siblings: Vec<String>,
}

impl From<&PoseidonMerkleProof> for WireProof {
    fn from(p: &PoseidonMerkleProof) -> Self {
        WireProof {
            position: fr_to_str(&p.position),
            siblings: p.siblings.iter().map(fr_to_str).collect(),
        }
    }
}
impl From<&WireProof> for PoseidonMerkleProof {
    fn from(w: &WireProof) -> Self {
        PoseidonMerkleProof {
            position: str_to_fr(&w.position),
            siblings: w.siblings.iter().map(|s| str_to_fr(s)).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireWitness {
    pub anchor: String,
    pub old_state: Value,
    pub owner: String,
    pub nsk: String,
    pub rho: String,
    pub merkle_proof: WireProof,
    pub effect_expr: Value,
    pub event: Value,
    pub new_owner: String,
    pub new_rho: String,
}

impl From<&TransitionWitness> for WireWitness {
    fn from(t: &TransitionWitness) -> Self {
        WireWitness {
            anchor: fr_to_str(&t.anchor),
            old_state: serde_json::from_str(&t.old_state_json).expect("valid old_state json"),
            owner: fr_to_str(&t.owner),
            nsk: fr_to_str(&t.nsk),
            rho: fr_to_str(&t.rho),
            merkle_proof: (&t.merkle_proof).into(),
            effect_expr: serde_json::from_str(&t.effect_expr_json).expect("valid effect_expr json"),
            event: serde_json::from_str(&t.event_json).expect("valid event json"),
            new_owner: fr_to_str(&t.new_owner),
            new_rho: fr_to_str(&t.new_rho),
        }
    }
}
impl From<&WireWitness> for TransitionWitness {
    fn from(w: &WireWitness) -> Self {
        TransitionWitness {
            anchor: str_to_fr(&w.anchor),
            old_state_json: w.old_state.to_string(),
            owner: str_to_fr(&w.owner),
            nsk: str_to_fr(&w.nsk),
            rho: str_to_fr(&w.rho),
            merkle_proof: (&w.merkle_proof).into(),
            effect_expr_json: w.effect_expr.to_string(),
            event_json: w.event.to_string(),
            new_owner: str_to_fr(&w.new_owner),
            new_rho: str_to_fr(&w.new_rho),
        }
    }
}
