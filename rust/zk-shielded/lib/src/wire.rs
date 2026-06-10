//! Serde-serialisable WIRE format for the transfer witness, so the host can hand a
//! witness to the SP1 guest over stdin (and tests can round-trip it). Fr elements travel
//! as decimal strings — portable, exact, and human-debuggable — and are parsed back into
//! `BigUint` on the guest side.

use crate::{Note, OutputNote, SpendInput, TransferWitness};
use num_bigint::BigUint;
use poseidon_bn254::merkle::PoseidonMerkleProof;
use serde::{Deserialize, Serialize};

fn fr_to_str(x: &BigUint) -> String {
    x.to_str_radix(10)
}
fn str_to_fr(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).expect("valid decimal Fr in witness")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireNote {
    pub value: u64,
    pub owner: String,
    pub asset: String,
    pub rho: String,
}

impl From<&Note> for WireNote {
    fn from(n: &Note) -> Self {
        WireNote {
            value: n.value,
            owner: fr_to_str(&n.owner),
            asset: fr_to_str(&n.asset),
            rho: fr_to_str(&n.rho),
        }
    }
}
impl From<&WireNote> for Note {
    fn from(w: &WireNote) -> Self {
        Note {
            value: w.value,
            owner: str_to_fr(&w.owner),
            asset: str_to_fr(&w.asset),
            rho: str_to_fr(&w.rho),
        }
    }
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
pub struct WireSpendInput {
    pub note: WireNote,
    pub nsk: String,
    pub merkle_proof: WireProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireOutputNote {
    pub note: WireNote,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireWitness {
    pub anchor: String,
    pub inputs: Vec<WireSpendInput>,
    pub outputs: Vec<WireOutputNote>,
    pub fee: u64,
}

impl From<&TransferWitness> for WireWitness {
    fn from(w: &TransferWitness) -> Self {
        WireWitness {
            anchor: fr_to_str(&w.anchor),
            inputs: w
                .inputs
                .iter()
                .map(|i| WireSpendInput {
                    note: (&i.note).into(),
                    nsk: fr_to_str(&i.nsk),
                    merkle_proof: (&i.merkle_proof).into(),
                })
                .collect(),
            outputs: w.outputs.iter().map(|o| WireOutputNote { note: (&o.note).into() }).collect(),
            fee: w.fee,
        }
    }
}
impl From<&WireWitness> for TransferWitness {
    fn from(w: &WireWitness) -> Self {
        TransferWitness {
            anchor: str_to_fr(&w.anchor),
            inputs: w
                .inputs
                .iter()
                .map(|i| SpendInput {
                    note: (&i.note).into(),
                    nsk: str_to_fr(&i.nsk),
                    merkle_proof: (&i.merkle_proof).into(),
                })
                .collect(),
            outputs: w.outputs.iter().map(|o| OutputNote { note: (&o.note).into() }).collect(),
            fee: w.fee,
        }
    }
}
