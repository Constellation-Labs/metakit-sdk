//! Ordinal-catalog attestation verifier.
//!
//! Given a trusted catalog root (from a signed `CommittedBreadcrumb`) and the
//! chain-wide `epoch_size`, verify an `OrdinalCatalogProof` — the catalog-side
//! attestation of "was an MPT root committed at snapshot ordinal N, and if so
//! which one?". Byte-for-byte aligned with the metakit (Scala) reference
//! (`lifecycle/committed/{CommitCatalog,OrdinalCatalogProof}.scala`), verified
//! against the shared `ordinal_catalog_test_vectors.json`. See
//! `docs/committed-roots.md`.
//!
//! The proof is a two-tier epoch rollup: the TOP catalog surfaces the hot-epoch
//! and level-1 (sealed) roots; a hot ordinal is one inclusion, an ancient
//! ordinal is two fixed-depth inclusions (level-1 -> sealed epoch tree),
//! non-membership is absence at both levels. Nothing inside the proof chooses
//! which keys are checked — they are recomputed locally from `ordinal` and
//! `epoch_size`, so a prover cannot prove absence in the wrong epoch tree.

use crate::auth_db::{check_smt_proof, hash_from_bytes, SmtCheckOutcome};

// --- catalog key derivation (CommitCatalog) ---
// Every catalog SMT key is: lowercaseHex( SHA-256( UTF-8(name) ) ) — a 64-char
// hex string, no `0x`. Integers inside names are plain decimal, unpadded.

fn catalog_key(name: &str) -> String {
    hash_from_bytes(name.as_bytes())
}

/// Catalog key for the hot-epoch subtree root (`sha256("epoch:hot")`).
pub fn hot_epochs_key() -> String {
    catalog_key("epoch:hot")
}

/// Catalog key for the level-1 (sealed epochs) subtree root (`sha256("epoch:sealed")`).
pub fn sealed_epochs_key() -> String {
    catalog_key("epoch:sealed")
}

/// Catalog key for a single ordinal (`sha256("ordinal:<N>")`).
pub fn ordinal_key(ordinal: u64) -> String {
    catalog_key(&format!("ordinal:{ordinal}"))
}

/// Catalog key for a sealed epoch's root (`sha256("epoch:<E>")`).
pub fn epoch_key(epoch: u64) -> String {
    catalog_key(&format!("epoch:{epoch}"))
}

/// `rootFromValueBytes`: the SMT leaf value bound to a child root is the raw 32
/// digest bytes, so the sub-tree root is their lowercase hex — a hex-encode, NOT
/// a hash.
fn root_from_value_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The verified outcome of an `OrdinalCatalogProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrdinalAttestation {
    /// Ordinal `ordinal` committed MPT root `mpt_root` (proven against the catalog root).
    CommittedAt { ordinal: u64, mpt_root: String },
    /// Ordinal `ordinal` is provably NOT committed in the catalog.
    NotCommitted { ordinal: u64 },
}

/// A verification-relevant failure (mirrors the verifier-produced subset of
/// Scala `CommittedProofError`). The `ProofInvalid` sub-cause is not recoverable
/// from the boolean SMT verifier, so it is reported at component granularity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrdinalCatalogError {
    WrongProofKey { component: String },
    ProofInvalid { component: String },
    MalformedOrdinalProof { reason: String },
}

/// The result of verifying an `OrdinalCatalogProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrdinalCatalogResult {
    Attested(OrdinalAttestation),
    Error(OrdinalCatalogError),
}

impl OrdinalCatalogResult {
    /// Serialize to the shared-vector `expected` shape for conformance comparison.
    pub fn to_expected_json(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            OrdinalCatalogResult::Attested(OrdinalAttestation::CommittedAt { ordinal, mpt_root }) => {
                json!({"type": "CommittedAt", "ordinal": ordinal, "mptRoot": mpt_root})
            }
            OrdinalCatalogResult::Attested(OrdinalAttestation::NotCommitted { ordinal }) => {
                json!({"type": "NotCommitted", "ordinal": ordinal})
            }
            OrdinalCatalogResult::Error(OrdinalCatalogError::WrongProofKey { component }) => {
                json!({"error": "WrongProofKey", "component": component})
            }
            OrdinalCatalogResult::Error(OrdinalCatalogError::ProofInvalid { component }) => {
                json!({"error": "ProofInvalid", "component": component})
            }
            OrdinalCatalogResult::Error(OrdinalCatalogError::MalformedOrdinalProof { .. }) => {
                json!({"error": "MalformedOrdinalProof"})
            }
        }
    }
}

/// Verify an `OrdinalCatalogProof` against a trusted `catalog_root` (raw
/// lowercase hex, no `0x`) under the chain-wide `epoch_size`.
///
/// `Err` only on an undecodable proof envelope / component or a non-positive
/// `epoch_size`; a well-formed proof that fails to attest is a
/// [`OrdinalCatalogResult::Error`], not an `Err`.
pub fn verify_ordinal_catalog_proof(
    catalog_root: &str,
    proof: &serde_json::Value,
    epoch_size: u64,
) -> Result<OrdinalCatalogResult, String> {
    use OrdinalCatalogError::{MalformedOrdinalProof, ProofInvalid, WrongProofKey};
    use OrdinalCatalogResult::{Attested, Error};

    if epoch_size == 0 {
        return Err("epochSize must be positive".to_string());
    }
    let obj = proof
        .as_object()
        .ok_or_else(|| "OrdinalCatalogProof: expected an object".to_string())?;
    let ordinal = obj
        .get("ordinal")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "OrdinalCatalogProof: `ordinal` must be a non-negative integer".to_string())?;
    let epoch = ordinal / epoch_size; // floor division

    let component = |name: &str| -> Result<&serde_json::Value, String> {
        obj.get(name)
            .ok_or_else(|| format!("OrdinalCatalogProof: missing `{name}`"))
    };

    // 1. topHot -> the hot epoch tree root (must be an inclusion in the top catalog).
    let hot_root = match check_smt_proof(catalog_root, component("topHot")?, &hot_epochs_key())? {
        SmtCheckOutcome::WrongKey { .. } => return Ok(Error(WrongProofKey { component: "topHot".into() })),
        SmtCheckOutcome::Invalid => return Ok(Error(ProofInvalid { component: "topHot".into() })),
        SmtCheckOutcome::Absent => {
            return Ok(Error(MalformedOrdinalProof {
                reason: "topHot must be an inclusion in the top catalog".into(),
            }))
        }
        SmtCheckOutcome::Present { value } => root_from_value_bytes(&value),
    };

    // 2. topSealed -> the level-1 (sealed epochs) tree root (must be an inclusion).
    let level1_root = match check_smt_proof(catalog_root, component("topSealed")?, &sealed_epochs_key())? {
        SmtCheckOutcome::WrongKey { .. } => return Ok(Error(WrongProofKey { component: "topSealed".into() })),
        SmtCheckOutcome::Invalid => return Ok(Error(ProofInvalid { component: "topSealed".into() })),
        SmtCheckOutcome::Absent => {
            return Ok(Error(MalformedOrdinalProof {
                reason: "topSealed must be an inclusion in the top catalog".into(),
            }))
        }
        SmtCheckOutcome::Present { value } => root_from_value_bytes(&value),
    };

    // 3. hot: is the ordinal in the current hot epoch?
    match check_smt_proof(&hot_root, component("hot")?, &ordinal_key(ordinal))? {
        SmtCheckOutcome::WrongKey { .. } => return Ok(Error(WrongProofKey { component: "hot".into() })),
        SmtCheckOutcome::Invalid => return Ok(Error(ProofInvalid { component: "hot".into() })),
        SmtCheckOutcome::Present { value } => {
            return Ok(Attested(OrdinalAttestation::CommittedAt {
                ordinal,
                mpt_root: root_from_value_bytes(&value),
            }))
        }
        SmtCheckOutcome::Absent => {}
    }

    // hot-absent -> 4. level1: was the ordinal's epoch ever sealed?
    let sealed_root = match check_smt_proof(&level1_root, component("level1")?, &epoch_key(epoch))? {
        SmtCheckOutcome::WrongKey { .. } => return Ok(Error(WrongProofKey { component: "level1".into() })),
        SmtCheckOutcome::Invalid => return Ok(Error(ProofInvalid { component: "level1".into() })),
        SmtCheckOutcome::Absent => return Ok(Attested(OrdinalAttestation::NotCommitted { ordinal })),
        SmtCheckOutcome::Present { value } => root_from_value_bytes(&value),
    };

    // 5. sealedEntry: inclusion of the ordinal inside its sealed epoch tree.
    let sealed_entry = obj.get("sealedEntry");
    match sealed_entry {
        None | Some(serde_json::Value::Null) => Ok(Error(MalformedOrdinalProof {
            reason: format!("epoch {epoch} is sealed; a sealedEntry proof is required"),
        })),
        Some(se) => Ok(match check_smt_proof(&sealed_root, se, &ordinal_key(ordinal))? {
            SmtCheckOutcome::WrongKey { .. } => Error(WrongProofKey { component: "sealedEntry".into() }),
            SmtCheckOutcome::Invalid => Error(ProofInvalid { component: "sealedEntry".into() }),
            SmtCheckOutcome::Present { value } => Attested(OrdinalAttestation::CommittedAt {
                ordinal,
                mpt_root: root_from_value_bytes(&value),
            }),
            SmtCheckOutcome::Absent => Attested(OrdinalAttestation::NotCommitted { ordinal }),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_keys_match_reference() {
        // Ground-truth: lowercaseHex(sha256(utf8(name))).
        assert_eq!(hot_epochs_key(), "bf219127ab671805b4bc75df3598e2db17eef5fab73facc3757e6baa8c416636");
        assert_eq!(sealed_epochs_key(), "19ab634f4720ce035b017e7ffb8e8ca5a4481e62309a5beffaf75da167ee1202");
        assert_eq!(ordinal_key(0), "c0020bf0613f2c15579e2e827e436cc0b445b6c2e2ee8f08922016e27c3d7be2");
        assert_eq!(ordinal_key(1), "2aeb90f46fe17b9672e4fe5b7f13ae003293a0fefe329e49095d77a727c1e19a");
        assert_eq!(epoch_key(0), "402a33e021e6fd2d8fb109ce145fef5df03a39a4d5e2f4f993fc812f79ca4692");
    }
}
