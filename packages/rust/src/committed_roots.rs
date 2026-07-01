//! Committed-roots light-client codecs.
//!
//! The constant-size on-chain commitment a syncing (light) client trusts: the
//! two-tier state-root pair a metagraph commits at each snapshot, plus the
//! validated commit-key universe for MPT state lookups.
//!
//! Byte-for-byte aligned with the metakit (Scala) reference
//! (`lifecycle/committed/CommittedRoots.scala`, `CommitKey.scala`, verified by
//! `CommittedRootsCodecKatSuite`). See `docs/committed-roots.md` for the
//! light-client flow (anchor the roots via [`CommittedRoots::combined_hash`],
//! then verify inclusion with the JLVM `smt_verify` / `mpt_verify` opcodes).
//!
//! Wire forms (matching the Scala circe codecs exactly):
//!   - `SparseMerkleRoot`    -> `{ "value": <hash-hex> }`
//!   - `CommittedRoots`      -> `{ "mptRoot": <hash-hex>, "catalogRoot": { "value": <hash-hex> } }`
//!   - `CommittedBreadcrumb` -> `{ "ordinal": <number>, "roots": <CommittedRoots> }`
//!   - `CommitKey`           -> a bare validated string (e.g. `"fiber/abc-1"`)
//!
//! `mpt_root` is a bare hash hex (Scala `Hash`); `catalog_root` is a
//! `SparseMerkleRoot` object; `ordinal` is a bare non-negative integer (Scala
//! `SnapshotOrdinal`, whose encoder is `Encoder[NonNegLong].contramap`).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// A Sparse Merkle tree root — wire form `{ "value": <hash-hex> }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMerkleRoot {
    /// Lowercase hex of the 32-byte root digest.
    pub value: String,
}

/// The two-tier commitment of a snapshot: the state-dict MPT root (tier 1) and
/// the live catalog root (tier 2 — the full-history epoch rollup).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedRoots {
    /// State-dict MPT root, a bare hash hex (Scala `Hash`).
    #[serde(rename = "mptRoot")]
    pub mpt_root: String,
    /// Catalog root (the full root-history rollup).
    #[serde(rename = "catalogRoot")]
    pub catalog_root: SparseMerkleRoot,
}

impl CommittedRoots {
    /// `sha256(rawBytes(mptRoot) ++ rawBytes(catalogRoot))` — the single hash
    /// binding the pair, mpt first, both roots as their raw digest bytes,
    /// returned as lowercase hex. This is exactly what a snapshot's on-chain
    /// calculated-state proof anchors, so a light client checks a received
    /// breadcrumb by comparing this against the snapshot's `calculatedStateHash`.
    pub fn combined_hash(&self) -> Result<String, hex::FromHexError> {
        let mut bytes = hex::decode(&self.mpt_root)?;
        bytes.extend_from_slice(&hex::decode(&self.catalog_root.value)?);
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

/// The constant-size on-chain breadcrumb: the [`CommittedRoots`] pair committed
/// at one ordinal. The latest signed breadcrumb transitively commits the whole
/// root history, so a light client obtains the catalog root in O(1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedBreadcrumb {
    /// Snapshot ordinal — a bare non-negative integer.
    pub ordinal: u64,
    pub roots: CommittedRoots,
}

/// Reasons a string fails [`CommitKey`] validation (mirrors Scala `CommitKeyError`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CommitKeyError {
    #[error("commit key must not be empty")]
    EmptyKey,
    #[error("commit key exceeds {max} chars: {len}")]
    KeyTooLong { max: usize, len: usize },
    #[error("commit key has an empty segment: '{0}'")]
    EmptySegment(String),
    #[error("commit key exceeds {max} segments: {count}")]
    TooManySegments { max: usize, count: usize },
    #[error("commit key segment exceeds {max} chars: '{segment}'")]
    SegmentTooLong { max: usize, segment: String },
    #[error("commit key segment must match ^[a-z0-9][a-z0-9._-]*$: '{0}'")]
    InvalidSegment(String),
}

/// A validated, namespaced path into the committed state dictionary — the MPT
/// key universe. The MPT path of a key is the lowercase hex of its UTF-8 bytes
/// ([`CommitKey::to_hex`]); because `/` is a single byte (0x2f), the hex of
/// `"ns/"` is a strict prefix of every key under namespace `ns`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitKey(String);

impl CommitKey {
    pub const MAX_SEGMENT_LENGTH: usize = 64;
    pub const MAX_SEGMENTS: usize = 16;
    pub const MAX_KEY_LENGTH: usize = 256;

    /// Validate and construct. Returns [`CommitKeyError`] on malformed input.
    pub fn from(value: &str) -> Result<CommitKey, CommitKeyError> {
        validate(value)?;
        Ok(CommitKey(value.to_string()))
    }

    /// True if `value` is a well-formed commit key.
    pub fn is_valid(value: &str) -> bool {
        validate(value).is_ok()
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    /// The MPT path: lowercase hex of the UTF-8 bytes of the key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// The UTF-8 bytes of the key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn segments(&self) -> Vec<&str> {
        self.0.split('/').collect()
    }

    /// The top-level namespace (first segment).
    pub fn namespace(&self) -> &str {
        self.0.split('/').next().unwrap_or("")
    }
}

fn is_valid_segment(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c0) if c0.is_ascii_lowercase() || c0.is_ascii_digit() => s.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-'
        }),
        _ => false,
    }
}

fn validate(value: &str) -> Result<(), CommitKeyError> {
    if value.is_empty() {
        return Err(CommitKeyError::EmptyKey);
    }
    let len = value.chars().count();
    if len > CommitKey::MAX_KEY_LENGTH {
        return Err(CommitKeyError::KeyTooLong {
            max: CommitKey::MAX_KEY_LENGTH,
            len,
        });
    }
    let segments: Vec<&str> = value.split('/').collect();
    if value.starts_with('/') || value.ends_with('/') || segments.iter().any(|s| s.is_empty()) {
        return Err(CommitKeyError::EmptySegment(value.to_string()));
    }
    if segments.len() > CommitKey::MAX_SEGMENTS {
        return Err(CommitKeyError::TooManySegments {
            max: CommitKey::MAX_SEGMENTS,
            count: segments.len(),
        });
    }
    for s in &segments {
        if s.chars().count() > CommitKey::MAX_SEGMENT_LENGTH {
            return Err(CommitKeyError::SegmentTooLong {
                max: CommitKey::MAX_SEGMENT_LENGTH,
                segment: s.to_string(),
            });
        }
        if !is_valid_segment(s) {
            return Err(CommitKeyError::InvalidSegment(s.to_string()));
        }
    }
    Ok(())
}

// CommitKey encodes as a bare validated string (matching the Scala newtype).
impl Serialize for CommitKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CommitKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        CommitKey::from(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-for-byte KATs mirroring the metakit (Scala) `CommittedRootsCodecKatSuite`.
    // mptRoot = Hash("aa" * 32), catalogRoot = SparseMerkleRoot(Hash("bb" * 32)).
    fn roots() -> CommittedRoots {
        CommittedRoots {
            mpt_root: "aa".repeat(32),
            catalog_root: SparseMerkleRoot {
                value: "bb".repeat(32),
            },
        }
    }

    #[test]
    fn commit_key_bare_string_and_hex() {
        let k = CommitKey::from("fiber/abc-1").unwrap();
        assert_eq!(serde_json::to_string(&k).unwrap(), "\"fiber/abc-1\"");
        assert_eq!(k.to_hex(), "66696265722f6162632d31"); // hex of UTF-8 "fiber/abc-1"
        assert_eq!(k.namespace(), "fiber");
        // round-trip through the bare-string codec
        let decoded: CommitKey = serde_json::from_str("\"fiber/abc-1\"").unwrap();
        assert_eq!(decoded, k);
    }

    #[test]
    fn commit_key_rejections() {
        assert!(matches!(CommitKey::from(""), Err(CommitKeyError::EmptyKey)));
        assert!(matches!(
            CommitKey::from("/fiber"),
            Err(CommitKeyError::EmptySegment(_))
        ));
        assert!(matches!(
            CommitKey::from("fiber/"),
            Err(CommitKeyError::EmptySegment(_))
        ));
        assert!(matches!(
            CommitKey::from("fiber//abc"),
            Err(CommitKeyError::EmptySegment(_))
        ));
        assert!(matches!(
            CommitKey::from("Fiber"),
            Err(CommitKeyError::InvalidSegment(_))
        )); // uppercase
        assert!(matches!(
            CommitKey::from(&"a".repeat(65)),
            Err(CommitKeyError::SegmentTooLong { .. })
        ));
        let many = vec!["a"; 17].join("/");
        assert!(matches!(
            CommitKey::from(&many),
            Err(CommitKeyError::TooManySegments { .. })
        ));
        assert!(CommitKey::is_valid("fiber/abc-1"));
        assert!(!CommitKey::is_valid("Fiber"));
    }

    #[test]
    fn committed_roots_wire_and_hash() {
        let r = roots();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"mptRoot\":\"{}\",\"catalogRoot\":{{\"value\":\"{}\"}}}}",
                "aa".repeat(32),
                "bb".repeat(32)
            )
        );
        assert_eq!(serde_json::from_str::<CommittedRoots>(&json).unwrap(), r);
        // Known-answer: sha256(0xaa*32 ++ 0xbb*32)
        assert_eq!(
            r.combined_hash().unwrap(),
            "e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6"
        );
    }

    #[test]
    fn committed_breadcrumb_wire() {
        let b = CommittedBreadcrumb {
            ordinal: 0,
            roots: roots(),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"ordinal\":0,\"roots\":{{\"mptRoot\":\"{}\",\"catalogRoot\":{{\"value\":\"{}\"}}}}}}",
                "aa".repeat(32),
                "bb".repeat(32)
            )
        );
        assert_eq!(
            serde_json::from_str::<CommittedBreadcrumb>(&json).unwrap(),
            b
        );
    }
}
