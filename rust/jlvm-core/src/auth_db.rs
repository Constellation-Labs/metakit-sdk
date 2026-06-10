//! Pure, deterministic implementations of the Tier-2a auth-DB ZK opcodes.
//!
//! Byte-for-byte port of the Scala
//! `io.constellationnetwork.metagraph_sdk.json_logic.ops.AuthDbOps` (WAVE 3:
//! `smt_verify`, `mpt_verify`, `mpt_prefix_verify`) together with the two
//! authenticated-database primitives it consumes:
//!   - the Sparse Merkle Tree verifier (`crypto/smt`), and
//!   - the Merkle Patricia Trie single / batch inclusion verifiers (`crypto/mpt`).
//!
//! # Hashing substrate
//!
//! All node and value digests route through the metakit canonical-bytes seam,
//! `std/JsonBinaryHasher.computeDigest = Hash.fromBytes(prefix ++ canonicalBytes)`:
//!   - `canonicalBytes` is the RFC-8785 (JCS) canonical encoding of the value's
//!     circe `Json` ([`crate::canonical::canonicalize_json`]); object keys are
//!     sorted, numbers route through `f64`.
//!   - `prefix` is a 1-byte domain-separation tag (leaf / branch / extension /
//!     internal), or empty for a raw value digest.
//!   - `Hash.fromBytes` is **lowercase-hex SHA-256** (tessellation
//!     `security.hash.Hash`); the resulting `Hash.value` is the 64-char hex string,
//!     and all digest equality is exact string equality on that form.
//!
//! Two subtleties this port pins down (caught by the cross-check vectors):
//!   1. Node-commitment pre-images use each commitment's **concrete** circe
//!      encoder (`{remaining, dataDigest}`, `{position, valueDigest}`, ...), NOT
//!      the sealed-trait `{type, contents}` wrapper -- `commitment.asJson` in the
//!      Scala verifiers resolves the concrete-type encoder.
//!   2. The canonicalizer **sorts object keys** (UTF-16), so e.g. an MPT leaf
//!      pre-image is `{"dataDigest":...,"remaining":...}` regardless of encoder
//!      field order.
//!
//! # Error discipline (mirrors `AuthDbOps`)
//!
//! Malformed / undecodable input (bad hex, a proof that does not match its
//! declared shape, wrong arg count or type) is an `Err(String)` -- the Scala
//! `JsonLogicException`. A WELL-FORMED proof that simply does not verify against
//! the root is a `false` / `valid:false` VALUE, so contracts can branch on it.

use crate::canonical::canonicalize_json;
use crate::value::{encode_value, Value};
use serde_json::json;
use sha2::{Digest, Sha256};

// ===========================================================================
// Hashing substrate.
// ===========================================================================

/// `Hash.fromBytes`: lowercase-hex SHA-256 of `bytes`. The returned `String` is
/// the 64-char lowercase hex digest -- the same `Hash.value` form the Scala
/// primitives compare on.
fn hash_from_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `Hash.empty`: the all-zeros default-subtree placeholder. Scala builds this as
/// `"%064d".format(0)` -- 64 ASCII `'0'` characters (which, read as hex, decodes
/// to 32 zero bytes).
fn hash_empty() -> String {
    "0".repeat(64)
}

/// `JsonBinaryHasher.computeDigest(json, prefix)` for a circe-`Json`-shaped value:
/// `Hash.fromBytes(prefix ++ canonicalBytes(json))`.
fn compute_digest_prefixed(json: &serde_json::Value, prefix: &[u8]) -> String {
    let canon = canonicalize_json(json);
    let mut pre = Vec::with_capacity(prefix.len() + canon.len());
    pre.extend_from_slice(prefix);
    pre.extend_from_slice(&canon);
    hash_from_bytes(&pre)
}

/// `JsonBinaryHasher.computeDigest(json)` with the empty prefix: the value digest
/// committed in an MPT leaf and computed by `mpt_verify` / `mpt_prefix_verify`.
fn compute_value_digest(json: &serde_json::Value) -> String {
    compute_digest_prefixed(json, &[])
}

// ===========================================================================
// Shared argument helpers (mirroring AuthDbOps.expectStr / parse*Hex).
// ===========================================================================

fn expect_str<'a>(role: &str, v: &'a Value) -> Result<&'a str, String> {
    match v {
        Value::Str(s) => Ok(s.as_str()),
        other => Err(format!(
            "{role}: expected a hex string, got {}",
            other.tag()
        )),
    }
}

/// Lowercase-hex / `0x`-prefix validation: `^0x[0-9a-f]*$` (mirrors
/// `HexBytes.HexPattern`).
fn is_valid_hex(hex: &str) -> bool {
    match hex.strip_prefix("0x") {
        Some(body) => body
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        None => false,
    }
}

/// `HexBytes.parseBytes(hex, None, role)` then `Hash(Hex.fromBytes(bytes).value)`:
/// validate `0x`-lowercase, even-length, and return the raw lowercase hex body
/// (no `0x`) -- the `Hash.value` form the SMT/MPT roots compare on. A wrong width
/// is permitted at the parse boundary; it simply fails the verify (RootMismatch).
fn parse_hash_hex(hex: &str, role: &str) -> Result<String, String> {
    if !is_valid_hex(hex) {
        return Err(format!(
            "{role}: malformed hex (expected lowercase ^0x[0-9a-f]*$): '{hex}'"
        ));
    }
    let body = &hex[2..];
    #[allow(clippy::manual_is_multiple_of)]
    if body.len() % 2 != 0 {
        return Err(format!(
            "{role}: odd-length hex body ({} nibbles): '{hex}'",
            body.len()
        ));
    }
    // Already lowercase by the pattern; this is the `Hex.fromBytes(bytes).value`
    // round-trip (which would also lowercase) applied to a validated body.
    Ok(body.to_string())
}

/// `HexBytes.parseNibbleHex(hex, role)`: validate `0x`-lowercase (odd nibble
/// counts ALLOWED -- MPT keys/prefixes are nibble-granular) and return the raw
/// hex body (no `0x`), the tessellation `Hex.value` form.
fn parse_nibble_hex(hex: &str, role: &str) -> Result<String, String> {
    if !is_valid_hex(hex) {
        return Err(format!(
            "{role}: malformed hex (expected lowercase ^0x[0-9a-f]*$): '{hex}'"
        ));
    }
    Ok(hex[2..].to_string())
}

/// Bridge a JLVM value to its circe-`Json`-equivalent `serde_json::Value` (the
/// `v.asJson` step), so it can be canonicalized for hashing or deserialized into a
/// proof type.
fn to_json(v: &Value) -> serde_json::Value {
    encode_value(v)
}

// ===========================================================================
// SMT verifier (port of crypto/smt + api/SparseMerkleVerifier).
// ===========================================================================

/// Total number of SMT position bits (256 -- a SHA-256 hash).
const SMT_POSITION_BITS: usize = 256;
/// Domain-separation prefix for an SMT leaf commitment pre-image.
const SMT_LEAF_PREFIX: &[u8] = &[0];
/// Domain-separation prefix for an SMT internal-node commitment pre-image.
const SMT_INTERNAL_PREFIX: &[u8] = &[1];

/// A decoded SMT sibling (`{"digest": hash}`).
struct SmtSibling {
    digest: String,
}

/// A decoded `SparseMerkleProof` (Inclusion | Absence{Default,OtherLeaf}).
enum SmtProof {
    Inclusion {
        key: String,
        value: Vec<u8>,
        value_digest: String,
        siblings: Vec<SmtSibling>,
    },
    AbsenceDefault {
        key: String,
        siblings: Vec<SmtSibling>,
    },
    AbsenceOtherLeaf {
        key: String,
        occupying_key: String,
        occupying_data_digest: String,
        siblings: Vec<SmtSibling>,
    },
}

impl SmtProof {
    fn key(&self) -> &str {
        match self {
            SmtProof::Inclusion { key, .. }
            | SmtProof::AbsenceDefault { key, .. }
            | SmtProof::AbsenceOtherLeaf { key, .. } => key,
        }
    }

    fn siblings(&self) -> &[SmtSibling] {
        match self {
            SmtProof::Inclusion { siblings, .. }
            | SmtProof::AbsenceDefault { siblings, .. }
            | SmtProof::AbsenceOtherLeaf { siblings, .. } => siblings,
        }
    }
}

/// Decode an SMT proof from a JSON object, mirroring `SparseMerkleProof.decoder`.
/// Any missing/typed-wrong field is an `Err` (undecodable proof -> Result error).
fn decode_smt_proof(j: &serde_json::Value) -> Result<SmtProof, String> {
    let role = "smt_verify proof";
    let obj = j
        .as_object()
        .ok_or_else(|| format!("{role}: undecodable proof JSON (not an object)"))?;
    let ty = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (missing type)"))?;
    let key = field_str(obj, "key", role)?;
    let siblings = decode_smt_siblings(obj.get("siblings"), role)?;
    match ty {
        "Inclusion" => {
            let value_hex = field_str(obj, "value", role)?;
            let value = decode_hex_value(&value_hex, role)?;
            let value_digest = field_str(obj, "valueDigest", role)?;
            Ok(SmtProof::Inclusion {
                key,
                value,
                value_digest,
                siblings,
            })
        }
        "Absence" => {
            let witness = obj
                .get("witness")
                .and_then(|v| v.as_object())
                .ok_or_else(|| format!("{role}: undecodable proof JSON (missing witness)"))?;
            let wty = witness
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("{role}: undecodable proof JSON (missing witness type)"))?;
            match wty {
                "Default" => Ok(SmtProof::AbsenceDefault { key, siblings }),
                "OtherLeaf" => {
                    let occupying_key = field_str(witness, "occupyingKey", role)?;
                    let occupying_data_digest = field_str(witness, "occupyingDataDigest", role)?;
                    Ok(SmtProof::AbsenceOtherLeaf {
                        key,
                        occupying_key,
                        occupying_data_digest,
                        siblings,
                    })
                }
                other => Err(format!("{role}: Unknown AbsenceWitness type: {other}")),
            }
        }
        other => Err(format!("{role}: Unknown SparseMerkleProof type: {other}")),
    }
}

fn decode_smt_siblings(
    v: Option<&serde_json::Value>,
    role: &str,
) -> Result<Vec<SmtSibling>, String> {
    let arr = v
        .and_then(|s| s.as_array())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (siblings not an array)"))?;
    arr.iter()
        .map(|s| {
            s.as_object()
                .and_then(|o| o.get("digest"))
                .and_then(|d| d.as_str())
                .map(|d| SmtSibling {
                    digest: d.to_string(),
                })
                .ok_or_else(|| format!("{role}: undecodable proof JSON (bad sibling)"))
        })
        .collect()
}

fn field_str(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    role: &str,
) -> Result<String, String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (missing/typed-wrong '{key}')"))
}

/// `SparseMerkleProof.valueDecoder`: `Decoder[Hex].map(_.toBytes)`. The value is a
/// raw (no `0x`) hex string; decode it to its bytes. Non-hex -> Err.
fn decode_hex_value(hex: &str, role: &str) -> Result<Vec<u8>, String> {
    let lower = hex.to_ascii_lowercase();
    #[allow(clippy::manual_is_multiple_of)]
    if lower.len() % 2 != 0 || !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{role}: undecodable proof JSON (value not hex): '{hex}'"
        ));
    }
    Ok((0..lower.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&lower[i..i + 2], 16).expect("validated hex"))
        .collect())
}

/// SMT `position(key) = Hash.fromBytes(key.value.getBytes(UTF_8))` -- the digest of
/// the UTF-8 bytes of the key's hex string (NOT the decoded bytes).
fn smt_position(key: &str) -> String {
    hash_from_bytes(key.as_bytes())
}

/// SMT `valueDigest(value) = Hash.fromBytes(value)` -- raw-bytes SHA-256.
fn smt_value_digest(value: &[u8]) -> String {
    hash_from_bytes(value)
}

/// SMT `leafDigest(position, valueDigest)` = `computeDigest(Leaf{position,
/// valueDigest}.asJson, LeafPrefix)`. The concrete `Leaf` encoder is
/// `{position, valueDigest}` (canonicalizer keeps that order: 'p' < 'v').
fn smt_leaf_digest(position: &str, value_digest: &str) -> String {
    let commitment = json!({ "position": position, "valueDigest": value_digest });
    compute_digest_prefixed(&commitment, SMT_LEAF_PREFIX)
}

/// SMT `internalDigest(left, right)` = `computeDigest(Internal{left,
/// right}.asJson, InternalPrefix)`. Concrete `Internal` encoder = `{left, right}`.
fn smt_internal_digest(left: &str, right: &str) -> String {
    let commitment = json!({ "left": left, "right": right });
    compute_digest_prefixed(&commitment, SMT_INTERNAL_PREFIX)
}

/// SMT `combine(bit, cur, sibling)`: bit=false -> path went LEFT (cur is left
/// child); bit=true -> path went RIGHT.
fn smt_combine(bit: bool, cur: &str, sibling: &str) -> String {
    if bit {
        smt_internal_digest(sibling, cur)
    } else {
        smt_internal_digest(cur, sibling)
    }
}

/// SMT `bit(position, index)`: bit `index` (0 = MSB of the first byte) of the
/// 32-byte position hash, read big-endian. The position is a 64-char hex string;
/// it is decoded to its 32 raw bytes first. Out-of-range -> false.
fn smt_bit(position: &str, index: usize) -> bool {
    // `Hex(position.value).toBytes`: decode the hex string to bytes. If the
    // position is not valid even-length hex (it always is here -- it is a SHA-256
    // hash), treat as all-zero (defensive, matches an empty byte array fold).
    let bytes = match decode_hex_value(position, "smt position") {
        Ok(b) => b,
        Err(_) => return false,
    };
    let byte_idx = index / 8;
    if byte_idx >= bytes.len() {
        return false;
    }
    let bit_in_byte = 7 - (index % 8);
    ((bytes[byte_idx] >> bit_in_byte) & 1) == 1
}

/// Fold a terminating digest `start` (at depth = `siblings.len()`) up to the root,
/// choosing left/right at each level by the corresponding bit of `position`.
/// `siblings` is top-down (root-first); consumed deepest-first.
fn smt_fold_up(position: &str, start: &str, siblings: &[SmtSibling]) -> String {
    let depth = siblings.len();
    let mut cur = start.to_string();
    // (level, sibling) pairs, deepest level first: level d-1 down to 0.
    for (i, sib) in siblings.iter().rev().enumerate() {
        let level = depth - 1 - i;
        cur = smt_combine(smt_bit(position, level), &cur, &sib.digest);
    }
    cur
}

/// The verified outcome of an SMT proof: either present (with value bytes) or
/// proven absent. `None` means a well-formed-but-invalid proof (RootMismatch,
/// ValueBindingFailed, MalformedProof) -> `valid:false`.
enum SmtVerified {
    Present { key: String, value: Vec<u8> },
    Absent { key: String },
}

/// `SparseMerkleVerifier.verify`: returns `Some(entry)` iff the proof folds to the
/// trusted `root`; `None` for any verification error (RootMismatch /
/// ValueBindingFailed / MalformedProof / OtherLeaf-collides).
fn smt_verify_proof(root: &str, proof: &SmtProof) -> Option<SmtVerified> {
    if proof.siblings().len() > SMT_POSITION_BITS {
        return None; // MalformedProof: PathTooDeep
    }
    match proof {
        SmtProof::Inclusion {
            key,
            value,
            value_digest,
            siblings,
        } => {
            let computed = smt_value_digest(value);
            if &computed != value_digest {
                return None; // ValueBindingFailed
            }
            let pos = smt_position(key);
            let leaf = smt_leaf_digest(&pos, value_digest);
            let recomputed = smt_fold_up(&pos, &leaf, siblings);
            if recomputed == root {
                Some(SmtVerified::Present {
                    key: key.clone(),
                    value: value.clone(),
                })
            } else {
                None // RootMismatch
            }
        }
        SmtProof::AbsenceDefault { key, siblings } => {
            let pos = smt_position(key);
            let recomputed = smt_fold_up(&pos, &hash_empty(), siblings);
            if recomputed == root {
                Some(SmtVerified::Absent { key: key.clone() })
            } else {
                None
            }
        }
        SmtProof::AbsenceOtherLeaf {
            key,
            occupying_key,
            occupying_data_digest,
            siblings,
        } => {
            let pos = smt_position(key);
            let occ_pos = smt_position(occupying_key);
            if occ_pos == pos {
                return None; // MalformedProof: OtherLeafCollidesWithKey
            }
            let leaf = smt_leaf_digest(&occ_pos, occupying_data_digest);
            let recomputed = smt_fold_up(&pos, &leaf, siblings);
            if recomputed == root {
                Some(SmtVerified::Absent { key: key.clone() })
            } else {
                None
            }
        }
    }
}

/// Render a tessellation `Hex` key as the JLVM's `0x`-prefixed lowercase hex
/// convention: `keyHex(key) = "0x" + key.value.toLowerCase`.
fn key_hex(key: &str) -> String {
    format!("0x{}", key.to_ascii_lowercase())
}

/// Bridge raw value bytes (from a verified SMT entry) to a JLVM value: parse the
/// bytes as UTF-8 JSON and decode to a JLVM value; on failure, fall back to the
/// `0x`-hex of the bytes. Mirrors `AuthDbOps.valueToJlv`.
fn value_to_jlv(value: &[u8]) -> Value {
    if let Ok(s) = std::str::from_utf8(value) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(s) {
            return crate::value::decode_value(&j);
        }
    }
    // Fallback: "0x" + Hex.fromBytes(value).value.toLowerCase
    let mut hex = String::with_capacity(2 + value.len() * 2);
    hex.push_str("0x");
    for b in value {
        hex.push_str(&format!("{b:02x}"));
    }
    Value::Str(hex)
}

/// Build the `smt_verify` result object
/// (`{valid, included, key, value}`), preserving the Scala field order
/// (canonicalization re-sorts keys anyway).
fn smt_result(valid: bool, included: bool, key: String, value: Value) -> Value {
    Value::Map(vec![
        ("valid".to_string(), Value::Bool(valid)),
        ("included".to_string(), Value::Bool(included)),
        ("key".to_string(), Value::Str(key)),
        ("value".to_string(), value),
    ])
}

/// `smt_verify([rootHex, proofJson]) -> {valid, included, key, value}`.
pub fn smt_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [root_v, proof_v] => {
            let root_hex = expect_str("smt_verify root", root_v)?;
            let root = parse_hash_hex(root_hex, "smt_verify root")?;
            let proof_json = to_json(proof_v);
            let proof = decode_smt_proof(&proof_json)?;

            match smt_verify_proof(&root, &proof) {
                // A well-formed proof that does not verify => valid:false.
                None => Ok(smt_result(false, false, key_hex(proof.key()), Value::Null)),
                Some(SmtVerified::Present { key, value }) => {
                    Ok(smt_result(true, true, key_hex(&key), value_to_jlv(&value)))
                }
                Some(SmtVerified::Absent { key }) => {
                    Ok(smt_result(true, false, key_hex(&key), Value::Null))
                }
            }
        }
        _ => Err(format!(
            "smt_verify: expected [rootHex, proofJson], got {values:?}"
        )),
    }
}

// ===========================================================================
// MPT verifier (port of crypto/mpt + api/MerklePatriciaVerifier).
// ===========================================================================

/// Domain-separation prefix for an MPT leaf node commitment pre-image.
const MPT_LEAF_PREFIX: &[u8] = &[0];
/// Domain-separation prefix for an MPT branch node commitment pre-image.
const MPT_BRANCH_PREFIX: &[u8] = &[1];
/// Domain-separation prefix for an MPT extension node commitment pre-image.
const MPT_EXTENSION_PREFIX: &[u8] = &[2];

/// A decoded `MerklePatriciaCommitment`. Nibble sequences are kept as their hex
/// string form (one hex char per nibble), exactly as the circe encoders emit.
#[derive(Clone)]
enum MptCommitment {
    /// `{remaining, dataDigest}` -- `remaining` is the leaf's nibble suffix.
    Leaf {
        remaining: String,
        data_digest: String,
    },
    /// `{pathsDigest: {nibble -> hash}}` -- child digests keyed by single-nibble.
    Branch { paths_digest: Vec<(String, String)> },
    /// `{shared, childDigest}` -- `shared` is the extension's shared nibble prefix.
    Extension {
        shared: String,
        child_digest: String,
    },
}

impl MptCommitment {
    /// The commitment's prefixed digest: `computeDigest(commitment.asJson,
    /// prefix)`, using the concrete-type circe encoder shape.
    fn digest(&self) -> String {
        match self {
            MptCommitment::Leaf {
                remaining,
                data_digest,
            } => {
                let j = json!({ "remaining": remaining, "dataDigest": data_digest });
                compute_digest_prefixed(&j, MPT_LEAF_PREFIX)
            }
            MptCommitment::Branch { paths_digest } => {
                let mut obj = serde_json::Map::new();
                for (k, v) in paths_digest {
                    obj.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
                let j = json!({ "pathsDigest": serde_json::Value::Object(obj) });
                compute_digest_prefixed(&j, MPT_BRANCH_PREFIX)
            }
            MptCommitment::Extension {
                shared,
                child_digest,
            } => {
                let j = json!({ "shared": shared, "childDigest": child_digest });
                compute_digest_prefixed(&j, MPT_EXTENSION_PREFIX)
            }
        }
    }
}

/// Decode a single `MerklePatriciaCommitment` from `{type, contents}` JSON.
fn decode_mpt_commitment(j: &serde_json::Value, role: &str) -> Result<MptCommitment, String> {
    let obj = j
        .as_object()
        .ok_or_else(|| format!("{role}: undecodable proof JSON (commitment not an object)"))?;
    let ty = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (commitment missing type)"))?;
    let contents = obj
        .get("contents")
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (commitment missing contents)"))?;
    match ty {
        "Leaf" => {
            let remaining = nibble_str(contents.get("remaining"), role)?;
            let data_digest = obj_field_str(contents, "dataDigest", role)?;
            Ok(MptCommitment::Leaf {
                remaining,
                data_digest,
            })
        }
        "Branch" => {
            let pd = contents
                .get("pathsDigest")
                .and_then(|v| v.as_object())
                .ok_or_else(|| format!("{role}: undecodable proof JSON (bad pathsDigest)"))?;
            let mut paths_digest: Vec<(String, String)> = Vec::with_capacity(pd.len());
            for (k, v) in pd {
                // Keys are single nibbles (one hex char); values are hashes.
                if k.len() != 1 || !k.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!(
                        "{role}: undecodable proof JSON (bad nibble key '{k}')"
                    ));
                }
                let h = v.as_str().ok_or_else(|| {
                    format!("{role}: undecodable proof JSON (bad pathsDigest value)")
                })?;
                paths_digest.push((k.clone(), h.to_string()));
            }
            Ok(MptCommitment::Branch { paths_digest })
        }
        "Extension" => {
            let shared = nibble_str(contents.get("shared"), role)?;
            let child_digest = obj_field_str(contents, "childDigest", role)?;
            Ok(MptCommitment::Extension {
                shared,
                child_digest,
            })
        }
        other => Err(format!("{role}: Unknown type: {other}")),
    }
}

/// Decode a nibble-sequence field: a string of hex chars (one per nibble). The
/// circe `nibbleSeqDecoder` validates each char is a hex nibble.
fn nibble_str(v: Option<&serde_json::Value>, role: &str) -> Result<String, String> {
    let s = v
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (nibble field not a string)"))?;
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{role}: undecodable proof JSON (bad nibble seq '{s}')"
        ));
    }
    Ok(s.to_string())
}

fn obj_field_str(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    role: &str,
) -> Result<String, String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (missing/typed-wrong '{key}')"))
}

/// A decoded single-path `MerklePatriciaInclusionProof` (`{path, witness}`).
struct MptInclusionProof {
    path: String,
    witness: Vec<MptCommitment>,
}

fn decode_mpt_inclusion_proof(
    j: &serde_json::Value,
    role: &str,
) -> Result<MptInclusionProof, String> {
    let obj = j
        .as_object()
        .ok_or_else(|| format!("{role}: undecodable proof JSON (not an object)"))?;
    let path = obj_field_str(obj, "path", role)?;
    // path is a Hex (raw hex string); the circe Hex decoder accepts any string,
    // and Nibble(path) maps each char to a nibble (non-hex chars become nibble 0
    // via the lenient `Nibble.unsafe` used by `Nibble.apply(Hex)`). We mirror the
    // verifier's use of `Nibble(proof.path)` exactly (see `path_nibbles`).
    let witness_arr = obj
        .get("witness")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (witness not an array)"))?;
    let witness = witness_arr
        .iter()
        .map(|c| decode_mpt_commitment(c, role))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MptInclusionProof { path, witness })
}

/// `Nibble(hex: Hex)`: one nibble per character of the hex string. `Nibble.apply`
/// uses `unsafe`, which for a non-hex char yields `(char & 0x0f)` -- but every
/// path in practice is hex. We represent a nibble by its 0..=15 value.
fn path_nibbles(path: &str) -> Vec<u8> {
    path.chars()
        .map(|c| {
            // Mirror Nibble.unsafe(char): hex chars 0-9/a-f/A-F map to their value;
            // anything else is masked. Java `char.toByte & 0x0f` for non-hex.
            match c {
                '0'..='9' => (c as u8) - b'0',
                'a'..='f' => (c as u8) - b'a' + 10,
                'A'..='F' => (c as u8) - b'A' + 10,
                other => (other as u8) & 0x0f,
            }
        })
        .collect()
}

/// Render a 0..=15 nibble value as its lowercase hex char (for comparing against a
/// decoded commitment's nibble-string fields).
fn nibble_char(n: u8) -> char {
    char::from_digit(n as u32 & 0x0f, 16).unwrap_or('0')
}

/// Render a nibble slice as a hex string (one char per nibble).
fn nibbles_to_str(nibbles: &[u8]) -> String {
    nibbles.iter().map(|n| nibble_char(*n)).collect()
}

/// `MerklePatriciaVerifier.confirm`: walk the leaf-first witness (`witness.reverse`)
/// from the root, folding through extension/branch nodes and terminating at a
/// single leaf. Returns `true` iff the proof reproduces the root for `path`.
fn mpt_confirm(root: &str, proof: &MptInclusionProof) -> bool {
    // The verifier folds `proof.witness.reverse` starting at `root` with the full
    // path nibbles. We mutate a working list (consumed head-first).
    let mut commitments: Vec<MptCommitment> = proof.witness.iter().rev().cloned().collect();
    let mut current_digest = root.to_string();
    let mut remaining: Vec<u8> = path_nibbles(&proof.path);

    loop {
        match commitments.split_first() {
            // A single trailing Leaf: terminal.
            Some((
                MptCommitment::Leaf {
                    remaining: leaf_rem,
                    ..
                },
                [],
            )) => {
                let leaf = commitments[0].clone();
                let digest = leaf.digest();
                return digest == current_digest && &nibbles_to_str(&remaining) == leaf_rem;
            }
            Some((
                MptCommitment::Extension {
                    shared,
                    child_digest,
                },
                _,
            )) => {
                let head = commitments[0].clone();
                let digest = head.digest();
                if digest != current_digest {
                    return false; // InvalidNodeCommitment
                }
                current_digest = child_digest.clone();
                let drop = shared.chars().count();
                if drop > remaining.len() {
                    // remaining.drop(n) in Scala clamps; mirror that.
                    remaining.clear();
                } else {
                    remaining = remaining[drop..].to_vec();
                }
                commitments.remove(0);
            }
            Some((MptCommitment::Branch { paths_digest }, _)) => {
                let head = commitments[0].clone();
                // verifyBranch: select child by remainingPath.head BEFORE hashing.
                let Some(&first) = remaining.first() else {
                    return false; // remainingPath.head on empty -> Scala throws -> false
                };
                let nib = nibble_char(first).to_string();
                match paths_digest.iter().find(|(k, _)| *k == nib) {
                    Some((_, child)) => {
                        let digest = head.digest();
                        if digest != current_digest {
                            return false; // InvalidNodeCommitment
                        }
                        current_digest = child.clone();
                        remaining = remaining[1..].to_vec();
                        commitments.remove(0);
                    }
                    None => return false, // InvalidPath
                }
            }
            // A Leaf that is not the sole remaining commitment, or empty list, or
            // any other shape -> InvalidWitness.
            _ => return false,
        }
    }
}

/// `mpt_verify([rootHex, keyHex, valueJson, proofJson]) -> bool`.
pub fn mpt_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [root_v, key_v, value_v, proof_v] => {
            let root_hex = expect_str("mpt_verify root", root_v)?;
            let root = parse_hash_hex(root_hex, "mpt_verify root")?;
            let key_hex_s = expect_str("mpt_verify key", key_v)?;
            let key = parse_nibble_hex(key_hex_s, "mpt_verify key")?;
            let value_js = to_json(value_v);
            let proof_json = to_json(proof_v);
            let proof = decode_mpt_inclusion_proof(&proof_json, "mpt_verify proof")?;

            // The proof's path must be exactly the queried key (case-insensitive).
            if !proof.path.eq_ignore_ascii_case(&key) {
                return Ok(Value::Bool(false));
            }
            // The leaf commitment must bind the queried value
            // (dataDigest == computeDigest(value)).
            let value_digest = compute_value_digest(&value_js);
            let leaf_binds = proof.witness.iter().any(|c| {
                matches!(
                    c,
                    MptCommitment::Leaf { data_digest, .. } if *data_digest == value_digest
                )
            });
            if !leaf_binds {
                return Ok(Value::Bool(false));
            }
            Ok(Value::Bool(mpt_confirm(&root, &proof)))
        }
        _ => Err(format!(
            "mpt_verify: expected [rootHex, keyHex, valueJson, proofJson], got {values:?}"
        )),
    }
}

// ===========================================================================
// MPT batch / prefix verifier (port of api/MerklePatriciaBatchInclusionVerifier).
// ===========================================================================

/// A decoded `MerklePatriciaBatchInclusionProof` (`{paths, witness}`).
struct MptBatchProof {
    paths: Vec<String>,
    witness: Vec<MptCommitment>,
}

fn decode_mpt_batch_proof(j: &serde_json::Value, role: &str) -> Result<MptBatchProof, String> {
    let obj = j
        .as_object()
        .ok_or_else(|| format!("{role}: undecodable proof JSON (not an object)"))?;
    let paths_arr = obj
        .get("paths")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (paths not an array)"))?;
    let paths = paths_arr
        .iter()
        .map(|p| {
            p.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("{role}: undecodable proof JSON (bad path)"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let witness_arr = obj
        .get("witness")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{role}: undecodable proof JSON (witness not an array)"))?;
    let witness = witness_arr
        .iter()
        .map(|c| decode_mpt_commitment(c, role))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MptBatchProof { paths, witness })
}

/// Reconstruct the per-path witness from the shared, de-duplicated batch witness
/// by walking from the root: at each step, find the commitment whose prefixed
/// digest matches the expected child digest and whose path is consistent with the
/// remaining nibbles. Then hand the (leaf-first) reconstructed witness to the
/// single-path verifier. Returns `true` iff the path verifies.
fn mpt_reconstruct_and_confirm(root: &str, path: &str, shared_witness: &[MptCommitment]) -> bool {
    let mut remaining: Vec<u8> = path_nibbles(path);
    let mut expected_digest = root.to_string();
    let mut acc: Vec<MptCommitment> = Vec::new(); // built leaf-first (commitment :: acc)

    loop {
        if remaining.is_empty() {
            break; // reconstruction succeeded with whatever acc we have
        }
        // findMatchingCommitment: first commitment in the shared witness whose
        // prefixed digest matches `expected_digest` and whose path is consistent.
        let mut matched: Option<(MptCommitment, String, Vec<u8>, bool)> = None;
        for c in shared_witness {
            match c {
                MptCommitment::Leaf {
                    remaining: leaf_rem,
                    ..
                } => {
                    if c.digest() == expected_digest && &nibbles_to_str(&remaining) == leaf_rem {
                        matched = Some((c.clone(), expected_digest.clone(), Vec::new(), true));
                        break;
                    }
                }
                MptCommitment::Extension {
                    shared,
                    child_digest,
                } => {
                    let shared_n = path_nibbles(shared);
                    if c.digest() == expected_digest && remaining.starts_with(&shared_n) {
                        let next = remaining[shared_n.len()..].to_vec();
                        matched = Some((c.clone(), child_digest.clone(), next, false));
                        break;
                    }
                }
                MptCommitment::Branch { paths_digest } => {
                    if c.digest() == expected_digest && !remaining.is_empty() {
                        let nib = nibble_char(remaining[0]).to_string();
                        if let Some((_, child)) = paths_digest.iter().find(|(k, _)| *k == nib) {
                            let next = remaining[1..].to_vec();
                            matched = Some((c.clone(), child.clone(), next, false));
                            break;
                        }
                    }
                }
            }
        }
        match matched {
            Some((commitment, _next_digest, _next_path, true)) => {
                // A Leaf terminates reconstruction (commitment :: acc), Right.
                acc.insert(0, commitment);
                return single_confirm_reconstructed(root, path, &acc);
            }
            Some((commitment, next_digest, next_path, false)) => {
                acc.insert(0, commitment);
                expected_digest = next_digest;
                remaining = next_path;
            }
            None => return false, // InvalidWitness: no matching commitment
        }
    }
    // remainingPath emptied without hitting a Leaf: Scala returns Right(acc) and
    // hands `acc` (leaf-first) to the single verifier.
    single_confirm_reconstructed(root, path, &acc)
}

/// Hand a reconstructed (leaf-first) witness to the single-path verifier.
fn single_confirm_reconstructed(root: &str, path: &str, witness: &[MptCommitment]) -> bool {
    let proof = MptInclusionProof {
        path: path.to_string(),
        witness: witness.to_vec(),
    };
    mpt_confirm(root, &proof)
}

/// `MerklePatriciaBatchInclusionVerifier.confirm`: every path must reconstruct and
/// verify against the root. Empty paths list -> false (InvalidWitness).
fn mpt_batch_confirm(root: &str, proof: &MptBatchProof) -> bool {
    if proof.paths.is_empty() {
        return false;
    }
    proof
        .paths
        .iter()
        .all(|p| mpt_reconstruct_and_confirm(root, p, &proof.witness))
}

/// `mpt_prefix_verify([rootHex, prefixHex, entriesJson, batchProofJson]) -> bool`.
///
/// Returns `true` iff `entries` is the COMPLETE, correctly-bound set of `key->value`
/// pairs under `prefix`, all authenticated at `root`. Soundness rests on three
/// cryptographic checks (the `claimedKeys == attestedKeys` set-equality is a cheap
/// well-formedness gate, NOT the soundness boundary):
///   1. PER-KEY BINDING: the leaf reconstructed for each key's path must commit
///      `dataDigest == computeValueDigest(value)` -- binds each value to ITS key's
///      leaf (not mere set-membership of the value among all leaves).
///   2. BATCH INCLUSION: every attested path reconstructs and verifies against the
///      root.
///   3. COMPLETENESS: the subtree rooted at the prefix point is traversed over the
///      witness, and EVERY leaf reachable in it must be an attested terminal. A
///      prover that omits a key under the prefix leaves a branch child pointing at
///      a node that is not an attested leaf, which fails completeness.
pub fn mpt_prefix_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [root_v, prefix_v, entries_v, proof_v] => {
            let root_hex = expect_str("mpt_prefix_verify root", root_v)?;
            let root = parse_hash_hex(root_hex, "mpt_prefix_verify root")?;
            let prefix_hex = expect_str("mpt_prefix_verify prefix", prefix_v)?;
            let prefix = parse_nibble_hex(prefix_hex, "mpt_prefix_verify prefix")?;
            // entries: {keyHex -> valueJson}.
            let entries = expect_entries("mpt_prefix_verify entries", entries_v)?;
            let proof_json = to_json(proof_v);
            let proof = decode_mpt_batch_proof(&proof_json, "mpt_prefix_verify batchProof")?;

            let prefix_lower = prefix.to_ascii_lowercase();
            let claimed_keys: std::collections::BTreeSet<String> =
                entries.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
            let attested_keys: std::collections::BTreeSet<String> =
                proof.paths.iter().map(|p| p.to_ascii_lowercase()).collect();

            // WELL-FORMEDNESS GATE: the claimed key-set must equal the attested
            // path-set, and every attested path must lie under the prefix. This is
            // a cheap consistency check on the prover's OWN lists; soundness is
            // enforced by per-key binding + batch inclusion + the completeness
            // traversal below (which do not trust these lists).
            let key_sets_match = claimed_keys == attested_keys;
            let all_under_prefix = attested_keys.iter().all(|k| k.starts_with(&prefix_lower));
            if !key_sets_match || !all_under_prefix {
                return Ok(Value::Bool(false));
            }

            // PER-KEY VALUE-BINDING: each (key, value) must bind to the leaf the
            // KEY's path reaches (dataDigest == computeValueDigest(value)). Swapping
            // which value belongs to which key now fails.
            if !values_bind_per_key(&root, &entries, &proof.witness) {
                return Ok(Value::Bool(false));
            }

            // BATCH INCLUSION: every attested path reconstructs and verifies.
            if !mpt_batch_confirm(&root, &proof) {
                return Ok(Value::Bool(false));
            }

            // COMPLETENESS: the attested set must be ALL keys under the prefix.
            Ok(Value::Bool(prefix_subtree_complete(
                &root,
                &prefix,
                &proof,
            )))
        }
        _ => Err(format!(
            "mpt_prefix_verify: expected [rootHex, prefixHex, entriesJson, batchProofJson], got {values:?}"
        )),
    }
}

/// `expectEntries`: the entries arg must be a `{keyHex -> value}` object. Returns
/// `(keyHex, valueJson)` pairs (insertion order preserved).
fn expect_entries(role: &str, v: &Value) -> Result<Vec<(String, serde_json::Value)>, String> {
    match v {
        Value::Map(m) => Ok(m.iter().map(|(k, val)| (k.clone(), to_json(val))).collect()),
        other => Err(format!(
            "{role}: expected a {{keyHex -> value}} object, got {}",
            other.tag()
        )),
    }
}

/// PER-KEY binding (`valuesBindToWitness`): for EVERY claimed `(keyHex, value)`,
/// the leaf that the KEY's path reconstructs to must commit
/// `dataDigest == computeValueDigest(value)`. This binds each value to ITS key's
/// leaf -- swapping which value belongs to which key fails, unlike a set-membership
/// test over all leaf digests. A key whose path does not reconstruct to a leaf
/// (under the trusted root) fails.
fn values_bind_per_key(
    root: &str,
    entries: &[(String, serde_json::Value)],
    witness: &[MptCommitment],
) -> bool {
    entries.iter().all(|(key_hex, value_js)| {
        let expected = compute_value_digest(value_js).to_ascii_lowercase();
        match reconstruct_terminal_leaf(root, key_hex, witness) {
            Some(ReconstructedLeaf { data_digest, .. }) => {
                data_digest.to_ascii_lowercase() == expected
            }
            None => false,
        }
    })
}

/// The terminal leaf a path reconstructs to: its prefixed commitment `node_digest`
/// (how the subtree traversal identifies attested leaves) and its `data_digest`
/// (what the per-key value-binding compares against).
struct ReconstructedLeaf {
    node_digest: String,
    data_digest: String,
}

/// Reconstruct `path` from the shared batch witness (the same root-down walk as
/// `mpt_reconstruct_and_confirm`) and return the terminal Leaf it reaches, or
/// `None` if it does not reconstruct to a leaf. The full `mpt_batch_confirm`
/// separately re-checks that the same reconstruction folds to the root.
fn reconstruct_terminal_leaf(
    root: &str,
    path: &str,
    shared_witness: &[MptCommitment],
) -> Option<ReconstructedLeaf> {
    let mut remaining: Vec<u8> = path_nibbles(path);
    let mut expected_digest = root.to_string();

    loop {
        if remaining.is_empty() {
            // Path exhausted without reaching a Leaf: no terminal leaf.
            return None;
        }
        let mut step: Option<(String, Vec<u8>)> = None; // (next_digest, next_path)
        for c in shared_witness {
            match c {
                MptCommitment::Leaf {
                    remaining: leaf_rem,
                    data_digest,
                } => {
                    if c.digest() == expected_digest && &nibbles_to_str(&remaining) == leaf_rem {
                        return Some(ReconstructedLeaf {
                            node_digest: expected_digest,
                            data_digest: data_digest.clone(),
                        });
                    }
                }
                MptCommitment::Extension {
                    shared,
                    child_digest,
                } => {
                    let shared_n = path_nibbles(shared);
                    if c.digest() == expected_digest && remaining.starts_with(&shared_n) {
                        step = Some((child_digest.clone(), remaining[shared_n.len()..].to_vec()));
                        break;
                    }
                }
                MptCommitment::Branch { paths_digest } => {
                    if c.digest() == expected_digest && !remaining.is_empty() {
                        let nib = nibble_char(remaining[0]).to_string();
                        if let Some((_, child)) = paths_digest.iter().find(|(k, _)| *k == nib) {
                            step = Some((child.clone(), remaining[1..].to_vec()));
                            break;
                        }
                    }
                }
            }
        }
        match step {
            Some((next_digest, next_path)) => {
                expected_digest = next_digest;
                remaining = next_path;
            }
            None => return None, // no matching commitment for this path
        }
    }
}

// ---------------------------------------------------------------------------
// COMPLETENESS: the attested set must be ALL keys under the prefix.
// ---------------------------------------------------------------------------

/// Find the first witness commitment whose prefixed digest equals `digest`
/// (first-match wins, mirroring `findMatchingCommitment`'s `collectFirst`).
fn commitment_by_digest<'a>(
    witness: &'a [MptCommitment],
    digest: &str,
) -> Option<&'a MptCommitment> {
    witness.iter().find(|c| c.digest() == digest)
}

/// COMPLETENESS check. After per-key binding and batch inclusion have passed (so
/// every attested path reconstructs to a leaf that folds to the root), require that
/// the attested leaves are ALL the leaves under the prefix:
///
///   1. Walk root -> prefix, consuming the prefix nibbles through branches /
///      extensions / a leaf, to find the subtree-root digest at (or just under)
///      the prefix point. If the prefix selects an absent branch child, diverges
///      from an extension, or its node is missing from the witness, there is NO
///      subtree under the prefix -> the only complete attestation is the empty set.
///   2. Traverse the subtree at that digest over the witness: every Branch requires
///      ALL of its `pathsDigest` children to be present-and-complete; an Extension
///      requires its single child; a Leaf must be an ATTESTED terminal (its digest
///      is among the leaves the attested paths reconstruct to). Any branch child
///      that points at a node absent from the witness, or at a leaf that no
///      attested path reaches, is an UNATTESTED key under the prefix -> INCOMPLETE.
///
/// Full-child coverage is enforced only AT OR BELOW the prefix point: nodes above
/// the prefix legitimately have siblings outside the prefix, which we never visit.
fn prefix_subtree_complete(root: &str, prefix: &str, proof: &MptBatchProof) -> bool {
    let witness = &proof.witness;

    // The set of leaf-commitment digests the attested paths actually terminate at.
    // A leaf is "attested" iff some path reconstructs down to it.
    let mut attested_leaf_digests: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for path in &proof.paths {
        match reconstruct_terminal_leaf(root, path, witness) {
            Some(ReconstructedLeaf { node_digest, .. }) => {
                attested_leaf_digests.insert(node_digest);
            }
            // A path that does not reconstruct to a leaf was already rejected by
            // batch inclusion; defensively, an incomplete attested set is unsound.
            None => return false,
        }
    }

    // 1. Walk root -> prefix point.
    let mut remaining: Vec<u8> = path_nibbles(prefix);
    let mut cur = root.to_string();
    loop {
        if remaining.is_empty() {
            break; // `cur` is the subtree-root digest at the prefix point.
        }
        let Some(c) = commitment_by_digest(witness, &cur) else {
            // The node on the prefix path is not in the witness: the prefix is not
            // covered by any attested path. The only complete attestation under a
            // prefix with no reachable node is the empty set.
            return proof.paths.is_empty();
        };
        match c {
            MptCommitment::Branch { paths_digest } => {
                let nib = nibble_char(remaining[0]).to_string();
                match paths_digest.iter().find(|(k, _)| *k == nib) {
                    // Descend toward the prefix; the chosen child is the next node.
                    Some((_, child)) => {
                        cur = child.clone();
                        remaining = remaining[1..].to_vec();
                    }
                    // Prefix selects a branch child that does not exist: no keys
                    // under the prefix -> only the empty set is complete.
                    None => return proof.paths.is_empty(),
                }
            }
            MptCommitment::Extension {
                shared,
                child_digest,
            } => {
                let shared_n = path_nibbles(shared);
                if remaining.starts_with(&shared_n) {
                    // Prefix consumes the whole shared segment; continue at child.
                    cur = child_digest.clone();
                    remaining = remaining[shared_n.len()..].to_vec();
                } else if shared_n.starts_with(&remaining) {
                    // Prefix ends MID-extension: the entire subtree below this
                    // extension's child lies under the prefix.
                    cur = child_digest.clone();
                    remaining = Vec::new();
                } else {
                    // Prefix diverges from the extension: no keys under prefix.
                    return proof.paths.is_empty();
                }
            }
            MptCommitment::Leaf {
                remaining: lrem, ..
            } => {
                // Prefix descends into a single leaf (single-leaf subtree). It is
                // under the prefix iff the leaf's remaining nibbles extend it.
                let lrem_n = path_nibbles(lrem);
                if lrem_n.starts_with(&remaining) {
                    // The leaf IS the whole subtree; `cur` already names it.
                    remaining = Vec::new();
                } else {
                    return proof.paths.is_empty();
                }
            }
        }
    }

    // 2. Traverse the subtree at `cur`, requiring every reachable leaf is attested.
    subtree_all_leaves_attested(witness, &cur, &attested_leaf_digests)
}

/// Recursively require that every leaf reachable in the subtree rooted at `digest`
/// is an attested terminal. At a Branch, EVERY `pathsDigest` child must itself be
/// complete (full-child coverage, since we are at/below the prefix). A node digest
/// absent from the witness, or a leaf not in `attested`, means an unattested key
/// exists under the prefix -> INCOMPLETE.
fn subtree_all_leaves_attested(
    witness: &[MptCommitment],
    digest: &str,
    attested: &std::collections::BTreeSet<String>,
) -> bool {
    let Some(c) = commitment_by_digest(witness, digest) else {
        // A child the subtree commits to is not present in the witness: its leaves
        // were not attested.
        return false;
    };
    match c {
        MptCommitment::Leaf { .. } => attested.contains(digest),
        MptCommitment::Extension { child_digest, .. } => {
            subtree_all_leaves_attested(witness, child_digest, attested)
        }
        MptCommitment::Branch { paths_digest } => paths_digest
            .iter()
            .all(|(_, child)| subtree_all_leaves_attested(witness, child, attested)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_from_bytes_matches_sha256() {
        // sha256("\"alice\"") = 0a50500b... (the SMT keyA value digest).
        assert_eq!(
            hash_from_bytes(b"\"alice\""),
            "0a50500b2a3435fe7472877eb22d48d47a228e946b0b991ab7402a8d00f6b32d"
        );
    }

    #[test]
    fn mpt_leaf_commitment_canon_sorts_keys() {
        // The leaf pre-image is {"dataDigest":...,"remaining":...} (sorted keys),
        // giving the branch child digest 3508013a... for v-a1.
        let leaf = MptCommitment::Leaf {
            remaining: "".to_string(),
            data_digest: "a7798cfe9d08badb8cbbfbfff9693faaf20e3d5069f9c55e8024020305b440d2"
                .to_string(),
        };
        assert_eq!(
            leaf.digest(),
            "3508013ae82e8173afa9cf7d3b83ae059f16a303ccee6d07e7fa767158d9b101"
        );
    }

    #[test]
    fn smt_leaf_uses_position_valuedigest_order() {
        let pos = smt_position("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let leaf = smt_leaf_digest(
            &pos,
            "0a50500b2a3435fe7472877eb22d48d47a228e946b0b991ab7402a8d00f6b32d",
        );
        // This leaf folds (with the vector siblings) to root 9b8baa67...
        assert_eq!(
            leaf,
            "a7182b0dde636567d9410b9120090c85ae24104ea1f71824758f51cf4d675ced"
        );
    }
}
