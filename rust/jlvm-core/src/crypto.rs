//! Pure, deterministic implementations of the Tier-1 ZK / crypto opcodes.
//!
//! Byte-for-byte port of the Scala
//! `io.constellationnetwork.metagraph_sdk.json_logic.ops.CryptoOps` (the subset
//! marked Tier 1: `poseidon`, `pmt_verify`, `schnorr_verify`).
//!
//! Like the Scala reference, every function returns `Result<Value, String>` and
//! NEVER panics to the caller: malformed inputs (bad hex, wrong width,
//! non-canonical field element, wrong arg count or type) all map to an `Err`.
//! Encoding is handled by [`crate::hex_bytes`]; the underlying primitives
//! (Poseidon, the Poseidon Merkle tree, BN254 G1) are consumed as-is.

use crate::hex_bytes as hb;
use crate::value::Value;
use ark_bn254::{Fq, Fr as ArkFr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero as ArkZero};
use num_bigint::BigUint;
use poseidon_bn254::merkle::{verify_inclusion, PoseidonMerkleProof};
use sha2::{Digest, Sha256};

/// Largest input count supported. The bundled circomlib constants cover widths
/// `t = #inputs + 1` in `2..=5` (see `poseidon-bn254` `constants::MAX_WIDTH = 5`),
/// so the real limit is `MAX_WIDTH - 1 = 4` inputs. This matches the Scala
/// reference: `Poseidon.hash` requires `t <= MaxWidth=5`, i.e. at most 4 inputs;
/// a 5-input call errors in BOTH impls.
const POSEIDON_MAX_INPUTS: usize = poseidon_bn254::MAX_INPUTS; // 4

// ---------------------------------------------------------------------------
// poseidon: variadic field elements -> Fr hash (32B hex).
// ---------------------------------------------------------------------------

/// `poseidon([hexFr, ...]) -> hexFr`.
///
/// Accepts either variadic hex args or a single array of hex args (matching the
/// Scala overload). At least one and at most [`POSEIDON_MAX_INPUTS`] inputs.
pub fn poseidon(values: &[Value]) -> Result<Value, String> {
    let hexes: Vec<&str> = match values {
        [] => return Err("poseidon: requires at least one field element".into()),
        // Single array of hex args.
        [Value::Array(arr)] if !arr.is_empty() => arr
            .iter()
            .map(|v| expect_str("poseidon input", v))
            .collect::<Result<_, _>>()?,
        _ => values
            .iter()
            .map(|v| expect_str("poseidon input", v))
            .collect::<Result<_, _>>()?,
    };

    if hexes.is_empty() {
        return Err("poseidon: requires at least one field element".into());
    }
    if hexes.len() > POSEIDON_MAX_INPUTS {
        return Err(format!(
            "poseidon: supports at most {POSEIDON_MAX_INPUTS} inputs, got {}",
            hexes.len()
        ));
    }
    let inputs: Vec<BigUint> = hexes
        .iter()
        .enumerate()
        .map(|(i, h)| hb::parse_fr(h, &format!("poseidon input[{i}]")))
        .collect::<Result<_, _>>()?;
    let digest = poseidon_bn254::hash(&inputs);
    let out = hb::encode_fr(&digest)?;
    Ok(Value::Str(out))
}

// ---------------------------------------------------------------------------
// pmt_verify: [root, leaf, index, [siblings...]] -> bool.
// ---------------------------------------------------------------------------

/// `pmt_verify([rootHex, leafHex, index, [siblingsHex]]) -> bool`.
///
/// Any malformed component (bad hex / non-canonical / negative or out-of-range
/// index) is an `Err`; a well-formed-but-wrong proof simply verifies to `false`.
pub fn pmt_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [root_v, leaf_v, index_v, Value::Array(siblings_v)] => {
            let root_hex = expect_str("pmt_verify root", root_v)?;
            let leaf_hex = expect_str("pmt_verify leaf", leaf_v)?;
            let root = hb::parse_fr(root_hex, "pmt_verify root")?;
            let leaf = hb::parse_fr(leaf_hex, "pmt_verify leaf")?;
            let index = expect_index("pmt_verify index", index_v)?;
            let siblings: Vec<BigUint> = siblings_v
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let h = expect_str(&format!("pmt_verify sibling[{i}]"), s)?;
                    hb::parse_fr(h, &format!("pmt_verify sibling[{i}]"))
                })
                .collect::<Result<_, _>>()?;
            let depth = siblings.len();
            // index < 2^depth
            if index >= (BigUint::from(1u32) << depth) {
                return Err(format!(
                    "pmt_verify: index {index} out of range for depth {depth}"
                ));
            }
            let proof = PoseidonMerkleProof {
                position: index,
                siblings,
            };
            Ok(Value::Bool(verify_inclusion(&leaf, &proof, &root)))
        }
        _ => Err(format!(
            "pmt_verify: expected [rootHex, leafHex, index, [siblingHex...]], got {values:?}"
        )),
    }
}

// ---------------------------------------------------------------------------
// schnorr_verify: [pkHex(64B G1), msgHex, proofHex(96B)] -> bool.
//   Schnorr proof of knowledge / signature on BN254 G1. Convention:
//     proof    = R(64B) || s(32B)
//     generator G = (1, 2) (the alt_bn128 G1 base point)
//     challenge c = SHA256(R || pk || msg) mod r   (r = BN254 group order)
//     accept iff  s*G == R + c*pk
// ---------------------------------------------------------------------------

/// `schnorr_verify([pkHex(64B), msgHex, proofHex(96B)]) -> bool`.
pub fn schnorr_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [pk_v, msg_v, proof_v] => {
            let pk_hex = expect_str("schnorr_verify pk", pk_v)?;
            let msg_hex = expect_str("schnorr_verify msg", msg_v)?;
            let proof_hex = expect_str("schnorr_verify proof", proof_v)?;

            let pk_coords = hb::parse_g1(pk_hex, "schnorr_verify pk")?;
            let msg = hb::parse_bytes(msg_hex, None, "schnorr_verify msg")?;
            // proof = R(64B) || s(32B) -> total 96 bytes.
            let proof = hb::parse_bytes(
                proof_hex,
                Some(hb::G1_BYTES + hb::SCALAR_BYTES),
                "schnorr_verify proof",
            )?;
            let r_bytes = &proof[0..hb::G1_BYTES];
            let s_bytes = &proof[hb::G1_BYTES..hb::G1_BYTES + hb::SCALAR_BYTES];

            let r_coords = hb::parse_g1(&hb::encode_bytes(r_bytes), "schnorr_verify R")?;
            let s = BigUint::from_bytes_be(s_bytes);

            // On-curve checks (the all-zero point (0,0) is the on-curve infinity).
            let pk = g1_on_curve(&pk_coords, "schnorr_verify pk")?;
            let r = g1_on_curve(&r_coords, "schnorr_verify R")?;

            // SOUNDNESS: reject the identity / point-at-infinity public key.
            // BN254 G1 is prime-order (cofactor 1), so on-curve ⇒ in-subgroup
            // EXCEPT for the identity O = (0,0). With pk = O the verification
            // equation `s*G == R + c*pk` collapses to `s*G == R`, which an
            // attacker satisfies for ANY message by choosing s and setting
            // R = s*G — a universal forgery. The identity pk is correct-WIDTH
            // but cryptographically invalid, so this is `false`, NOT an Err
            // (malformed-width inputs still error above, as before).
            if pk.is_zero() {
                return Ok(Value::Bool(false));
            }

            // c = SHA256(R || pk || msg) mod groupOrder
            let pk_bytes = hb::parse_bytes(pk_hex, Some(hb::G1_BYTES), "schnorr_verify pk")?;
            let mut hasher = Sha256::new();
            hasher.update(r_bytes);
            hasher.update(&pk_bytes);
            hasher.update(&msg);
            let digest = hasher.finalize();
            let group_order = hb::modulus();
            let c = BigUint::from_bytes_be(&digest) % group_order;

            // accept iff s*G == R + c*pk
            let s_mod = &s % group_order;
            let lhs = generator().mul_biguint(&s_mod); // s*G
            let rhs = (r + pk.mul_biguint(&c)).into_affine(); // R + c*pk
            Ok(Value::Bool(affine_eq(&lhs, &rhs)))
        }
        _ => Err(format!(
            "schnorr_verify: expected [pkHex(64B), msgHex, proofHex(96B)], got {values:?}"
        )),
    }
}

// ---------------------------------------------------------------------------
// BN254 G1 helpers (matching Besu AltBn128Point / Scala Bn254.G1 semantics).
// ---------------------------------------------------------------------------

/// The BN254 G1 generator (1, 2), matching Besu's `AltBn128Point.g1()` and the
/// Scala `SchnorrGenerator`.
fn generator() -> G1Projective {
    let g = G1Affine::new_unchecked(Fq::from(1u64), Fq::from(2u64));
    debug_assert!(g.is_on_curve());
    g.into_group()
}

/// Build an on-curve G1 point from parsed `(x, y)` coordinates; reject off-curve
/// points. The all-zero point `(0, 0)` is the EVM / Besu point-at-infinity and
/// is treated as on-curve (mapped to the ark identity).
fn g1_on_curve(coords: &(BigUint, BigUint), role: &str) -> Result<G1Projective, String> {
    let (x, y) = coords;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Projective::zero());
    }
    let xf = Fq::from(x.clone());
    let yf = Fq::from(y.clone());
    let p = G1Affine::new_unchecked(xf, yf);
    // Scala's `Bn254.G1.isOnCurve` (Besu) only checks curve membership. BN254 G1
    // has cofactor 1 (prime-order), so on-curve implies in the correct subgroup.
    if p.is_on_curve() {
        Ok(p.into_group())
    } else {
        Err(format!("{role}: point is not on the BN254 curve"))
    }
}

/// `point.multiply(scalar)` with the scalar reduced mod R (matching
/// `Bn254.G1.multiply`, which does `scalar.mod(R)`).
trait MulBigUint {
    fn mul_biguint(&self, scalar: &BigUint) -> G1Affine;
}

impl MulBigUint for G1Projective {
    fn mul_biguint(&self, scalar: &BigUint) -> G1Affine {
        let s = ArkFr::from(scalar.clone()); // ark reduces mod R automatically
        (*self * s).into_affine()
    }
}

/// Affine equality on the Besu `(x, y)`-with-(0,0)-infinity convention: two
/// points are equal iff their canonical affine coordinates (with infinity mapped
/// to `(0, 0)`) match. This mirrors the Scala `lhs.x == rhs.x && lhs.y == rhs.y`.
fn affine_eq(a: &G1Affine, b: &G1Affine) -> bool {
    affine_xy(a) == affine_xy(b)
}

/// Canonical `(x, y)` with the point-at-infinity rendered as `(0, 0)` (Besu /
/// EVM convention), as big-endian `BigUint`s.
fn affine_xy(p: &G1Affine) -> (BigUint, BigUint) {
    match p.xy() {
        Some((x, y)) => (
            BigUint::from_bytes_be(&x.into_bigint().to_bytes_be()),
            BigUint::from_bytes_be(&y.into_bigint().to_bytes_be()),
        ),
        None => (BigUint::zero(), BigUint::zero()),
    }
}

// ---------------------------------------------------------------------------
// Shared argument helpers (mirroring CryptoOps.expectStr / expectIndex).
// ---------------------------------------------------------------------------

fn expect_str<'a>(role: &str, v: &'a Value) -> Result<&'a str, String> {
    match v {
        Value::Str(s) => Ok(s.as_str()),
        other => Err(format!(
            "{role}: expected a hex string, got {}",
            other.tag()
        )),
    }
}

fn expect_index(role: &str, v: &Value) -> Result<BigUint, String> {
    match v {
        Value::Int(i) => {
            use num_traits::Signed;
            if i.is_negative() {
                Err(format!("{role}: must be non-negative, got {i}"))
            } else {
                Ok(i.magnitude().clone())
            }
        }
        other => Err(format!(
            "{role}: expected a non-negative integer, got {}",
            other.tag()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_hard_acceptance() {
        let v = poseidon(&[
            Value::Str("0x0000000000000000000000000000000000000000000000000000000000000001".into()),
            Value::Str("0x0000000000000000000000000000000000000000000000000000000000000002".into()),
        ])
        .unwrap();
        match v {
            Value::Str(s) => assert_eq!(
                s,
                "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
            ),
            _ => panic!("expected str"),
        }
    }

    #[test]
    fn generator_is_on_curve() {
        let g = generator().into_affine();
        let (x, y) = affine_xy(&g);
        assert_eq!(x, BigUint::from(1u32));
        assert_eq!(y, BigUint::from(2u32));
    }
}
