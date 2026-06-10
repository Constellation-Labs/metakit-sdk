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
use ark_bn254::{Fq, Fq2, Fr as ArkFr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One as ArkOne, PrimeField, Zero as ArkZero};
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

// ===========================================================================
// TIER-2b: BN254 (alt_bn128) curve ops -- ecAdd / ecMul / ecPairing.
//   Byte-for-byte port of the Scala CryptoOps.bn254Add / bn254Mul /
//   bn254Pairing (over Bn254.scala). EIP-196 / EIP-197 encoding:
//     G1 = 64B  (x || y, big-endian Fq; infinity = all-zero)
//     G2 = 128B (Fp2 imaginary-first: x.c1 || x.c0 || y.c1 || y.c0)
//   off-curve / wrong-width -> Err (a Scala JsonLogicException). For the pairing
//   G2 inputs we ALSO require order-r subgroup membership (G2 has a non-trivial
//   cofactor); an on-curve-but-non-subgroup G2 point is rejected as malformed,
//   identical to off-curve. G1 is prime-order (cofactor 1), so on-curve already
//   implies subgroup membership and no extra check is needed there.
// ===========================================================================

// ---------------------------------------------------------------------------
// bn254_add: [aHex(64B), bHex(64B)] -> 64B G1 (EIP-196 ecAdd).
// ---------------------------------------------------------------------------

/// `bn254_add([aHex(64B), bHex(64B)]) -> 64B G1`.
pub fn bn254_add(values: &[Value]) -> Result<Value, String> {
    match values {
        [a_v, b_v] => {
            let a_hex = expect_str("bn254_add a", a_v)?;
            let b_hex = expect_str("bn254_add b", b_v)?;
            let a_c = hb::parse_g1(a_hex, "bn254_add a")?;
            let b_c = hb::parse_g1(b_hex, "bn254_add b")?;
            let a = g1_on_curve(&a_c, "bn254_add a")?;
            let b = g1_on_curve(&b_c, "bn254_add b")?;
            let sum = (a + b).into_affine();
            encode_g1_point(&sum).map(Value::Str)
        }
        _ => Err(format!(
            "bn254_add: expected [aHex(64B), bHex(64B)], got {values:?}"
        )),
    }
}

// ---------------------------------------------------------------------------
// bn254_mul: [pHex(64B), sHex(32B)] -> 64B G1 (EIP-196 ecMul).
//   The scalar is any 256-bit value; multiplication reduces it mod R.
// ---------------------------------------------------------------------------

/// `bn254_mul([pointHex(64B), scalarHex(32B)]) -> 64B G1`.
pub fn bn254_mul(values: &[Value]) -> Result<Value, String> {
    match values {
        [p_v, s_v] => {
            let p_hex = expect_str("bn254_mul point", p_v)?;
            let s_hex = expect_str("bn254_mul scalar", s_v)?;
            let p_c = hb::parse_g1(p_hex, "bn254_mul point")?;
            // Scalar is any 256-bit value; mul reduces it mod R.
            let s = hb::parse_scalar(s_hex, "bn254_mul scalar")?;
            let p = g1_on_curve(&p_c, "bn254_mul point")?;
            let prod = p.mul_biguint(&s);
            encode_g1_point(&prod).map(Value::Str)
        }
        _ => Err(format!(
            "bn254_mul: expected [pointHex(64B), scalarHex(32B)], got {values:?}"
        )),
    }
}

// ---------------------------------------------------------------------------
// bn254_pairing: [[g1Hex(64B), g2Hex(128B)], ...] -> bool (EIP-197).
//   true iff product of e(g1_i, g2_i) == 1; empty input -> true.
// ---------------------------------------------------------------------------

/// `bn254_pairing([[g1Hex(64B), g2Hex(128B)], ...]) -> bool`.
///
/// Accepts the natural EIP-197 shape (a single array of `[g1, g2]` pairs) as
/// well as variadic pairs, matching the Scala disambiguation: unwrap the outer
/// array only when every element is itself an array (a pair).
pub fn bn254_pairing(values: &[Value]) -> Result<Value, String> {
    let raw_pairs: &[Value] = match values {
        [Value::Array(arr)] if arr.iter().all(|v| matches!(v, Value::Array(_))) => arr.as_slice(),
        other => other,
    };

    let mut pairs: Vec<(G1Affine, G2Affine)> = Vec::with_capacity(raw_pairs.len());
    for (i, p) in raw_pairs.iter().enumerate() {
        match p {
            Value::Array(inner) => match inner.as_slice() {
                [g1_v, g2_v] => {
                    let g1_h = expect_str(&format!("bn254_pairing[{i}].g1"), g1_v)?;
                    let g2_h = expect_str(&format!("bn254_pairing[{i}].g2"), g2_v)?;
                    let g1_c = hb::parse_g1(g1_h, &format!("bn254_pairing[{i}].g1"))?;
                    let g2_c = hb::parse_g2(g2_h, &format!("bn254_pairing[{i}].g2"))?;
                    let g1 = g1_on_curve(&g1_c, &format!("bn254_pairing[{i}].g1"))?.into_affine();
                    let g2 = g2_on_curve(&g2_c, &format!("bn254_pairing[{i}].g2"))?;
                    pairs.push((g1, g2));
                }
                _ => {
                    return Err(format!(
                        "bn254_pairing[{i}]: expected [g1Hex(64B), g2Hex(128B)], got {p:?}"
                    ))
                }
            },
            other => {
                return Err(format!(
                    "bn254_pairing[{i}]: expected [g1Hex(64B), g2Hex(128B)], got {other:?}"
                ))
            }
        }
    }

    Ok(Value::Bool(pairing_product_is_one(&pairs)))
}

/// Build an on-curve BN254 G2 affine point from the parsed
/// `(xReal, xImag, yReal, yImag)` Fp2 limbs; reject off-curve points. Mirrors
/// the Scala `g2OnCurve` over `Bn254.G2`. Each Fp2 coordinate is
/// `Fq2::new(c0 = real, c1 = imag)`.
fn g2_on_curve(
    coords: &(BigUint, BigUint, BigUint, BigUint),
    role: &str,
) -> Result<G2Affine, String> {
    let (x_real, x_imag, y_real, y_imag) = coords;
    let x = Fq2::new(Fq::from(x_real.clone()), Fq::from(x_imag.clone()));
    let y = Fq2::new(Fq::from(y_real.clone()), Fq::from(y_imag.clone()));
    let p = G2Affine::new_unchecked(x, y);
    // Two-step validation, mirroring the Scala `g2OnCurve` over `Bn254.G2`:
    //   1. curve membership (`is_on_curve` == Besu `AltBn128Fq2Point.isOnCurve`);
    //   2. order-r subgroup membership. BN254 G2 has a non-trivial cofactor, so an
    //      on-curve point may live OUTSIDE the order-r subgroup. Feeding such a
    //      point to the pairing breaks the soundness assumptions of the Groth16
    //      check (it is not a valid GT input), so we reject it as malformed —
    //      identical handling to the off-curve case (an `Err` / Scala
    //      `JsonLogicException`). This is `Bn254.G2.isInGroup` on the Scala side
    //      (Besu `AltBn128Fq2Point.isInGroup`, i.e. `[r]P == O`).
    if !p.is_on_curve() {
        return Err(format!("{role}: point is not on the BN254 G2 curve"));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!(
            "{role}: point is not in the BN254 G2 order-r subgroup"
        ));
    }
    Ok(p)
}

/// Multi-pairing product check: `true` iff `∏ e(g1_i, g2_i) == 1` in GT.
/// Mirrors `Bn254.pairingProductIsOne` (EVM ECPAIRING semantics). The empty
/// product is the GT identity, so an empty input yields `true`.
fn pairing_product_is_one(pairs: &[(G1Affine, G2Affine)]) -> bool {
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    // `multi_pairing` accumulates the Miller loop and finalizes once, exactly
    // like the Scala (product of Miller-loop outputs then a single final exp).
    let g1s: Vec<G1Affine> = pairs.iter().map(|(g1, _)| *g1).collect();
    let g2s: Vec<G2Affine> = pairs.iter().map(|(_, g2)| *g2).collect();
    let result = Bn254::multi_pairing(g1s, g2s);
    result.0.is_one()
}

/// Encode a BN254 G1 affine point as a 64-byte `0x`-hex string (`x || y`),
/// rendering the point-at-infinity as the all-zero point (Besu / EVM
/// convention). Mirrors `CryptoOps.encodeG1` over `HexBytes.encodeG1`.
fn encode_g1_point(p: &G1Affine) -> Result<String, String> {
    let (x, y) = affine_xy(p);
    hb::encode_g1(&x, &y)
}

// ---------------------------------------------------------------------------
// ecvrf_verify: [pkHex(32B), alphaHex, proofHex(80B)]
//                 -> {"valid": bool, "beta": hexOrNull}.
//   ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 suite 0x03). Byte-for-byte port of
//   the Scala CryptoOps.ecVrfVerify over MiraclEcVrf25519.
// ---------------------------------------------------------------------------

/// `ecvrf_verify([pkHex(32B), alphaHex, proofHex(80B)]) -> {valid, beta}`.
///
/// `pk` is a 32-byte point; `proof` is 80 bytes; `alpha` is arbitrary-length
/// message bytes. Wrong width (pk != 32B, proof != 80B) is an `Err` (a Scala
/// `JsonLogicException`); a well-formed-but-wrong proof yields
/// `{valid: false, beta: null}`.
pub fn ecvrf_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [pk_v, alpha_v, proof_v] => {
            let pk_hex = expect_str("ecvrf_verify pk", pk_v)?;
            let alpha_hex = expect_str("ecvrf_verify alpha", alpha_v)?;
            let proof_hex = expect_str("ecvrf_verify proof", proof_v)?;
            let pk = hb::parse_bytes(pk_hex, Some(crate::ecvrf::POINT_BYTES), "ecvrf_verify pk")?;
            let alpha = hb::parse_bytes(alpha_hex, None, "ecvrf_verify alpha")?;
            let proof = hb::parse_bytes(
                proof_hex,
                Some(crate::ecvrf::PROOF_BYTES),
                "ecvrf_verify proof",
            )?;

            let valid = crate::ecvrf::vrf_verify(&pk, &alpha, &proof);
            let beta = if valid {
                match crate::ecvrf::vrf_proof_to_hash(&proof) {
                    Some(b) => Value::Str(hb::encode_bytes(&b)),
                    // A valid proof should always yield beta; defensive null.
                    None => Value::Null,
                }
            } else {
                Value::Null
            };
            // Mirror the Scala `MapValue(Map("valid" -> ..., "beta" -> ...))`;
            // the canonical serializer sorts keys, so member order is immaterial.
            Ok(Value::Map(vec![
                ("valid".to_string(), Value::Bool(valid)),
                ("beta".to_string(), beta),
            ]))
        }
        _ => Err(format!(
            "ecvrf_verify: expected [pkHex(32B), alphaHex, proofHex(80B)], got {values:?}"
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
