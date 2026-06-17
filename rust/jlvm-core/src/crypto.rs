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
            let s = require_canonical_scalar(BigUint::from_bytes_be(s_bytes), "schnorr_verify s")?;

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

// ===========================================================================
// TIER-3a: SP1 Groth16-BN254 verifier (`groth16_verify`).
//   Byte-for-byte port of the Scala `Sp1Groth16Verifier` + `Groth16Verifier`
//   (crypto/zk), SP1 groth16 circuit v6.1.0. The opcode boundary mirrors the
//   Scala `CryptoOps.groth16Verify`:
//     groth16_verify([vkeyHex(32B), publicValuesHex, proofHex]) -> bool
//   * vkey MUST be exactly 32 bytes (wrong width -> Err, a JsonLogicException);
//   * publicValues / proof are arbitrary-width byte strings;
//   * `verify(...).isRight` -> true, any `Left(_)` -> false (a malformed but
//     well-typed proof is simply invalid, NOT an error).
// ===========================================================================

mod groth16 {
    //! Pure port of `Sp1Groth16Verifier` + `Groth16Verifier` (SP1 v6.1.0). The
    //! hardcoded gnark VK constants, the SP1 framing checks and the four-pairing
    //! Groth16 equation are reproduced verbatim from the Scala reference.

    use super::{g1_on_curve, g2_on_curve, pairing_product_is_one, MulBigUint};
    use crate::hex_bytes as hb;
    use ark_bn254::{G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use num_bigint::BigUint;
    use num_traits::Zero;
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;

    // -- SP1 framing constants (Sp1Groth16Verifier) --------------------------

    /// First 4 bytes of `VERIFIER_HASH()` from SP1VerifierGroth16.sol (v6.1.0).
    const VERIFIER_SELECTOR: [u8; 4] = [0x43, 0x88, 0xa2, 0x1c];

    /// `4 + 32 * 11` = selector + (exitCode, vkRoot, nonce, proof[8]).
    const EXPECTED_PROOF_LENGTH: usize = 4 + 32 * 11;

    /// `VK_ROOT()` from SP1VerifierGroth16.sol (v6.1.0).
    fn vk_root() -> &'static BigUint {
        static V: OnceLock<BigUint> = OnceLock::new();
        V.get_or_init(|| {
            BigUint::parse_bytes(
                b"002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352",
                16,
            )
            .expect("valid VK_ROOT")
        })
    }

    /// Mask `(1 << 253) - 1` applied to the public-values sha256 digest.
    fn digest_mask() -> &'static BigUint {
        static M: OnceLock<BigUint> = OnceLock::new();
        M.get_or_init(|| (BigUint::from(1u8) << 253usize) - BigUint::from(1u8))
    }

    /// `sha256(publicValues) & ((1 << 253) - 1)`.
    fn hash_public_values(public_values: &[u8]) -> BigUint {
        let digest = Sha256::digest(public_values);
        BigUint::from_bytes_be(&digest) & digest_mask()
    }

    fn bi(s: &str) -> BigUint {
        BigUint::parse_bytes(s.as_bytes(), 10).expect("valid decimal constant")
    }

    // -- Hardcoded Groth16 VK (Groth16Verifier, SP1 groth16 v6.1.0) ----------
    // G2 constants are already negated (BETA/GAMMA/DELTA). _0 = real, _1 = imag.

    /// Build the verification-key bundle once: alpha (G1), the negated G2 VK
    /// points (beta/gamma/delta), the constant G1 point and the 5 public-input
    /// G1 points. Off-curve here would be a programming error in the constants,
    /// so `g1_on_curve`/`g2_on_curve` are expected to succeed.
    struct Vk {
        alpha: G1Affine,
        beta_neg: G2Affine,
        gamma_neg: G2Affine,
        delta_neg: G2Affine,
        constant: G1Affine,
        pub_points: [G1Affine; 5],
    }

    fn g1(x: &str, y: &str) -> G1Affine {
        g1_on_curve(&(bi(x), bi(y)), "groth16 vk G1")
            .expect("VK G1 constant on curve")
            .into_affine()
    }

    fn g2(x0: &str, x1: &str, y0: &str, y1: &str) -> G2Affine {
        // (real, imag) == (c0, c1); g2_on_curve takes (xReal, xImag, yReal, yImag).
        g2_on_curve(&(bi(x0), bi(x1), bi(y0), bi(y1)), "groth16 vk G2")
            .expect("VK G2 constant on curve")
    }

    fn vk() -> &'static Vk {
        static VK: OnceLock<Vk> = OnceLock::new();
        VK.get_or_init(|| Vk {
            // Groth16 alpha point in G1.
            alpha: g1(
                "15279411540481963483749982645131486879260751823620651493692884460296130891713",
                "15872895802316430142046488442363778159164596024024981740547841316113839677454",
            ),
            // beta in G2 (negated), _0 = real, _1 = imag.
            beta_neg: g2(
                "6145571844528009385227270901181311049451968424667282936975270874464890915386",
                "12771786691609444002416405093387705070206640282801320788762089789398249455552",
                "4488883874756188982949192438322346627006627895205628031405236004639323835517",
                "1735169520034591855846686229876971881413094324547255227368057137445726296809",
            ),
            // gamma in G2 (negated).
            gamma_neg: g2(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
                "13392588948715843804641432497768002650278120570034223513918757245338268106653",
                "17805874995975841540914202342111839520379459829704422454583296818431106115052",
            ),
            // delta in G2 (negated).
            delta_neg: g2(
                "10465707362494635227101096813108413078937487707553051407465224907243675430929",
                "8014260607368773541998918215611927658290278403999176336697043972644519659243",
                "19389283139277148919245778864125350153699493315071306268776225113374776030523",
                "16335894885742905444968709132584769120387318573561090701871591658625758958113",
            ),
            // Constant + public-input points (G1).
            constant: g1(
                "20281192269339458123687070687118212311775320590888414619062163734024177320592",
                "4733327396113282720944079206751955104965328647794767422434462962576999295035",
            ),
            pub_points: [
                g1(
                    "6933777020392885277709527453058337947310422411038083362275568070104688005311",
                    "981134475045095331624771061624185350383934842154508663637397442918499383708",
                ),
                g1(
                    "4994703368938944727583784298191985234033403433117347198670233075674015451426",
                    "8251219283963080431419977720140972699009004688253176317231536639169726973868",
                ),
                g1(
                    "4290838847096051522936899065591427041691227664160185228987863596451823131267",
                    "20588566735491008722164159313316540988426258906449040460220495569364391658476",
                ),
                g1(
                    "10868099250506113890234768256645470833285719586092080686774540776807380789751",
                    "481415511937576118656966359026147167555048629225366340770167496559184060449",
                ),
                g1(
                    "248210862999154995000539012177951057105481472135341820587821789934938975214",
                    "4435539404843896136682123140600986858809597152596796648926707165831171499457",
                ),
            ],
        })
    }

    /// Number of public inputs this verifier expects (Groth16Verifier).
    const NUM_PUBLIC_INPUTS: usize = 5;

    /// Public-input MSM `L = CONSTANT + sum_i input_i * PUB_i`. Each scalar must
    /// already be reduced (`< R`); unreduced scalars are rejected (mirrors the
    /// Solidity `lt(s, R)` checks).
    fn public_input_msm(input: &[BigUint]) -> Result<G1Affine, String> {
        if input.len() != NUM_PUBLIC_INPUTS {
            return Err(format!(
                "expected {NUM_PUBLIC_INPUTS} public inputs, got {}",
                input.len()
            ));
        }
        let r = hb::modulus();
        if input.iter().any(|s| s >= r) {
            return Err("public input not in scalar field".to_string());
        }
        let v = vk();
        // acc starts at CONSTANT, then adds input_i * PUB_i.
        let mut acc = v.constant.into_group();
        for (i, s) in input.iter().enumerate() {
            // G1.multiply reduces the scalar mod R (here already < R).
            let term = v.pub_points[i].into_group().mul_biguint(s); // -> G1Affine
            acc += term.into_group(); // G1Projective += G1Projective
        }
        Ok(acc.into_affine())
    }

    /// Sentinel prefix marking a MALFORMED-ENCODING error (a proof coordinate
    /// `>= P`, i.e. a non-canonical field-element encoding). The opcode layer
    /// distinguishes these from cryptographic-invalidity errors: an encoding
    /// error is a hard `Err` (a `JsonLogicException` on the Scala side), while a
    /// well-formed-but-invalid point (off-curve / non-subgroup) verifies `false`.
    /// Kept in lockstep with the Scala `Groth16Verifier.EncodingErrorPrefix`.
    pub(super) const ENCODING_ERROR_PREFIX: &str = "ENCODING: ";

    /// Reject a non-canonical (`>= P`) proof coordinate. `ark`'s `Fq::from`
    /// silently reduces mod P, so we must check the raw BigUint BEFORE building
    /// the field element. A coordinate `>= P` is a malformed ENCODING and is
    /// returned with the [`ENCODING_ERROR_PREFIX`] sentinel.
    fn checked_fq(value: &BigUint, role: &str) -> Result<ark_bn254::Fq, String> {
        use ark_ff::{BigInteger, PrimeField};
        let p = {
            // BN254 base-field modulus P, as a BigUint (== ark `Fq::MODULUS`).
            static P: std::sync::OnceLock<BigUint> = std::sync::OnceLock::new();
            P.get_or_init(|| BigUint::from_bytes_be(&ark_bn254::Fq::MODULUS.to_bytes_be()))
        };
        if value >= p {
            return Err(format!(
                "{ENCODING_ERROR_PREFIX}{role}: coordinate not in base field (>= P): {value}"
            ));
        }
        Ok(ark_bn254::Fq::from(value.clone()))
    }

    /// Verify an uncompressed Groth16 proof against five public inputs. `proof`
    /// is `(A.x, A.y, B.x_imag, B.x_real, B.y_imag, B.y_real, C.x, C.y)` in
    /// EIP-197 order (the layout produced by gnark / abi-encoded SP1 proofs).
    ///
    /// VALIDATION (soundness hardening, lockstep with Scala `Groth16Verifier`):
    ///   1. CANONICAL ENCODING: every proof coordinate must be `< P`. A `>= P`
    ///      coordinate is a non-canonical encoding (`ark`'s `Fq::from` would
    ///      silently reduce it) and is an `Err` tagged with
    ///      [`ENCODING_ERROR_PREFIX`] -> a hard opcode error.
    ///   2. ON-CURVE: A, B, C must satisfy the curve equation.
    ///   3. SUBGROUP: B (G2) must lie in the order-`r` subgroup. A, C (G1) are
    ///      cofactor-1 (prime order), so on-curve implies correct subgroup; we
    ///      still reject the identity for A/B/C (a degenerate proof point).
    ///
    /// A well-formed but cryptographically invalid point (off-curve, non-subgroup
    /// or identity) is an `Err` WITHOUT the encoding prefix; the opcode maps it
    /// to `false`, exactly like a failed pairing.
    fn verify_proof(proof: &[BigUint], input: &[BigUint]) -> Result<(), String> {
        use ark_bn254::Fq2;
        if proof.len() != 8 {
            return Err(format!("expected 8 proof elements, got {}", proof.len()));
        }
        let l = public_input_msm(input)?;
        let v = vk();

        // (1) Canonical-encoding check on every coordinate (>= P -> ENCODING Err).
        let a_x = checked_fq(&proof[0], "proof A.x")?;
        let a_y = checked_fq(&proof[1], "proof A.y")?;
        let b_x_imag = checked_fq(&proof[2], "proof B.x_imag")?;
        let b_x_real = checked_fq(&proof[3], "proof B.x_real")?;
        let b_y_imag = checked_fq(&proof[4], "proof B.y_imag")?;
        let b_y_real = checked_fq(&proof[5], "proof B.y_real")?;
        let c_x = checked_fq(&proof[6], "proof C.x")?;
        let c_y = checked_fq(&proof[7], "proof C.y")?;

        // A = (proof0, proof1) in G1.
        let a = G1Affine::new_unchecked(a_x, a_y);
        // B in G2; EIP-197 order in `proof`: imag before real.
        //   xReal = proof3, xImag = proof2, yReal = proof5, yImag = proof4.
        let b = G2Affine::new_unchecked(Fq2::new(b_x_real, b_x_imag), Fq2::new(b_y_real, b_y_imag));
        // C = (proof6, proof7) in G1.
        let c = G1Affine::new_unchecked(c_x, c_y);

        // (2)+(3) On-curve, subgroup, and non-identity checks. These are
        // cryptographic-invalidity failures -> `false` at the opcode layer.
        check_g1(&a, "proof A")?;
        check_g2(&b, "proof B")?;
        check_g1(&c, "proof C")?;

        // e(A, B) * e(C, -delta) * e(alpha, -beta) * e(L, -gamma) == 1
        let ok = pairing_product_is_one(&[
            (a, b),
            (c, v.delta_neg),
            (v.alpha, v.beta_neg),
            (l, v.gamma_neg),
        ]);
        if ok {
            Ok(())
        } else {
            Err("pairing check failed".to_string())
        }
    }

    /// G1 proof-point validation: on-curve and non-identity. BN254 G1 has
    /// cofactor 1 (prime order), so on-curve already implies correct-subgroup;
    /// the identity is rejected as a degenerate proof point. Cryptographic
    /// invalidity (NOT an encoding error) -> `Err` without the encoding prefix.
    fn check_g1(p: &G1Affine, role: &str) -> Result<(), String> {
        if p.is_zero() {
            return Err(format!("{role}: point is the identity (degenerate)"));
        }
        if !p.is_on_curve() {
            return Err(format!("{role}: point is not on the BN254 G1 curve"));
        }
        Ok(())
    }

    /// G2 proof-point validation: on-curve, non-identity, AND order-`r` subgroup
    /// membership (G2 has a non-trivial cofactor, so on-curve is NOT sufficient).
    /// Cryptographic invalidity -> `Err` without the encoding prefix.
    fn check_g2(p: &G2Affine, role: &str) -> Result<(), String> {
        if p.is_zero() {
            return Err(format!("{role}: point is the identity (degenerate)"));
        }
        if !p.is_on_curve() {
            return Err(format!("{role}: point is not on the BN254 G2 curve"));
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(format!("{role}: G2 point is not in the order-r subgroup"));
        }
        Ok(())
    }

    /// Decode `count` consecutive big-endian uint256 words starting at `offset`.
    fn decode_words(bytes: &[u8], offset: usize, count: usize) -> Vec<BigUint> {
        (0..count)
            .map(|i| {
                let start = offset + i * 32;
                BigUint::from_bytes_be(&bytes[start..start + 32])
            })
            .collect()
    }

    fn selector_matches(proof_bytes: &[u8]) -> bool {
        proof_bytes.len() >= 4 && proof_bytes[0..4] == VERIFIER_SELECTOR
    }

    /// Full SP1 verify: `Right(())` on success, `Left(reason)` on any failure.
    /// `program_vkey` is the (already width-checked, 32-byte) program VK.
    pub(super) fn verify(
        program_vkey: &[u8],
        public_values: &[u8],
        proof_bytes: &[u8],
    ) -> Result<(), String> {
        // programVKey length is enforced at the opcode boundary (HexBytes wants
        // 32B), but the Scala verifier re-checks it too; mirror that exactly.
        if program_vkey.len() != 32 {
            return Err(format!(
                "programVKey must be 32 bytes, got {}",
                program_vkey.len()
            ));
        }
        if proof_bytes.len() != EXPECTED_PROOF_LENGTH {
            return Err(format!(
                "proofBytes must be {EXPECTED_PROOF_LENGTH} bytes, got {}",
                proof_bytes.len()
            ));
        }
        if !selector_matches(proof_bytes) {
            return Err("wrong verifier selector".to_string());
        }
        // abi.decode(proofBytes[4:], (uint256, uint256, uint256, uint256[8]))
        let words = decode_words(proof_bytes, 4, 11);
        let exit_code = &words[0];
        let vk_root_word = &words[1];
        let nonce = &words[2];
        let proof = &words[3..11]; // uint256[8], inline

        if !exit_code.is_zero() {
            return Err("invalid exit code".to_string());
        }
        if vk_root_word != vk_root() {
            return Err("invalid vk root".to_string());
        }
        let program_vkey_int = BigUint::from_bytes_be(program_vkey);
        let public_values_digest = hash_public_values(public_values);
        let inputs = vec![
            program_vkey_int,
            public_values_digest,
            exit_code.clone(),
            vk_root_word.clone(),
            nonce.clone(),
        ];
        verify_proof(proof, &inputs)
    }
}

// ---------------------------------------------------------------------------
// groth16_verify: [vkeyHex(32B), publicValuesHex, proofHex] -> bool.
// ---------------------------------------------------------------------------

/// `groth16_verify([vkeyHex(32B), publicValuesHex, proofHex]) -> bool`.
///
/// Byte-for-byte port of the Scala `CryptoOps.groth16Verify`:
///   * `vkey` MUST be exactly 32 bytes (wrong width -> `Err`);
///   * `publicValues` / `proof` are arbitrary-width byte strings;
///   * `Sp1Groth16Verifier.verify(...).isRight` -> `true`, any `Left(_)` ->
///     `false` (a malformed-but-well-typed proof is simply invalid, NOT an
///     error).
pub fn groth16_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [vkey_v, pub_v, proof_v] => {
            let vkey_hex = expect_str("groth16_verify vkey", vkey_v)?;
            let pub_hex = expect_str("groth16_verify publicValues", pub_v)?;
            let proof_hex = expect_str("groth16_verify proof", proof_v)?;
            let vkey = hb::parse_bytes(vkey_hex, Some(32), "groth16_verify vkey")?;
            let public_values = hb::parse_bytes(pub_hex, None, "groth16_verify publicValues")?;
            let proof = hb::parse_bytes(proof_hex, None, "groth16_verify proof")?;
            // Error-vs-false discipline (lockstep with the Scala opcode layer):
            //   * Ok(())               -> true
            //   * Err(ENCODING: ...)   -> hard opcode Err (a malformed, non-canonical
            //                             coordinate encoding is NOT a valid proof
            //                             encoding -- propagate, do NOT swallow);
            //   * any other Err(_)     -> false (a well-formed but cryptographically
            //                             invalid proof: off-curve / non-subgroup /
            //                             wrong pairing / bad framing).
            match groth16::verify(&vkey, &public_values, &proof) {
                Ok(()) => Ok(Value::Bool(true)),
                Err(e) if e.starts_with(groth16::ENCODING_ERROR_PREFIX) => {
                    Err(format!("groth16_verify: {e}"))
                }
                Err(_) => Ok(Value::Bool(false)),
            }
        }
        _ => Err(format!(
            "groth16_verify: expected [vkeyHex, publicValuesHex, proofHex], got {values:?}"
        )),
    }
}

// ===========================================================================
// TIER-3b: BLS12-381 signatures (`bls_verify` / `bls_aggregate_verify`).
//   Byte-for-byte port of the Scala `CryptoOps.blsVerify` / `blsAggregateVerify`
//   over `Bls12381` (BouncyCastle 1.85 `BLS12_381ProofOfPossession`), itself a
//   port of Constellation's canonical `BlsSigner` (tessellation-bls).
//
//   Ciphersuite (the byte-identity contract -- matches eth2 / IETF
//   draft-irtf-cfrg-bls-signature ProofOfPossession AND ethereum/bls12-381-tests
//   v0.1.2):
//     * scheme    : ProofOfPossession (PoP)
//     * variant   : minimal-pubkey-size -- pubkeys in G1, signatures in G2
//     * pubkey    : 48-byte compressed G1   (`PUBLIC_KEY_BYTES`)
//     * signature : 96-byte compressed G2   (`SIGNATURE_BYTES`)
//     * hash-to-curve: expand_message_xmd over SHA-256 with the SSWU map (RO)
//     * signature DST: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
//
//   Backed by `blst` (supranational/blst, the eth2 reference BLS library), whose
//   `min_pk` module is exactly the minimal-pubkey-size variant. This is the same
//   library and DST the published eth2 vectors were produced against, so Rust
//   matching them PROVES Scala<->Rust BLS byte-identity (the Scala side already
//   reproduces them via BouncyCastle).
//
//   Edge-case semantics mirror the Scala reference EXACTLY:
//     * wrong WIDTH pk/sig -> Err (a JsonLogicException), via `hb::parse_bytes`
//       with `Some(48)` / `Some(96)` at the opcode boundary -- NOT `false`.
//     * bad / non-canonical / wrong-subgroup point (correct width) -> `false`
//       (the Scala `Bls12381.verify` / `fastAggregateVerify` catch the
//       decompression / subgroup failure and return `false`, never throw). blst
//       returns an error from `key_validate` / `uncompress` / verify, which we
//       map to `false`.
//     * empty pubkey list (aggregate) -> Err (Scala `Either.cond(pks.nonEmpty)`).
// ===========================================================================

#[cfg(feature = "bls")]
mod bls {
    //! Thin wrapper over `blst::min_pk` fixing the eth2 PoP ciphersuite. Mirrors
    //! the public surface of the Scala `Bls12381` object used by `CryptoOps`.

    use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
    use blst::BLST_ERROR;

    /// Compressed G1 public-key size (minimal-pubkey-size variant).
    pub(super) const PUBLIC_KEY_BYTES: usize = 48;

    /// Compressed G2 signature / PoP size (minimal-pubkey-size variant).
    pub(super) const SIGNATURE_BYTES: usize = 96;

    /// Signature domain-separation tag for the ProofOfPossession ciphersuite
    /// (`BLS12_381ProofOfPossession.sign` / `verify` DST in BouncyCastle 1.85;
    /// identical to the eth2 / IETF `..._SIG_..._POP_` suite).
    pub(super) const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// Verify a single signature against a single public key + message.
    ///
    /// `pk` is a 48-byte compressed G1 point, `sig` a 96-byte compressed G2
    /// point, `message` arbitrary bytes. Returns `false` (never panics) on any
    /// malformed / non-canonical / wrong-subgroup input or failed check -- byte
    /// for byte the Scala `Bls12381.verify` contract.
    pub(super) fn verify(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        // Width is enforced at the opcode boundary; re-assert defensively (the
        // Scala primitive also re-checks `pk.length != 48 || sig.length != 96`).
        if pk.len() != PUBLIC_KEY_BYTES || sig.len() != SIGNATURE_BYTES {
            return false;
        }
        // `key_validate` = decompress + subgroup check (BC's decompressG1 enforces
        // subgroup membership); `uncompress` decompresses the G2 signature.
        let pk = match PublicKey::key_validate(pk) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let sig = match Signature::uncompress(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // sig_groupcheck = true (validate the sig subgroup), empty augmentation,
        // pk_validate = true (re-validate the pubkey subgroup, as BC does).
        sig.verify(true, message, DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
    }

    /// Verify an aggregate signature against N public keys + the single shared
    /// message (same-message `fastAggregateVerify`).
    ///
    /// `pks` are N 48-byte compressed G1 points, `agg` a 96-byte compressed G2
    /// point, `message` arbitrary bytes. Returns `false` (never panics) on an
    /// empty list, any malformed / non-canonical / non-member point, or a failed
    /// pairing check -- byte for byte the Scala `Bls12381.fastAggregateVerify`
    /// contract (which returns `false` when `pks.isEmpty`; the opcode boundary
    /// rejects the empty list earlier as an error, matching Scala's `CryptoOps`).
    pub(super) fn fast_aggregate_verify(pks: &[Vec<u8>], message: &[u8], agg: &[u8]) -> bool {
        if pks.is_empty() || agg.len() != SIGNATURE_BYTES {
            return false;
        }
        // Decompress + subgroup-check every pubkey (BC `decompressG1`).
        let mut parsed: Vec<PublicKey> = Vec::with_capacity(pks.len());
        for pk in pks {
            if pk.len() != PUBLIC_KEY_BYTES {
                return false;
            }
            match PublicKey::key_validate(pk) {
                Ok(p) => parsed.push(p),
                Err(_) => return false,
            }
        }
        let sig = match Signature::uncompress(agg) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Aggregate the (already subgroup-validated) pubkeys, then verify the
        // single signature against the shared message -- exactly the
        // BC `fastAggregateVerify` path.
        let refs: Vec<&PublicKey> = parsed.iter().collect();
        let agg_pk = match AggregatePublicKey::aggregate(&refs, false) {
            Ok(a) => a.to_public_key(),
            Err(_) => return false,
        };
        sig.verify(true, message, DST, &[], &agg_pk, false) == BLST_ERROR::BLST_SUCCESS
    }
}

// ---------------------------------------------------------------------------
// bls_verify: [pkHex(48B G1), msgHex, sigHex(96B G2)] -> bool.
//   Eth2 / IETF ProofOfPossession ciphersuite
//   (BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_).
// ---------------------------------------------------------------------------

/// `bls_verify([pkHex(48B), msgHex, sigHex(96B)]) -> bool`.
///
/// Byte-for-byte port of the Scala `CryptoOps.blsVerify`:
///   * `pk` MUST be exactly 48 bytes, `sig` exactly 96 bytes (wrong width ->
///     `Err`, a JsonLogicException);
///   * `msg` is an arbitrary-width byte string;
///   * a bad / non-canonical / wrong-subgroup point or a failed check is simply
///     `false`, NOT an error.
#[cfg(feature = "bls")]
pub fn bls_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [pk_v, msg_v, sig_v] => {
            let pk_hex = expect_str("bls_verify pk", pk_v)?;
            let msg_hex = expect_str("bls_verify msg", msg_v)?;
            let sig_hex = expect_str("bls_verify sig", sig_v)?;
            let pk = hb::parse_bytes(pk_hex, Some(bls::PUBLIC_KEY_BYTES), "bls_verify pk")?;
            let msg = hb::parse_bytes(msg_hex, None, "bls_verify msg")?;
            let sig = hb::parse_bytes(sig_hex, Some(bls::SIGNATURE_BYTES), "bls_verify sig")?;
            Ok(Value::Bool(bls::verify(&pk, &msg, &sig)))
        }
        _ => Err(format!(
            "bls_verify: expected [pkHex(48B), msgHex, sigHex(96B)], got {values:?}"
        )),
    }
}

// ---------------------------------------------------------------------------
// bls_aggregate_verify: [[pkHex(48B), ...], msgHex, aggSigHex(96B)] -> bool.
//   SAME-message N-of-N aggregation (threshold / multisig) via the Eth2
//   ProofOfPossession fastAggregateVerify.
// ---------------------------------------------------------------------------

/// `bls_aggregate_verify([[pkHex(48B), ...], msgHex, aggSigHex(96B)]) -> bool`.
///
/// Byte-for-byte port of the Scala `CryptoOps.blsAggregateVerify`:
///   * at least one pubkey is required (empty list -> `Err`);
///   * every `pk` MUST be exactly 48 bytes, `aggSig` exactly 96 bytes (wrong
///     width -> `Err`, a JsonLogicException);
///   * `msg` is an arbitrary-width byte string;
///   * any non-canonical / wrong-subgroup point or a failed pairing check is
///     simply `false`, NOT an error.
#[cfg(feature = "bls")]
pub fn bls_aggregate_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [Value::Array(pks_v), msg_v, sig_v] => {
            if pks_v.is_empty() {
                return Err("bls_aggregate_verify: at least one public key required".into());
            }
            let msg_hex = expect_str("bls_aggregate_verify msg", msg_v)?;
            let sig_hex = expect_str("bls_aggregate_verify aggSig", sig_v)?;
            let pks: Vec<Vec<u8>> = pks_v
                .iter()
                .enumerate()
                .map(|(i, pk_v)| {
                    let role = format!("bls_aggregate_verify pk[{i}]");
                    let h = expect_str(&role, pk_v)?;
                    hb::parse_bytes(h, Some(bls::PUBLIC_KEY_BYTES), &role)
                })
                .collect::<Result<_, _>>()?;
            let msg = hb::parse_bytes(msg_hex, None, "bls_aggregate_verify msg")?;
            let agg_sig =
                hb::parse_bytes(sig_hex, Some(bls::SIGNATURE_BYTES), "bls_aggregate_verify aggSig")?;
            Ok(Value::Bool(bls::fast_aggregate_verify(&pks, &msg, &agg_sig)))
        }
        _ => Err(format!(
            "bls_aggregate_verify: expected [[pkHex(48B), ...], msgHex, aggSigHex(96B)], got {values:?}"
        )),
    }
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

// ===========================================================================
// SIGMA PROTOCOLS (classical, no-trusted-setup, Ergo / EIP-11 family).
//   Byte-for-byte port of the Scala CryptoOps Sigma section:
//     - prove_dlog_verify    : first-class ALIAS for schnorr_verify (DLog leaf).
//     - prove_dhtuple_verify : the DDH / Diffie-Hellman-tuple Σ-leaf.
//     - sigma_verify         : the recursive CDS proposition verifier
//                              (AND / OR / THRESHOLD), strong Fiat-Shamir over
//                              the FROZEN serialization (docs/sigma-verify.md).
// ===========================================================================

// ---------------------------------------------------------------------------
// prove_dlog_verify: [pkHex(64B G1), msgHex, proofHex(96B)] -> bool.
//   First-class sigma-leaf ALIAS for schnorr_verify (identical inputs and
//   semantics). The only difference is the error-message role label, matching
//   the Scala `.leftMap(_.replace("schnorr_verify", "prove_dlog_verify"))`.
// ---------------------------------------------------------------------------

/// `prove_dlog_verify([pkHex(64B), msgHex, proofHex(96B)]) -> bool`.
pub fn prove_dlog_verify(values: &[Value]) -> Result<Value, String> {
    schnorr_verify(values).map_err(|e| e.replace("schnorr_verify", "prove_dlog_verify"))
}

// ---------------------------------------------------------------------------
// prove_dhtuple_verify: [gHex(64B), hHex(64B), uHex(64B), vHex(64B), msgHex, proofHex(160B)] -> bool.
//   DDH / Diffie-Hellman-tuple Σ-leaf on BN254 G1. Statement (g,h,u,v) ∈ G1⁴,
//   claim ∃w. u = g^w ∧ v = h^w. Convention:
//     proof = a1(64B) || a2(64B) || z(32B)   (total 160 bytes)
//     a1 = g^r, a2 = h^r, z = r + e·w
//     STRONG Fiat-Shamir: e = SHA256(g‖h‖u‖v‖a1‖a2‖msg) mod R
//     accept iff  z·g == a1 + e·u  AND  z·h == a2 + e·v
//
//   STRONG-FS IS THE LOAD-BEARING CORRECTNESS POINT: the challenge binds the FULL
//   statement (g,h,u,v) AND both commitments (a1,a2) AND the message. Byte-for-
//   byte port of the Scala CryptoOps.proveDhTupleVerify.
// ---------------------------------------------------------------------------

/// Total proof width: a1(64B) || a2(64B) || z(32B).
const DHTUPLE_PROOF_BYTES: usize = hb::G1_BYTES + hb::G1_BYTES + hb::SCALAR_BYTES;

/// `prove_dhtuple_verify([gHex, hHex, uHex, vHex, msgHex, proofHex(160B)]) -> bool`.
pub fn prove_dhtuple_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [g_v, h_v, u_v, v_v, msg_v, proof_v] => {
            let g_hex = expect_str("prove_dhtuple_verify g", g_v)?;
            let h_hex = expect_str("prove_dhtuple_verify h", h_v)?;
            let u_hex = expect_str("prove_dhtuple_verify u", u_v)?;
            let v_hex = expect_str("prove_dhtuple_verify v", v_v)?;
            let msg_hex = expect_str("prove_dhtuple_verify msg", msg_v)?;
            let proof_hex = expect_str("prove_dhtuple_verify proof", proof_v)?;

            let g_c = hb::parse_g1(g_hex, "prove_dhtuple_verify g")?;
            let h_c = hb::parse_g1(h_hex, "prove_dhtuple_verify h")?;
            let u_c = hb::parse_g1(u_hex, "prove_dhtuple_verify u")?;
            let v_c = hb::parse_g1(v_hex, "prove_dhtuple_verify v")?;
            let msg = parse_sigma_message(msg_hex, "prove_dhtuple_verify msg")?;
            // proof = a1(64B) || a2(64B) || z(32B) -> total 160 bytes.
            let proof = hb::parse_bytes(
                proof_hex,
                Some(DHTUPLE_PROOF_BYTES),
                "prove_dhtuple_verify proof",
            )?;
            let a1_bytes = &proof[0..hb::G1_BYTES];
            let a2_bytes = &proof[hb::G1_BYTES..hb::G1_BYTES * 2];
            let z_bytes = &proof[hb::G1_BYTES * 2..DHTUPLE_PROOF_BYTES];

            let a1_c = hb::parse_g1(&hb::encode_bytes(a1_bytes), "prove_dhtuple_verify a1")?;
            let a2_c = hb::parse_g1(&hb::encode_bytes(a2_bytes), "prove_dhtuple_verify a2")?;
            let z = require_canonical_scalar(BigUint::from_bytes_be(z_bytes), "prove_dhtuple_verify z")?;

            let g = g1_on_curve(&g_c, "prove_dhtuple_verify g")?;
            let h = g1_on_curve(&h_c, "prove_dhtuple_verify h")?;
            let u = g1_on_curve(&u_c, "prove_dhtuple_verify u")?;
            let v = g1_on_curve(&v_c, "prove_dhtuple_verify v")?;
            let a1 = g1_on_curve(&a1_c, "prove_dhtuple_verify a1")?;
            let a2 = g1_on_curve(&a2_c, "prove_dhtuple_verify a2")?;

            // SOUNDNESS: reject the identity / point-at-infinity on ANY of the four
            // statement points (g/h base => equation collapse, u/v image => degenerate
            // hiding). a1 / a2 may legitimately be the identity (r ≡ 0), so they are
            // NOT rejected -- but they are still bound into the transcript below.
            // Correct-WIDTH but cryptographically invalid -> false, NOT an Err.
            if g.is_zero() || h.is_zero() || u.is_zero() || v.is_zero() {
                return Ok(Value::Bool(false));
            }

            // STRONG Fiat-Shamir: bind the full statement AND both commitments AND
            // the message. Re-encode each statement point to its canonical fixed-width
            // 64-byte form (parse_g1 validated width) so the transcript is layout-
            // deterministic; a1/a2 are taken as their raw proof bytes (already 64B).
            let g_bytes = hb::parse_bytes(g_hex, Some(hb::G1_BYTES), "prove_dhtuple_verify g")?;
            let h_bytes = hb::parse_bytes(h_hex, Some(hb::G1_BYTES), "prove_dhtuple_verify h")?;
            let u_bytes = hb::parse_bytes(u_hex, Some(hb::G1_BYTES), "prove_dhtuple_verify u")?;
            let v_bytes = hb::parse_bytes(v_hex, Some(hb::G1_BYTES), "prove_dhtuple_verify v")?;
            let mut hasher = Sha256::new();
            hasher.update(&g_bytes);
            hasher.update(&h_bytes);
            hasher.update(&u_bytes);
            hasher.update(&v_bytes);
            hasher.update(a1_bytes);
            hasher.update(a2_bytes);
            hasher.update(&msg);
            let digest = hasher.finalize();
            let group_order = hb::modulus();
            let e = BigUint::from_bytes_be(&digest) % group_order;

            // accept iff z·g == a1 + e·u  AND  z·h == a2 + e·v
            let zr = &z % group_order;
            let lhs1 = g.mul_biguint(&zr);
            let rhs1 = (u.mul_biguint(&e) + a1).into_affine();
            let lhs2 = h.mul_biguint(&zr);
            let rhs2 = (v.mul_biguint(&e) + a2).into_affine();
            let ok = affine_eq(&lhs1, &rhs1) && affine_eq(&lhs2, &rhs2);
            Ok(Value::Bool(ok))
        }
        _ => Err(format!(
            "prove_dhtuple_verify: expected [gHex(64B), hHex(64B), uHex(64B), vHex(64B), msgHex, proofHex(160B)], got {values:?}"
        )),
    }
}

// ===========================================================================
// sigma_verify: the RECURSIVE CDS Σ-protocol proposition verifier.
//
//   {"sigma_verify": [ <proposition>, <proof>, <messageHex> ]} -> bool
//
// Byte-for-byte port of the Scala CryptoOps.sigmaVerify (Ergo "Verifier Steps
// 1-6" for BN254 G1). The FROZEN canonical serialization (docs/sigma-verify.md
// §4) MUST match the Scala byte layout exactly -- it is the strong-FS transcript.
//
//   Node tags: dlog=0x00, dhtuple=0x01, and=0x02, or=0x03, threshold=0x04.
//   k and every child-count: 4-byte big-endian.
//   Points (pk,g,h,u,v and reconstructed a/a1/a2): canonical 64-byte x‖y.
//     dlog      := 0x00 ‖ pk(64) ‖ a(64)
//     dhtuple   := 0x01 ‖ g(64) ‖ h(64) ‖ u(64) ‖ v(64) ‖ a1(64) ‖ a2(64)
//     and       := 0x02 ‖ nChildren(4) ‖ child_0 ‖ …
//     or        := 0x03 ‖ nChildren(4) ‖ child_0 ‖ …
//     threshold := 0x04 ‖ k(4) ‖ nChildren(4) ‖ child_0 ‖ …
//   Root challenge := low31( SHA256( DomainSep ‖ serializeTree(root) ‖ message ) ),
//   DomainSep = ascii("sigma_verify:v1").
//
// CHALLENGE DOMAIN — INJECTIVE BYTE↔SCALAR MAP (audit finding #1, the CDS soundness
// fix). Challenges are 31-byte (248-bit) values, NOT 32-byte. `2^248 < R` (BN254
// `R ≈ 2^253.6`), so the byte↔Fr-scalar map `e ↦ BigUint::from_bytes_be(e)` is a
// BIJECTION onto `[0, 2^248)` — there is NO raw-vs-mod-R duality. Previously
// challenges were 32 bytes, used RAW for the OR-XOR / GF(2^8) split BUT reduced mod
// R for the leaf scalar arithmetic, so `e` and `e + R` (both < 2^256) collapsed to
// the same scalar (a CDS-soundness weakness). Now the SAME 31-byte value is the
// GF(2)^248 / XOR object AND, unchanged (no mod R), the Fr scalar `z·G − e·pk`.
// Responses `z` stay canonical 32-byte (< R); commitments stay 64-byte G1; the serialized
// transcript is UNCHANGED (challenges are not in it).
//
// ERROR-VS-FALSE (lockstep with the leaves): malformed (bad hex/width, off-curve,
// structurally invalid tree, k<=0 or k>n, prop/proof shape mismatch) => Err.
// Well-formed-but-cryptographically-wrong (root hash != root challenge, OR
// challenges do not XOR, threshold does not interpolate, identity statement
// point) => false.
// ===========================================================================

// One fixed tag byte per node kind (part of the bound transcript).
const SIGMA_TAG_DLOG: u8 = 0x00;
const SIGMA_TAG_DHTUPLE: u8 = 0x01;
const SIGMA_TAG_AND: u8 = 0x02;
const SIGMA_TAG_OR: u8 = 0x03;
const SIGMA_TAG_THRESHOLD: u8 = 0x04;

/// Domain separator for the sigma_verify root hash (distinct from leaf transcripts).
const SIGMA_DOMAIN_SEP: &[u8] = b"sigma_verify:v1";

/// Fixed challenge width in bytes — 31 (248-bit), the INJECTIVE-into-Fr domain
/// (finding #1). `2^248 < R`, so a 31-byte challenge is always a canonical Fr
/// element and the byte↔scalar map is a bijection (no `e` vs `e+R` alias). The CDS
/// XOR / GF(2^8) split operates on these 31 bytes (closed in GF(2)^248), and the
/// SAME bytes are the Fr scalar for `z·G − e·pk`.
const SIGMA_CHALLENGE_BYTES: usize = 31;

/// Canonical challenge derivation: the LOW-ORDER 31 bytes of a 32-byte SHA-256
/// digest, i.e. the least-significant 31 bytes (`&digest[1..]`). The single
/// SHA-256→challenge rule (root challenge). Result is in `[0, 2^248)`, a canonical
/// Fr element. Byte-for-byte the Scala `Sigma.low31`.
fn sigma_low31(digest32: &[u8]) -> &[u8] {
    &digest32[digest32.len() - SIGMA_CHALLENGE_BYTES..]
}

/// The 31-byte challenge as its Fr SCALAR, taken DIRECTLY from the bytes (no mod-R
/// reduction). Injective because `from_bytes_be(e) < 2^248 < R` for any 31-byte `e`
/// — the point of the 31-byte domain (finding #1). Byte-for-byte the Scala
/// `Sigma.challengeScalar`.
fn sigma_challenge_scalar(e: &[u8]) -> BigUint {
    BigUint::from_bytes_be(e)
}

// --- Parsed PROPOSITION tree (statement only; no challenges/responses). ---
// `DhTuple` is intentionally larger than `Dlog` (4 points + 4 canonical-byte
// vectors vs 1). The tree is built once per `sigma_verify` call and walked
// recursively -- it is never stored in a large homogeneous collection -- so the
// per-variant size gap is irrelevant; boxing would add indirection to the
// crypto-critical reconstruction path for no benefit.
#[allow(clippy::large_enum_variant)]
enum PropNode {
    Dlog {
        pk: G1Projective,
        pk_bytes: Vec<u8>,
    },
    DhTuple {
        g: G1Projective,
        h: G1Projective,
        u: G1Projective,
        v: G1Projective,
        g_bytes: Vec<u8>,
        h_bytes: Vec<u8>,
        u_bytes: Vec<u8>,
        v_bytes: Vec<u8>,
    },
    And(Vec<PropNode>),
    Or(Vec<PropNode>),
    Threshold(usize, Vec<PropNode>),
}

// --- Parsed PROOF tree (per-node challenge `e`; per-leaf response `z`). ---
enum ProofNode {
    Dlog {
        e: Vec<u8>,
        z: BigUint,
    },
    DhTuple {
        e: Vec<u8>,
        z: BigUint,
    },
    And {
        e: Vec<u8>,
        children: Vec<ProofNode>,
    },
    Or {
        e: Vec<u8>,
        children: Vec<ProofNode>,
    },
    Threshold {
        e: Vec<u8>,
        k: usize,
        children: Vec<ProofNode>,
    },
}

impl ProofNode {
    fn challenge(&self) -> &[u8] {
        match self {
            ProofNode::Dlog { e, .. }
            | ProofNode::DhTuple { e, .. }
            | ProofNode::And { e, .. }
            | ProofNode::Or { e, .. }
            | ProofNode::Threshold { e, .. } => e,
        }
    }
}

/// Absolute backstop on a sigma tree's size/depth (the unpaid-traversal DoS bound). Applied to BOTH
/// the proposition (before its recursive parse — IMPL-1) and the proof. For the proof the PRIMARY
/// bound is also structural: the proof must mirror the (already gas-charged) proposition, so its node
/// count and depth may not exceed the proposition's (checked cheaply BEFORE the recursive
/// `parse_proof_node` / curve work). `pub(crate)` so the gas estimator bounds its proposition-shape
/// walk with the SAME values. Byte-for-byte the Scala `SigmaMaxProofNodes` / `SigmaMaxProofDepth`.
pub(crate) const SIGMA_MAX_PROOF_NODES: usize = 4096;
pub(crate) const SIGMA_MAX_PROOF_DEPTH: usize = 64;

/// IMPL-3 (DoS): absolute cap on a sigma message length, in bytes. The message is hashed into the
/// challenge but is NOT part of the gas-priced proposition shape; without a cap a caller could force
/// unbounded hex-decode + SHA-256 work outside the Sigma-tree pricing. Shared by `sigma_verify` and
/// `prove_dhtuple_verify`. Byte-for-byte the Scala `CryptoOps.SigmaMaxMessageBytes`.
const SIGMA_MAX_MESSAGE_BYTES: usize = 4096;

/// `sigma_verify([proposition, proof, messageHex]) -> bool`.
pub fn sigma_verify(values: &[Value]) -> Result<Value, String> {
    match values {
        [prop_v, proof_v, msg_v] => {
            let msg_hex = expect_str("sigma_verify message", msg_v)?;
            let msg = parse_sigma_message(msg_hex, "sigma_verify message")?;
            // IMPL-1 (DoS): bound the proposition's RAW shape with the absolute caps BEFORE its
            // recursive parse. Both parse_prop_node and sigma_raw_shape descend the attacker-supplied
            // proposition, so a deeply nested / very wide proposition must be rejected here first.
            bound_raw_shape(
                prop_v,
                SIGMA_MAX_PROOF_NODES,
                SIGMA_MAX_PROOF_DEPTH,
                "sigma_verify.proposition",
            )?;
            let prop = parse_prop_node(prop_v, "sigma_verify.proposition")?;
            // FINDING #2 (DoS): bound the raw proof shape against the (gas-charged) proposition
            // BEFORE the expensive recursive proof parse (hex decode, on-curve, scalar mul). A tiny
            // proposition + huge mismatched proof is rejected here after only a bounded raw-tree
            // walk. Because unknown fields are rejected at parse, the proposition's raw shape equals
            // its semantic shape — no leaf-with-bogus-children inflates the bound (IMPL-2). The
            // per-node type/child-count mirror check is still enforced in verify_node.
            let (prop_nodes, prop_depth) = sigma_raw_shape(prop_v);
            let max_nodes = prop_nodes.min(SIGMA_MAX_PROOF_NODES);
            let max_depth = prop_depth.min(SIGMA_MAX_PROOF_DEPTH);
            bound_raw_shape(proof_v, max_nodes, max_depth, "sigma_verify.proof")?;
            let proof = parse_proof_node(proof_v, "sigma_verify.proof")?;
            let result = verify_tree(&prop, &proof, &msg)?;
            Ok(Value::Bool(result))
        }
        _ => Err(format!(
            "sigma_verify: expected [proposition, proof, messageHex], got {values:?}"
        )),
    }
}

/// Cheap node-count + depth of a RAW sigma tree value (proposition or proof): one node per map,
/// recursing into a `children` array. Mirrors the Scala `sigmaRawShape`. A non-map / unrecognised
/// shape counts as a single node (the real parser raises the fault).
fn sigma_raw_shape(v: &Value) -> (usize, usize) {
    match v {
        Value::Map(m) => match m
            .iter()
            .rev()
            .find(|(k, _)| k == "children")
            .map(|(_, v)| v)
        {
            Some(Value::Array(cs)) => {
                let (n, d) = cs.iter().fold((0usize, 0usize), |(acc_n, acc_d), c| {
                    let (cn, cd) = sigma_raw_shape(c);
                    (acc_n + cn, acc_d.max(cd))
                });
                (n + 1, d + 1)
            }
            _ => (1, 1),
        },
        _ => (1, 1),
    }
}

/// Reject — BEFORE the recursive parse — a raw sigma tree whose node count or depth exceeds
/// (`max_nodes` / `max_depth`). Applied to the proposition with the absolute caps (IMPL-1) and to
/// the proof with the proposition-derived caps (FINDING #2). The walk aborts as soon as a bound is
/// crossed, so the work is O(min(tree_size, max_nodes)). Purely structural (no hex / curve work);
/// the per-node type/child-count mirror check is still enforced in verify_node. Mirrors the Scala
/// `boundRawShape`.
fn bound_raw_shape(
    v: &Value,
    max_nodes: usize,
    max_depth: usize,
    role: &str,
) -> Result<(), String> {
    fn too_large(role: &str, max_nodes: usize, max_depth: usize) -> String {
        format!(
            "{role}: sigma tree exceeds the allowed structure \
             (max {max_nodes} nodes, depth {max_depth}) — rejected before traversal (DoS bound)"
        )
    }
    // Returns Ok(nodes_so_far) or Err as soon as a bound is crossed; `depth` is 1-based.
    fn go(
        node: &Value,
        depth: usize,
        nodes_so_far: usize,
        max_nodes: usize,
        max_depth: usize,
        role: &str,
    ) -> Result<usize, String> {
        if depth > max_depth {
            return Err(too_large(role, max_nodes, max_depth));
        }
        let n = nodes_so_far + 1;
        if n > max_nodes {
            return Err(too_large(role, max_nodes, max_depth));
        }
        match node {
            Value::Map(m) => match m
                .iter()
                .rev()
                .find(|(k, _)| k == "children")
                .map(|(_, v)| v)
            {
                Some(Value::Array(cs)) => {
                    let mut running = n;
                    for c in cs {
                        running = go(c, depth + 1, running, max_nodes, max_depth, role)?;
                    }
                    Ok(running)
                }
                _ => Ok(n),
            },
            _ => Ok(n),
        }
    }
    go(v, 1, 0, max_nodes, max_depth, role).map(|_| ())
}

// --- Proposition parsing (statement only). Malformed => hard error. ---

// LAST-wins on duplicate keys (== Scala `Map` semantics / parser dedup); see `Value::map_get` (audit #1).
fn sigma_field<'a>(role: &str, m: &'a [(String, Value)], key: &str) -> Result<&'a Value, String> {
    m.iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or_else(|| format!("{role}: missing required field '{key}'"))
}

/// IMPL-2 / IMPL-5: reject any field outside the canonical schema for this node kind, so the raw
/// proposition / proof encoding is canonical (no ignored field can inflate the DoS shape bound or
/// leave the bytes ambiguous for logs / caches / external signing layers). Mirrors the Scala
/// `sigmaRejectUnknownFields`.
fn sigma_reject_unknown_fields(
    role: &str,
    m: &[(String, Value)],
    allowed: &[&str],
) -> Result<(), String> {
    match m.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
        Some((k, _)) => Err(format!(
            "{role}: unknown field '{k}' (allowed: {})",
            allowed.join(", ")
        )),
        None => Ok(()),
    }
}

/// IMPL-3 (DoS): parse a sigma message (arbitrary-width hex) and enforce the absolute length cap.
/// Shared by `sigma_verify` and `prove_dhtuple_verify`. Mirrors the Scala `parseSigmaMessage`.
fn parse_sigma_message(hex: &str, role: &str) -> Result<Vec<u8>, String> {
    let bytes = hb::parse_bytes(hex, None, role)?;
    if bytes.len() > SIGMA_MAX_MESSAGE_BYTES {
        return Err(format!(
            "{role}: message too long ({} > {SIGMA_MAX_MESSAGE_BYTES} bytes) — DoS bound",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Parse a G1 statement point: on-curve check + canonical 64-byte re-encoding.
fn sigma_point(
    role: &str,
    m: &[(String, Value)],
    key: &str,
) -> Result<(G1Projective, Vec<u8>), String> {
    let v = sigma_field(role, m, key)?;
    let hex = expect_str(&format!("{role}.{key}"), v)?;
    let coords = hb::parse_g1(hex, &format!("{role}.{key}"))?;
    let p = g1_on_curve(&coords, &format!("{role}.{key}"))?;
    let bytes = hb::parse_bytes(hex, Some(hb::G1_BYTES), &format!("{role}.{key}"))?;
    Ok((p, bytes))
}

fn sigma_children_values<'a>(role: &str, m: &'a [(String, Value)]) -> Result<&'a [Value], String> {
    match sigma_field(role, m, "children")? {
        Value::Array(arr) if !arr.is_empty() => Ok(arr.as_slice()),
        Value::Array(_) => Err(format!("{role}: 'children' must be a non-empty array")),
        other => Err(format!(
            "{role}: 'children' must be an array, got {}",
            other.tag()
        )),
    }
}

fn sigma_int(role: &str, m: &[(String, Value)], key: &str) -> Result<usize, String> {
    match sigma_field(role, m, key)? {
        Value::Int(i) => {
            use num_traits::ToPrimitive;
            // 0 <= i <= Int.MaxValue (the Scala bound). usize on 64-bit holds it.
            match i.to_i64() {
                Some(n) if (0..=i64::from(i32::MAX)).contains(&n) => Ok(n as usize),
                _ => Err(format!("{role}.{key}: out of range: {i}")),
            }
        }
        other => Err(format!(
            "{role}.{key}: expected an integer, got {}",
            other.tag()
        )),
    }
}

fn sigma_type<'a>(role: &str, m: &'a [(String, Value)]) -> Result<&'a str, String> {
    let v = sigma_field(role, m, "type")?;
    expect_str(&format!("{role}.type"), v)
}

fn parse_prop_node(v: &Value, role: &str) -> Result<PropNode, String> {
    match v {
        Value::Map(m) => match sigma_type(role, m)? {
            "dlog" => {
                sigma_reject_unknown_fields(role, m, &["type", "pk"])?;
                let (pk, b) = sigma_point(role, m, "pk")?;
                Ok(PropNode::Dlog { pk, pk_bytes: b })
            }
            "dhtuple" => {
                sigma_reject_unknown_fields(role, m, &["type", "g", "h", "u", "v"])?;
                let (g, g_bytes) = sigma_point(role, m, "g")?;
                let (h, h_bytes) = sigma_point(role, m, "h")?;
                let (u, u_bytes) = sigma_point(role, m, "u")?;
                let (vv, v_bytes) = sigma_point(role, m, "v")?;
                Ok(PropNode::DhTuple {
                    g,
                    h,
                    u,
                    v: vv,
                    g_bytes,
                    h_bytes,
                    u_bytes,
                    v_bytes,
                })
            }
            "and" => {
                sigma_reject_unknown_fields(role, m, &["type", "children"])?;
                let cs = sigma_children_values(role, m)?;
                let children = cs
                    .iter()
                    .enumerate()
                    .map(|(i, c)| parse_prop_node(c, &format!("{role}.and[{i}]")))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PropNode::And(children))
            }
            "or" => {
                sigma_reject_unknown_fields(role, m, &["type", "children"])?;
                let cs = sigma_children_values(role, m)?;
                let children = cs
                    .iter()
                    .enumerate()
                    .map(|(i, c)| parse_prop_node(c, &format!("{role}.or[{i}]")))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PropNode::Or(children))
            }
            "threshold" => {
                sigma_reject_unknown_fields(role, m, &["type", "k", "children"])?;
                let k = sigma_int(role, m, "k")?;
                let cs = sigma_children_values(role, m)?;
                let children = cs
                    .iter()
                    .enumerate()
                    .map(|(i, c)| parse_prop_node(c, &format!("{role}.threshold[{i}]")))
                    .collect::<Result<Vec<_>, _>>()?;
                let n = children.len();
                // Structural validity: 1 <= k <= n; n <= 255 (GF(2^8) child indices 1..n).
                if k < 1 {
                    return Err(format!("{role}.threshold: k must be >= 1, got {k}"));
                }
                if k > n {
                    return Err(format!(
                        "{role}.threshold: k ({k}) > number of children ({n})"
                    ));
                }
                if n > 255 {
                    return Err(format!(
                        "{role}.threshold: at most 255 children (GF(2^8) indices), got {n}"
                    ));
                }
                Ok(PropNode::Threshold(k, children))
            }
            other => Err(format!("{role}: unknown node type '{other}'")),
        },
        other => Err(format!(
            "{role}: expected a proposition node object, got {}",
            other.tag()
        )),
    }
}

// --- Proof parsing (per-node challenge + per-leaf response). Malformed => hard error. ---

fn sigma_challenge(role: &str, m: &[(String, Value)]) -> Result<Vec<u8>, String> {
    let v = sigma_field(role, m, "e")?;
    let hex = expect_str(&format!("{role}.e"), v)?;
    // Challenge is a fixed 31-byte (248-bit) big-endian value — the injective-into-Fr
    // domain (finding #1). It is the SAME object the CDS XOR / GF(2^8) split runs over
    // AND, taken directly (no mod R), the Fr scalar for the leaf reconstruction. The
    // verifier compares it byte-for-byte against the recomputed 31-byte challenge.
    hb::parse_bytes(hex, Some(SIGMA_CHALLENGE_BYTES), &format!("{role}.e"))
}

/// Reject a NON-CANONICAL response scalar (`z`/`s` >= R) as a hard error (audit #4). A response is a
/// curve scalar, so `z` and `z + R` are congruent mod R and verify identically; accepting raw 32-byte
/// responses makes the proof bytes malleable. Requiring `z < R` makes the response encoding canonical.
/// Mirrors the Scala `CryptoOps.requireCanonicalScalar`. (Challenges are already canonical: 31 bytes
/// < 2^248 < R.)
fn require_canonical_scalar(z: BigUint, role: &str) -> Result<BigUint, String> {
    if &z < hb::modulus() {
        Ok(z)
    } else {
        Err(format!(
            "{role}: non-canonical response scalar (must be < R)"
        ))
    }
}

fn sigma_response(role: &str, m: &[(String, Value)]) -> Result<BigUint, String> {
    let v = sigma_field(role, m, "z")?;
    let hex = expect_str(&format!("{role}.z"), v)?;
    let z = hb::parse_scalar(hex, &format!("{role}.z"))?;
    require_canonical_scalar(z, &format!("{role}.z"))
}

fn parse_proof_node(v: &Value, role: &str) -> Result<ProofNode, String> {
    match v {
        Value::Map(m) => {
            let e = sigma_challenge(role, m)?;
            let typ = sigma_type(role, m)?;
            match typ {
                "dlog" => {
                    sigma_reject_unknown_fields(role, m, &["type", "e", "z"])?;
                    let z = sigma_response(role, m)?;
                    Ok(ProofNode::Dlog { e, z })
                }
                "dhtuple" => {
                    sigma_reject_unknown_fields(role, m, &["type", "e", "z"])?;
                    let z = sigma_response(role, m)?;
                    Ok(ProofNode::DhTuple { e, z })
                }
                "and" => {
                    sigma_reject_unknown_fields(role, m, &["type", "e", "children"])?;
                    let cs = sigma_children_values(role, m)?;
                    let children = cs
                        .iter()
                        .enumerate()
                        .map(|(i, c)| parse_proof_node(c, &format!("{role}.and[{i}]")))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(ProofNode::And { e, children })
                }
                "or" => {
                    sigma_reject_unknown_fields(role, m, &["type", "e", "children"])?;
                    let cs = sigma_children_values(role, m)?;
                    let children = cs
                        .iter()
                        .enumerate()
                        .map(|(i, c)| parse_proof_node(c, &format!("{role}.or[{i}]")))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(ProofNode::Or { e, children })
                }
                "threshold" => {
                    sigma_reject_unknown_fields(role, m, &["type", "e", "k", "children"])?;
                    let k = sigma_int(role, m, "k")?;
                    let cs = sigma_children_values(role, m)?;
                    let children = cs
                        .iter()
                        .enumerate()
                        .map(|(i, c)| parse_proof_node(c, &format!("{role}.threshold[{i}]")))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(ProofNode::Threshold { e, k, children })
                }
                other => Err(format!("{role}: unknown node type '{other}'")),
            }
        }
        other => Err(format!(
            "{role}: expected a proof node object, got {}",
            other.tag()
        )),
    }
}

/// The recursive verifier (Ergo Verifier Steps 1-6).
///   Err(_)  -> MALFORMED (prop/proof shape mismatch, off-curve, identity base,
///              bad threshold degree/index) -- a hard encoding fault;
///   Ok(false) -> well-formed but cryptographically INVALID;
///   Ok(true)  -> accept.
fn verify_tree(prop: &PropNode, proof: &ProofNode, msg: &[u8]) -> Result<bool, String> {
    let (crypto_ok, serialized) = verify_node(prop, proof, "sigma_verify")?;
    if !crypto_ok {
        return Ok(false);
    }
    // Steps 5-6: STRONG Fiat-Shamir over (DomainSep ‖ canonical tree ‖ message). The
    // root challenge is the LOW-ORDER 31 bytes of the digest (the injective challenge
    // domain, finding #1) — compared BYTE-FOR-BYTE against the proof's 31-byte root
    // challenge. No mod-R reduction on EITHER side: both are 31-byte (< 2^248 < R)
    // values, so byte equality is exactly Fr equality with no `e` vs `e+R` alias.
    let mut hasher = Sha256::new();
    hasher.update(SIGMA_DOMAIN_SEP);
    hasher.update(&serialized);
    hasher.update(msg);
    let digest = hasher.finalize();
    let recomputed_root = sigma_low31(&digest);
    Ok(constant_time_eq(recomputed_root, proof.challenge()))
}

/// One recursive node visit. Returns `(crypto_ok, serialized_bytes)`:
/// `crypto_ok = false` is a well-formed-but-wrong verdict that propagates up;
/// `Err` is a structural/encoding fault (prop/proof shape mismatch is hard error).
fn verify_node(prop: &PropNode, proof: &ProofNode, role: &str) -> Result<(bool, Vec<u8>), String> {
    let group_order = hb::modulus();
    match (prop, proof) {
        // --- DLog leaf: reconstruct a = z·G − e·pk, serialize 0x00 ‖ pk ‖ a. ---
        (PropNode::Dlog { pk, pk_bytes }, ProofNode::Dlog { e, z }) => {
            // SOUNDNESS: reject the identity pk (universal forgery).
            if pk.is_zero() {
                return Ok((false, Vec::new()));
            }
            // The 31-byte challenge IS the Fr scalar, taken directly (no mod R — finding #1).
            let e_scalar = sigma_challenge_scalar(e);
            let z_scalar = z % group_order;
            let a = dlog_compute_commitment(pk, &e_scalar, &z_scalar);
            let a_bytes = encode_g1_bytes(&a, &format!("{role}.dlog.a"))?;
            let mut out = Vec::with_capacity(1 + hb::G1_BYTES * 2);
            out.push(SIGMA_TAG_DLOG);
            out.extend_from_slice(pk_bytes);
            out.extend_from_slice(&a_bytes);
            Ok((true, out))
        }

        // --- DHTuple leaf: a1 = z·g − e·u, a2 = z·h − e·v; serialize 0x01 ‖ g‖h‖u‖v‖a1‖a2. ---
        (
            PropNode::DhTuple {
                g,
                h,
                u,
                v,
                g_bytes,
                h_bytes,
                u_bytes,
                v_bytes,
            },
            ProofNode::DhTuple { e, z },
        ) => {
            // SOUNDNESS: reject identity on any statement point.
            if g.is_zero() || h.is_zero() || u.is_zero() || v.is_zero() {
                return Ok((false, Vec::new()));
            }
            // The 31-byte challenge IS the Fr scalar, taken directly (no mod R — finding #1).
            let e_scalar = sigma_challenge_scalar(e);
            let z_scalar = z % group_order;
            // The single shared response z is used for BOTH coordinate reconstructions.
            let a1 = dhtuple_compute_commitment(g, u, &e_scalar, &z_scalar);
            let a2 = dhtuple_compute_commitment(h, v, &e_scalar, &z_scalar);
            let a1_bytes = encode_g1_bytes(&a1, &format!("{role}.dhtuple.a1"))?;
            let a2_bytes = encode_g1_bytes(&a2, &format!("{role}.dhtuple.a2"))?;
            let mut out = Vec::with_capacity(1 + hb::G1_BYTES * 6);
            out.push(SIGMA_TAG_DHTUPLE);
            out.extend_from_slice(g_bytes);
            out.extend_from_slice(h_bytes);
            out.extend_from_slice(u_bytes);
            out.extend_from_slice(v_bytes);
            out.extend_from_slice(&a1_bytes);
            out.extend_from_slice(&a2_bytes);
            Ok((true, out))
        }

        // --- CAND: every child challenge MUST equal the node challenge. ---
        (
            PropNode::And(p_children),
            ProofNode::And {
                e,
                children: pr_children,
            },
        ) => {
            if p_children.len() != pr_children.len() {
                return Err(format!(
                    "{role}.and: proposition/proof child count mismatch ({} vs {})",
                    p_children.len(),
                    pr_children.len()
                ));
            }
            let child_challenges_ok = pr_children
                .iter()
                .all(|c| constant_time_eq(c.challenge(), e));
            let mut all_ok = child_challenges_ok;
            let mut body = Vec::new();
            for (i, (pc, prc)) in p_children.iter().zip(pr_children.iter()).enumerate() {
                let (ok, ser) = verify_node(pc, prc, &format!("{role}.and[{i}]"))?;
                all_ok = all_ok && ok;
                body.extend_from_slice(&ser);
            }
            let mut out = Vec::with_capacity(1 + 4 + body.len());
            out.push(SIGMA_TAG_AND);
            out.extend_from_slice(&uint32(p_children.len()));
            out.extend_from_slice(&body);
            Ok((all_ok, out))
        }

        // --- COR: child challenges MUST XOR to the node challenge (CDS XOR). ---
        (
            PropNode::Or(p_children),
            ProofNode::Or {
                e,
                children: pr_children,
            },
        ) => {
            if p_children.len() != pr_children.len() {
                return Err(format!(
                    "{role}.or: proposition/proof child count mismatch ({} vs {})",
                    p_children.len(),
                    pr_children.len()
                ));
            }
            let child_es: Vec<&[u8]> = pr_children.iter().map(|c| c.challenge()).collect();
            let xor_ok = constant_time_eq(&xor_bytes(&child_es, SIGMA_CHALLENGE_BYTES), e);
            let mut all_ok = xor_ok;
            let mut body = Vec::new();
            for (i, (pc, prc)) in p_children.iter().zip(pr_children.iter()).enumerate() {
                let (ok, ser) = verify_node(pc, prc, &format!("{role}.or[{i}]"))?;
                all_ok = all_ok && ok;
                body.extend_from_slice(&ser);
            }
            let mut out = Vec::with_capacity(1 + 4 + body.len());
            out.push(SIGMA_TAG_OR);
            out.extend_from_slice(&uint32(p_children.len()));
            out.extend_from_slice(&body);
            Ok((all_ok, out))
        }

        // --- CTHRESHOLD(k,n): child challenges are P(1..n) for a degree-(n-k)
        //     GF(2^8) poly P with P(0) = node challenge. ---
        (
            PropNode::Threshold(p_k, p_children),
            ProofNode::Threshold {
                e,
                k: pr_k,
                children: pr_children,
            },
        ) => {
            if p_k != pr_k {
                return Err(format!(
                    "{role}.threshold: proposition/proof k mismatch ({p_k} vs {pr_k})"
                ));
            }
            if p_children.len() != pr_children.len() {
                return Err(format!(
                    "{role}.threshold: proposition/proof child count mismatch ({} vs {})",
                    p_children.len(),
                    pr_children.len()
                ));
            }
            let n = p_children.len();
            let child_es: Vec<&[u8]> = pr_children.iter().map(|c| c.challenge()).collect();
            let interp_ok = threshold_interpolates(e, &child_es, *p_k, n);
            let mut all_ok = interp_ok;
            let mut body = Vec::new();
            for (i, (pc, prc)) in p_children.iter().zip(pr_children.iter()).enumerate() {
                let (ok, ser) = verify_node(pc, prc, &format!("{role}.threshold[{i}]"))?;
                all_ok = all_ok && ok;
                body.extend_from_slice(&ser);
            }
            let mut out = Vec::with_capacity(1 + 8 + body.len());
            out.push(SIGMA_TAG_THRESHOLD);
            out.extend_from_slice(&uint32(*p_k));
            out.extend_from_slice(&uint32(n));
            out.extend_from_slice(&body);
            Ok((all_ok, out))
        }

        // --- Any other (prop, proof) pairing is a structural shape mismatch. ---
        (p, pr) => Err(format!(
            "{role}: proposition/proof node-type mismatch ({} vs {})",
            prop_node_kind(p),
            proof_node_kind(pr)
        )),
    }
}

/// CTHRESHOLD interpolation check (byte-wise GF(2^8)). The `n` child challenges
/// must be `P(1), …, P(n)` of a degree-`(n-k)` GF(2^8) polynomial with
/// `P(0) = parent challenge`, computed independently per byte-lane (exactly Ergo,
/// over the 31-byte injective challenge domain, finding #1). `false` (not error) on
/// mismatch.
fn threshold_interpolates(parent_e: &[u8], child_es: &[&[u8]], k: usize, n: usize) -> bool {
    let degree = n - k; // (degree + 1) points define the polynomial
    let known_count = degree + 1;
    // Defining x-coords: 0 (parent), then child indices 1..degree.
    let xs: Vec<i32> = (0..known_count as i32).collect();
    // Each of the 31 byte-lanes must independently interpolate.
    (0..SIGMA_CHALLENGE_BYTES).all(|lane| {
        let ys: Vec<i32> = (0..known_count)
            .map(|j| {
                if j == 0 {
                    i32::from(parent_e[lane]) // P(0) = parent challenge
                } else {
                    i32::from(child_es[j - 1][lane]) // child (j-1) sits at x = j
                }
            })
            .collect();
        // Remaining (unconstrained) children: indices degree .. n-1, i.e. x = degree+1 .. n.
        (degree..n)
            .all(|c| i32::from(child_es[c][lane]) == gf_lagrange_eval(&xs, &ys, c as i32 + 1))
    })
}

/// Node-kind label for shape-mismatch error messages.
fn prop_node_kind(n: &PropNode) -> &'static str {
    match n {
        PropNode::Dlog { .. } => "dlog",
        PropNode::DhTuple { .. } => "dhtuple",
        PropNode::And(_) => "and",
        PropNode::Or(_) => "or",
        PropNode::Threshold(..) => "threshold",
    }
}

fn proof_node_kind(n: &ProofNode) -> &'static str {
    match n {
        ProofNode::Dlog { .. } => "dlog",
        ProofNode::DhTuple { .. } => "dhtuple",
        ProofNode::And { .. } => "and",
        ProofNode::Or { .. } => "or",
        ProofNode::Threshold { .. } => "threshold",
    }
}

// ---------------------------------------------------------------------------
// Commitment-recovery primitives (the sigma_verify tree's bottom-up step).
//   dlog:    a = z·G − e·pk         (honest: a = R = r·G)
//   dhtuple: a = z·base − e·image   (honest: a = r·base)
// ---------------------------------------------------------------------------

/// DLog commitment recovery: `a = z·G − e·pk`. The caller passes `e` (the 31-byte
/// challenge, used DIRECTLY as the Fr scalar — no mod R, finding #1) and a canonical
/// response `z` (< R). Byte-for-byte: the resulting affine point's canonical (x,y) is
/// what gets serialized.
fn dlog_compute_commitment(pk: &G1Projective, e: &BigUint, z: &BigUint) -> G1Affine {
    // z·G + (−e·pk): computed in projective, converted to affine. The affine
    // (x,y) (with infinity -> (0,0)) is identical to the Scala manual y-negation.
    let z_g = generator().mul_biguint(z); // affine
    let e_pk = pk.mul_biguint(e); // affine
    (z_g.into_group() - e_pk.into_group()).into_affine()
}

/// DHTuple commitment recovery for one base: `a = z·base − e·image`.
fn dhtuple_compute_commitment(
    base: &G1Projective,
    image: &G1Projective,
    e: &BigUint,
    z: &BigUint,
) -> G1Affine {
    let z_base = base.mul_biguint(z);
    let e_img = image.mul_biguint(e);
    (z_base.into_group() - e_img.into_group()).into_affine()
}

/// Re-encode a reconstructed G1 commitment to its canonical 64-byte big-endian
/// bytes (matching the Scala `encodeG1Bytes`: `HexBytes.encodeG1` then parse to
/// fixed 64-byte width). Infinity -> 64 zero bytes.
fn encode_g1_bytes(p: &G1Affine, role: &str) -> Result<Vec<u8>, String> {
    let hex = encode_g1_point(p)?;
    hb::parse_bytes(&hex, Some(hb::G1_BYTES), role)
}

/// Fixed 4-byte big-endian encoding of a non-negative count / threshold k.
fn uint32(v: usize) -> [u8; 4] {
    (v as u32).to_be_bytes()
}

/// XOR a list of equal-width byte arrays into one `width`-byte array (CDS OR fold).
fn xor_bytes(arrays: &[&[u8]], width: usize) -> Vec<u8> {
    (0..width)
        .map(|i| arrays.iter().fold(0u8, |acc, a| acc ^ a[i]))
        .collect()
}

/// Length-checked, data-independent byte equality (no early-exit timing leak).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// GF(2^8) Shamir arithmetic for the CTHRESHOLD challenge split (AES field 0x11b).
//   Byte-for-byte port of the Scala gfMul / gfInv / gfLagrangeEval. The challenge
//   is a 31-byte array (finding #1); interpolation runs over 31 independent lanes.
// ---------------------------------------------------------------------------

/// GF(2^8) multiply (Russian-peasant, AES reduction poly 0x11b).
fn gf_mul(a0: i32, b0: i32) -> i32 {
    let mut prod = 0i32;
    let mut a = a0 & 0xff;
    let mut b = b0 & 0xff;
    for _ in 0..8 {
        if (b & 1) != 0 {
            prod ^= a;
        }
        let high = a & 0x80;
        a = (a << 1) & 0xff;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    prod & 0xff
}

/// GF(2^8) multiplicative inverse via Fermat (a^254 = a^-1 for a != 0). gf_inv(0)=0.
fn gf_inv(a: i32) -> i32 {
    if (a & 0xff) == 0 {
        return 0;
    }
    // a^254: square-and-multiply over the 8 bits of 254 = 0b11111110.
    let mut acc = 1i32;
    let mut base = a & 0xff;
    for bit in 0..8 {
        if ((254 >> bit) & 1) != 0 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
    }
    acc & 0xff
}

/// Lagrange evaluation in GF(2^8): given DISTINCT sample points `(xs, ys)`, return
/// the interpolating polynomial evaluated at `x_eval`. Subtraction == XOR.
fn gf_lagrange_eval(xs: &[i32], ys: &[i32], x_eval: i32) -> i32 {
    let mut acc = 0i32;
    for i in 0..xs.len() {
        // basis_i(x_eval) = ∏_{j!=i} (x_eval - xs_j) / (xs_i - xs_j).
        let mut num = 1i32;
        let mut den = 1i32;
        for j in 0..xs.len() {
            if j != i {
                num = gf_mul(num, x_eval ^ xs[j]);
                den = gf_mul(den, xs[i] ^ xs[j]);
            }
        }
        acc ^= gf_mul(ys[i], gf_mul(num, gf_inv(den)));
    }
    acc & 0xff
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
    fn map_get_last_wins_on_duplicate_keys() {
        // audit #1: Rust map lookup must match the Scala reference (`Map.get` = last-wins) so a
        // duplicate-key object resolves identically cross-runtime. `decode_value` never yields
        // duplicate pairs (serde_json collapses to last at parse); a hand-built `Value::Map` could,
        // and last-wins keeps Rust == Scala. Pins `value::map_get` (also used by gas_eval / mirrored
        // by `sigma_field`).
        use crate::value::decode_value;
        let m = Value::Map(vec![
            ("type".to_string(), Value::Str("dlog".to_string())),
            ("type".to_string(), Value::Str("dhtuple".to_string())),
        ]);
        assert!(
            m.map_get("type")
                .expect("key present")
                .deep_eq(&Value::Str("dhtuple".to_string())),
            "duplicate key must resolve last-wins (dhtuple)"
        );
        // JSON path: serde_json already collapses duplicates to last, so decode + lookup agree.
        let v =
            decode_value(&serde_json::from_str::<serde_json::Value>(r#"{"a":1,"a":2}"#).unwrap());
        assert!(
            v.map_get("a")
                .expect("key present")
                .deep_eq(&Value::int_from_i64(2)),
            "JSON duplicate key must resolve last-wins (2)"
        );
    }

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

    // -- Tier-3a: ark-bn254 == alt_bn128 (same base/scalar field moduli) ------

    #[test]
    fn ark_bn254_equals_alt_bn128_moduli() {
        use ark_ff::{BigInteger, PrimeField};
        // Scala Bn254.P (Fp modulus) and Bn254.R (Fr modulus / group order).
        let p_scala = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap();
        let r_scala = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();
        let p_ark = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
        let r_ark = BigUint::from_bytes_be(&ArkFr::MODULUS.to_bytes_be());
        assert_eq!(
            p_ark, p_scala,
            "ark-bn254 Fq modulus must equal alt_bn128 P"
        );
        assert_eq!(
            r_ark, r_scala,
            "ark-bn254 Fr modulus must equal alt_bn128 R"
        );
        // Generator (1, 2) confirms the same short-Weierstrass curve y^2=x^3+3.
        assert!(G1Affine::new_unchecked(Fq::from(1u64), Fq::from(2u64)).is_on_curve());
    }

    // -- Tier-3a: the real SP1 Groth16 fixture verifies ----------------------

    fn b(hex: &str) -> Vec<u8> {
        hb::parse_bytes(hex, None, "test").unwrap()
    }

    const FIX_VKEY: &str = "0x00f31d3c82e1ac5e413efe237066f7b6820416878cd71f6c9d4f642b24732a93";
    const FIX_PUB: &str = "0x58d7c56e77ed39c091110d92d46a66cea049a474d753f6b956aa705da6d37910f93307032beacc2e0689ce1995ac2d0e5c10bd07368f02a3c66a48d6a92379de32b53f73997cb99264404f7864305478604d1fe6a294d02ba66fbca99486521a0000000000000000000000000000000000000000000000000000000000000001";
    const FIX_PROOF: &str = "0x4388a21c0000000000000000000000000000000000000000000000000000000000000000002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f253520000000000000000000000000000000000000000000000000000000000000000290c3934305db216c7a88e30e3aaf6c6d0987552c2538c944cf3b9594780b1c01a42da01353837bd8b620918fc2589197feb2195512b68d814df02f27b33bc752f47a335f7336670e17c24c6b60620f5cc36732006467eebfe47fce06299a1672867b465bb0370cee01c0e48f00cbbe5fc1aeb01b45d4b91901d6b12a8d447372405d77dd7bebda65275600b86cc732015db2740ff20f0e782ba27bd575f082520a19daad962d6791b5d72cd476c5ede8f04e042bedff291d8adc35f3d6cd5f60cfe1755fdb55da90ed1b58b271c39f0956c0eb876cfc0fdad0d62a37ae616741b90155ee4f9846f42ca5dfb9e235ddc24575d36545d108b1b87328a368ee768";

    #[test]
    fn real_sp1_groth16_proof_verifies() {
        let res = groth16::verify(&b(FIX_VKEY), &b(FIX_PUB), &b(FIX_PROOF));
        assert_eq!(res, Ok(()), "the real SP1 Groth16 proof MUST verify");
    }

    #[test]
    fn tampered_last_proof_byte_fails() {
        let mut proof = b(FIX_PROOF);
        let n = proof.len() - 1;
        proof[n] ^= 0x01;
        assert!(groth16::verify(&b(FIX_VKEY), &b(FIX_PUB), &proof).is_err());
    }

    #[test]
    fn wrong_selector_fails() {
        let mut proof = b(FIX_PROOF);
        proof[0] ^= 0x01;
        assert_eq!(
            groth16::verify(&b(FIX_VKEY), &b(FIX_PUB), &proof),
            Err("wrong verifier selector".to_string())
        );
    }

    #[test]
    fn wrong_public_values_fails() {
        let mut pub_v = b(FIX_PUB);
        pub_v[0] ^= 0x01;
        assert!(groth16::verify(&b(FIX_VKEY), &pub_v, &b(FIX_PROOF)).is_err());
    }

    #[test]
    fn wrong_program_vkey_fails() {
        let mut vkey = b(FIX_VKEY);
        vkey[0] ^= 0x01;
        assert!(groth16::verify(&vkey, &b(FIX_PUB), &b(FIX_PROOF)).is_err());
    }

    // -- Tier-3a: soundness hardening (proof-point validation) ----------------

    /// off-curve proof point A (A.y := A.y+1) -> verifier Err WITHOUT the
    /// encoding prefix; opcode maps it to `false` (cryptographically invalid).
    const ADV_OFFCURVE_A: &str = "0x4388a21c0000000000000000000000000000000000000000000000000000000000000000002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f253520000000000000000000000000000000000000000000000000000000000000000290c3934305db216c7a88e30e3aaf6c6d0987552c2538c944cf3b9594780b1c01a42da01353837bd8b620918fc2589197feb2195512b68d814df02f27b33bc762f47a335f7336670e17c24c6b60620f5cc36732006467eebfe47fce06299a1672867b465bb0370cee01c0e48f00cbbe5fc1aeb01b45d4b91901d6b12a8d447372405d77dd7bebda65275600b86cc732015db2740ff20f0e782ba27bd575f082520a19daad962d6791b5d72cd476c5ede8f04e042bedff291d8adc35f3d6cd5f60cfe1755fdb55da90ed1b58b271c39f0956c0eb876cfc0fdad0d62a37ae616741b90155ee4f9846f42ca5dfb9e235ddc24575d36545d108b1b87328a368ee768";

    /// proof point B replaced with an on-curve G2 point at x=(2,1) NOT in the
    /// order-r subgroup -> verifier Err WITHOUT the encoding prefix; opcode
    /// maps it to `false`.
    const ADV_NONSUB_B: &str = "0x4388a21c0000000000000000000000000000000000000000000000000000000000000000002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f253520000000000000000000000000000000000000000000000000000000000000000290c3934305db216c7a88e30e3aaf6c6d0987552c2538c944cf3b9594780b1c01a42da01353837bd8b620918fc2589197feb2195512b68d814df02f27b33bc75000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000022b76c179599bb92a963dac85546a005a777f7c13f6a7b75d5918b6b5808f5fde101f7278419308b95099eca02dcee0c5381f4d26d1d62313f057167f064101ce0cfe1755fdb55da90ed1b58b271c39f0956c0eb876cfc0fdad0d62a37ae616741b90155ee4f9846f42ca5dfb9e235ddc24575d36545d108b1b87328a368ee768";

    /// proof coordinate A.x := P (== base-field modulus, >= P) -> NON-CANONICAL
    /// encoding -> verifier Err WITH the encoding prefix; opcode propagates as
    /// a hard error.
    const ADV_COORD_GE_P: &str = "0x4388a21c0000000000000000000000000000000000000000000000000000000000000000002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd471a42da01353837bd8b620918fc2589197feb2195512b68d814df02f27b33bc752f47a335f7336670e17c24c6b60620f5cc36732006467eebfe47fce06299a1672867b465bb0370cee01c0e48f00cbbe5fc1aeb01b45d4b91901d6b12a8d447372405d77dd7bebda65275600b86cc732015db2740ff20f0e782ba27bd575f082520a19daad962d6791b5d72cd476c5ede8f04e042bedff291d8adc35f3d6cd5f60cfe1755fdb55da90ed1b58b271c39f0956c0eb876cfc0fdad0d62a37ae616741b90155ee4f9846f42ca5dfb9e235ddc24575d36545d108b1b87328a368ee768";

    #[test]
    fn adversarial_offcurve_a_is_false_not_error() {
        // Verifier: Err, but NOT an encoding error.
        let res = groth16::verify(&b(FIX_VKEY), &b(FIX_PUB), &b(ADV_OFFCURVE_A));
        let e = res.expect_err("off-curve A must be rejected");
        assert!(
            !e.starts_with(groth16::ENCODING_ERROR_PREFIX),
            "off-curve A is cryptographic invalidity, not an encoding error: {e}"
        );
        // Opcode: false (NOT an error).
        let v = groth16_verify(&[
            Value::Str(FIX_VKEY.into()),
            Value::Str(FIX_PUB.into()),
            Value::Str(ADV_OFFCURVE_A.into()),
        ])
        .expect("off-curve A must be a value (false), not an opcode error");
        assert!(matches!(v, Value::Bool(false)));
    }

    #[test]
    fn adversarial_nonsubgroup_b_is_false_not_error() {
        let res = groth16::verify(&b(FIX_VKEY), &b(FIX_PUB), &b(ADV_NONSUB_B));
        let e = res.expect_err("non-subgroup B must be rejected");
        assert!(
            !e.starts_with(groth16::ENCODING_ERROR_PREFIX),
            "non-subgroup B is cryptographic invalidity, not an encoding error: {e}"
        );
        assert!(
            e.contains("subgroup"),
            "non-subgroup B must fail the G2 subgroup check specifically: {e}"
        );
        let v = groth16_verify(&[
            Value::Str(FIX_VKEY.into()),
            Value::Str(FIX_PUB.into()),
            Value::Str(ADV_NONSUB_B.into()),
        ])
        .expect("non-subgroup B must be a value (false), not an opcode error");
        assert!(matches!(v, Value::Bool(false)));
    }

    #[test]
    fn adversarial_coordinate_ge_p_is_error() {
        // Verifier: Err WITH the encoding prefix.
        let res = groth16::verify(&b(FIX_VKEY), &b(FIX_PUB), &b(ADV_COORD_GE_P));
        let e = res.expect_err("coordinate >= P must be rejected");
        assert!(
            e.starts_with(groth16::ENCODING_ERROR_PREFIX),
            "coordinate >= P is a non-canonical ENCODING error: {e}"
        );
        // Opcode: hard error (NOT false).
        let err = groth16_verify(&[
            Value::Str(FIX_VKEY.into()),
            Value::Str(FIX_PUB.into()),
            Value::Str(ADV_COORD_GE_P.into()),
        ]);
        assert!(
            err.is_err(),
            "coordinate >= P must be an opcode error, not false: {err:?}"
        );
    }

    #[test]
    fn groth16_opcode_isright_to_bool() {
        // Opcode boundary: real proof -> true.
        let ok = groth16_verify(&[
            Value::Str(FIX_VKEY.into()),
            Value::Str(FIX_PUB.into()),
            Value::Str(FIX_PROOF.into()),
        ])
        .unwrap();
        assert!(matches!(ok, Value::Bool(true)));
        // Wrong-width vkey -> Err (a JsonLogicException), NOT false.
        let bad_vkey = format!("0x{}", "00".repeat(31)); // 31 bytes
        let err = groth16_verify(&[
            Value::Str(bad_vkey),
            Value::Str(FIX_PUB.into()),
            Value::Str(FIX_PROOF.into()),
        ]);
        assert!(err.is_err(), "wrong-width vkey must be an opcode error");
    }

    // -- Tier-3b: BLS12-381 PoP ciphersuite (blst min_pk) --------------------

    /// The signature DST MUST be the eth2 / IETF ProofOfPossession suite tag.
    #[cfg(feature = "bls")]
    #[test]
    fn bls_dst_is_eth2_pop() {
        assert_eq!(bls::DST, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
        assert_eq!(bls::PUBLIC_KEY_BYTES, 48);
        assert_eq!(bls::SIGNATURE_BYTES, 96);
    }

    /// PUBLISHED ethereum/bls12-381-tests v0.1.2 `verify_valid_case_e8a50c445c855360`.
    /// Independent ground truth: matching it (as the eth2-conformant Scala
    /// `Bls12381` already does) proves Scala<->Rust BLS byte-identity.
    #[cfg(feature = "bls")]
    #[test]
    fn bls_published_verify_valid_case() {
        let ok = bls_verify(&[
            Value::Str("0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a".into()),
            Value::Str("0x0000000000000000000000000000000000000000000000000000000000000000".into()),
            Value::Str("0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55".into()),
        ])
        .unwrap();
        assert!(matches!(ok, Value::Bool(true)));
    }

    /// PUBLISHED `verify_wrong_pubkey_case_2f09d443ab8a3ac2`: a valid signature
    /// checked against the wrong pubkey verifies `false` (NOT an error).
    #[cfg(feature = "bls")]
    #[test]
    fn bls_published_wrong_pubkey_is_false() {
        let r = bls_verify(&[
            Value::Str("0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81".into()),
            Value::Str("0x0000000000000000000000000000000000000000000000000000000000000000".into()),
            Value::Str("0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55".into()),
        ])
        .unwrap();
        assert!(matches!(r, Value::Bool(false)));
    }

    /// PUBLISHED `fast_aggregate_verify_valid_3d7576f3c0e3570a`: 3-signer
    /// same-message aggregate verifies `true`.
    #[cfg(feature = "bls")]
    #[test]
    fn bls_published_fast_aggregate_verify_valid() {
        let ok = bls_aggregate_verify(&[
            Value::Array(vec![
                Value::Str("0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a".into()),
                Value::Str("0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81".into()),
                Value::Str("0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f".into()),
            ]),
            Value::Str("0xabababababababababababababababababababababababababababababababab".into()),
            Value::Str("0x9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930".into()),
        ])
        .unwrap();
        assert!(matches!(ok, Value::Bool(true)));
    }

    /// PUBLISHED `fast_aggregate_verify_extra_pubkey_5a38e6b4017fe4dd`: an extra
    /// 4th pubkey (not part of the 3-signer aggregate) verifies `false`.
    #[cfg(feature = "bls")]
    #[test]
    fn bls_published_fast_aggregate_verify_extra_pubkey() {
        let r = bls_aggregate_verify(&[
            Value::Array(vec![
                Value::Str("0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a".into()),
                Value::Str("0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81".into()),
                Value::Str("0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f".into()),
                Value::Str("0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f".into()),
            ]),
            Value::Str("0xabababababababababababababababababababababababababababababababab".into()),
            Value::Str("0x9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930".into()),
        ])
        .unwrap();
        assert!(matches!(r, Value::Bool(false)));
    }

    /// Wrong-WIDTH pk (47 bytes) is an opcode ERROR (a JsonLogicException), NOT
    /// `false` -- mirrors the Scala `HexBytes.parseBytes(_, Some(48), ...)`.
    #[cfg(feature = "bls")]
    #[test]
    fn bls_wrong_width_pk_is_error() {
        let bad_pk = format!("0x{}", "ab".repeat(47)); // 47 bytes
        let err = bls_verify(&[
            Value::Str(bad_pk),
            Value::Str("0x636f6e7374656c6c6174696f6e2d736e617073686f742d30783031".into()),
            Value::Str("0xa816e2440371eea63b85484f0111914874974cfb8f83833b214ba365bc1bc46cfd070d75c8decb6e9d9bcea0e2a2b92214cfe0bed5c00a7702741a2e92186454f76ba5e4e86804908e7a2f38a0f123941b3513bff5a4af6951c6c7a8e61b04ee".into()),
        ]);
        assert!(err.is_err(), "wrong-width pk must be an opcode error");
    }

    /// Empty pubkey list in aggregate verify is an opcode ERROR (matches the
    /// Scala `Either.cond(pks.nonEmpty, ...)`).
    #[cfg(feature = "bls")]
    #[test]
    fn bls_aggregate_empty_pubkeys_is_error() {
        let err = bls_aggregate_verify(&[
            Value::Array(vec![]),
            Value::Str("0x636f6d6d69747465652d726f756e642d37".into()),
            Value::Str("0xa3f4674d9b713ca0598e394a19c98e5312eafd2b4e3698b41090651332d507d330d5a9e36aa46f8247ec84e1e0302c1c08bdd8f7944dc7a8daa0cb8c07b6c3837015b6c8533247c1c8876102d9650857c00924f9d7999f4df8a2a30af33c48d4".into()),
        ]);
        assert!(err.is_err(), "empty pubkey list must be an opcode error");
    }

    // -----------------------------------------------------------------------
    // SIGMA serialization byte-contract (frozen layout, docs/sigma-verify.md §4).
    //
    // For a VALID proof the verifier's `verify_node` serialization (over the
    // RECONSTRUCTED commitments) equals the Scala prover's `serializeWithCommitments`
    // (over the SAME commitments). These KATs are the Scala-emitted
    // `serializedHex` (src/test/resources/conformance/sigma_serialization_kats.json,
    // produced by metakit's SigmaVectorGen). Asserting `verify_node` reproduces
    // them DIRECTLY pins the Rust strong-FS transcript byte layout against the
    // Scala byte layout, independent of the true/false verification outcome --
    // this is the crown-jewel byte-identity evidence for an external audit.
    // -----------------------------------------------------------------------
    #[test]
    fn sigma_serialization_byte_identity_against_scala_kats() {
        // (name, proposition JSON, proof JSON, serializedHex) -- Scala SigmaVectorGen output.
        let kats: &[(&str, &str, &str, &str)] = &[
            (
                "dlog_leaf",
                r#"{"type":"dlog","pk":"0x14e2946f9ea29efcd6c8d3bc8ebce97aff2267495f19207d83a5a278b3d1b6750d6d60e75a6a4aef02b7c664972665bbdfa16ef85493ca2cc449eea611b9ed31"}"#,
                r#"{"type":"dlog","e":"0x2430cab45f89f4b1eaf2d8f5a50e7ad580b7dc16a64b3354112260d86bc256","z":"0x17d5e6804e36b07d0513a88e1752f57f76220e519b54158da168ccc3b3376ef7"}"#,
                "0x0014e2946f9ea29efcd6c8d3bc8ebce97aff2267495f19207d83a5a278b3d1b6750d6d60e75a6a4aef02b7c664972665bbdfa16ef85493ca2cc449eea611b9ed312a809b6fd67e25c49a02f77a027549454c315f3b2ab5abb9dd1703f58b3e577029f44e34d7780544f048c41a6553ef973c6c7f8ae1c750d4bf3e82292201182b",
            ),
            (
                "dhtuple_leaf",
                r#"{"type":"dhtuple","g":"0x0769bf9ac56bea3ff40232bcb1b6bd159315d84715b8e679f2d355961915abf02ab799bee0489429554fdb7c8d086475319e63b40b9c5b57cdf1ff3dd9fe2261","h":"0x17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c","u":"0x2eba7a08251112136606485e9ef2e55c89618b022ba2026780f015eb009781e320142996aa0765cc8c5ecbc54fe1d745894e84e61a65a8be30e940299d267428","v":"0x1bc98a3a15f93ae006e031b63507c00fd6f754a3d6f3412f8aada736ee976c0218fc62bcab6e3d356c9dd7946c656177f41c17ef2cd02a3955df2c75ab227d70"}"#,
                r#"{"type":"dhtuple","e":"0x16982c4fa6a92b71b4144e34979338925a424ce1efe6219bb75f01e079cc77","z":"0x0b114f46e47439db9ed88df52a196cdda454caa6a6034f868d0a76652b2ac2a8"}"#,
                "0x010769bf9ac56bea3ff40232bcb1b6bd159315d84715b8e679f2d355961915abf02ab799bee0489429554fdb7c8d086475319e63b40b9c5b57cdf1ff3dd9fe226117c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c2eba7a08251112136606485e9ef2e55c89618b022ba2026780f015eb009781e320142996aa0765cc8c5ecbc54fe1d745894e84e61a65a8be30e940299d2674281bc98a3a15f93ae006e031b63507c00fd6f754a3d6f3412f8aada736ee976c0218fc62bcab6e3d356c9dd7946c656177f41c17ef2cd02a3955df2c75ab227d70295d927e26b6641e0f6a019b9dcf4aed7381a9cd1985f27da31f58d10232e40902c0735a9a98e11fec528e703f5eb70a84ad93726f5ab2e8c51852d6d5ab2a4e1de6f7a27cf74bf33d4650b8488989812960f94391d97a0e19221abdc20172721a49c5d53779e959f9fbb11808d7fbaea6254baeb7892648e382c78d8cc87c7d",
            ),
            (
                "and_dlog_dhtuple",
                r#"{"type":"and","children":[{"type":"dlog","pk":"0x17072b2ed3bb8d759a5325f477629386cb6fc6ecb801bd76983a6b86abffe078168ada6cd130dd52017bb54bfa19377aadfe3bf05d18f41b77809f7f60d4af9e"},{"type":"dhtuple","g":"0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4","h":"0x039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98","u":"0x22c54997b1e4f7710df6e925b259327d9bb23b29af52a8ab9d271c846c1f20752a537682cb57be952ce98746dc33229fbcd6bf0d113e45ffd2df20cadcc748e9","v":"0x236ecf67512dd8b3157d61220f369e1ed51043a80aeb449252b4d617386d792716105ce337dce18aa0a9894c354e9365c14d312625d14e3334128af51a477c1f"}]}"#,
                r#"{"type":"and","e":"0x96158ab9fbfb4883379451733088a04e894164153fe703469da1e7411adef9","children":[{"type":"dlog","e":"0x96158ab9fbfb4883379451733088a04e894164153fe703469da1e7411adef9","z":"0x057e4987f00ae105a86795c2545eec7eddaf503d9986d9549404d95f1047e7c1"},{"type":"dhtuple","e":"0x96158ab9fbfb4883379451733088a04e894164153fe703469da1e7411adef9","z":"0x071b7085f5af476cd450b676e1d7d5061dc7749bb5716d133c3cb15cd2bf6d3f"}]}"#,
                "0x02000000020017072b2ed3bb8d759a5325f477629386cb6fc6ecb801bd76983a6b86abffe078168ada6cd130dd52017bb54bfa19377aadfe3bf05d18f41b77809f7f60d4af9e1221f30fef7dc01cf68820287d83aacd34fb18f82e9bf824c7f870a28940ff6d1c9b015ad48983282b472d5e956b000d736aaf8deb4bc8641eeb90403825dce001030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d9822c54997b1e4f7710df6e925b259327d9bb23b29af52a8ab9d271c846c1f20752a537682cb57be952ce98746dc33229fbcd6bf0d113e45ffd2df20cadcc748e9236ecf67512dd8b3157d61220f369e1ed51043a80aeb449252b4d617386d792716105ce337dce18aa0a9894c354e9365c14d312625d14e3334128af51a477c1f1c3a9d42812441f38bfb619ef71bbfbf1074ed691ce1bfdbe46f84e50b5ef93a19a66b5e7152c9f25eac242de91c8a80997a9e74548ab0f007553bc19986c97206958a0da25a2edab55f8882b2ff401d27a52f5b3f102bcb16b6a57710073a9206bb3ad35548d5fad8df9de103f7d0efd53ee750287ab0db0235f87a9042695b",
            ),
            (
                "threshold_2of3",
                r#"{"type":"threshold","k":2,"children":[{"type":"dlog","pk":"0x003994af9546cdff40006d2c4f32dbb004d348f9a97dfeb88d6cf1671c2e3d932e0191fc912a1eb50c10abd503e81b1a53bfb2605c6689117d9a561bf85fed3c"},{"type":"dlog","pk":"0x276869d833946d4b8d9155cc4264a4f5216b8c87afadfaaf1e8d290ecbd8c7a306d915e47e5908cdad1ccd5f092b94cf3f0152705e0f737988075b110be63658"},{"type":"dlog","pk":"0x298a2726c54a32c634a63eac47ad9ac9e9ce5773ab17a7d2cb0d6361e0fa12d92e0485223f68b741ca1b5a1aea8e040318c2c6a33becbcfa04667d7eeec0d43b"}]}"#,
                r#"{"type":"threshold","e":"0xbaa89e5ee85d41bc0dc0b3a6e30a0399941a8ea2f8370c7a54c3cf42bea722","k":2,"children":[{"type":"dlog","e":"0x53792b5975bfd634aeab8862f43ee4d48004dd95898f2094a1f7c6a924b17f","z":"0x01a83d2fe4629d3a419f70c7ad1a32d1a6ab2a177375252da9bbdc3113266cfe"},{"type":"dlog","e":"0x7311ef50c98274b75016c535cd62d603bc2628cc1a5c54bda5abdd8f918b98","z":"0x00f71e00ee696fb5cedd1c4f83beb6961cafbcf01a9aaf8e58d94b598fa2b062"},{"type":"dlog","e":"0x9ac05a575460e33ff37dfef1da56314ea8387bfb6be47853509fd4640b9dc5","z":"0x1ba8ed8d772a2ce57feb82d9d26c2f9a13b7b378ed3ed9c2010be4dd0096e51f"}]}"#,
                "0x04000000020000000300003994af9546cdff40006d2c4f32dbb004d348f9a97dfeb88d6cf1671c2e3d932e0191fc912a1eb50c10abd503e81b1a53bfb2605c6689117d9a561bf85fed3c25ec8644ab850f14cde799de612d011baf7c929c13cc5021cf37c5fbfc9d30bb05facd1d00c720142fbe951bb0bc1facf79b7e923d895fecda5a50849657819400276869d833946d4b8d9155cc4264a4f5216b8c87afadfaaf1e8d290ecbd8c7a306d915e47e5908cdad1ccd5f092b94cf3f0152705e0f737988075b110be6365821e08dd89f020c7b74dd92ba0e68eb5bca615e04da171dc17952df19f7b99c16074cc2253b6ebedef75eebf94842ea51b4892f1ec1dddc861306f9b97d76536f00298a2726c54a32c634a63eac47ad9ac9e9ce5773ab17a7d2cb0d6361e0fa12d92e0485223f68b741ca1b5a1aea8e040318c2c6a33becbcfa04667d7eeec0d43b2567890bf5e0dec245624fa4264913003890486700dabd799dcbd93ea66cf41124b2d3087eccefea38ef245878aeb22b9f8be4d3f62169be10ecc77925d8f671",
            ),
        ];

        for (name, prop_json, proof_json, want_hex) in kats {
            let prop_v: serde_json::Value =
                serde_json::from_str(prop_json).expect("KAT proposition is valid JSON");
            let proof_v: serde_json::Value =
                serde_json::from_str(proof_json).expect("KAT proof is valid JSON");
            let prop = parse_prop_node(&crate::value::decode_value(&prop_v), "kat.prop")
                .unwrap_or_else(|e| panic!("KAT {name} proposition parse: {e}"));
            let proof = parse_proof_node(&crate::value::decode_value(&proof_v), "kat.proof")
                .unwrap_or_else(|e| panic!("KAT {name} proof parse: {e}"));
            let (crypto_ok, serialized) = verify_node(&prop, &proof, "kat")
                .unwrap_or_else(|e| panic!("KAT {name} verify_node errored: {e}"));
            // The KATs are all VALID proofs, so the CDS relations hold.
            assert!(
                crypto_ok,
                "KAT {name} should be cryptographically well-formed"
            );
            let got_hex = hb::encode_bytes(&serialized);
            assert_eq!(
                &got_hex, want_hex,
                "SIGMA serialization byte mismatch for KAT `{name}` (Rust verify_node vs Scala serializeTree)"
            );
        }
    }

    // -----------------------------------------------------------------------
    // FINDING #1: the 31-byte challenge domain is INJECTIVE into Fr (no e vs e+R
    // alias). 2^248 < R, so every 31-byte challenge is a distinct canonical Fr
    // element and the byte->scalar map is a bijection. Mirrors the Scala test.
    // -----------------------------------------------------------------------
    #[test]
    fn sigma_challenge_domain_is_injective_into_fr() {
        let r = hb::modulus(); // BN254 group order R
        let two_pow_248 = BigUint::from(1u8) << (8 * SIGMA_CHALLENGE_BYTES); // 2^248
                                                                             // (a) the injective domain sits strictly below R.
        assert!(
            &two_pow_248 < r,
            "2^248 must be < R for the challenge domain to be injective into Fr"
        );
        // (b) the largest 31-byte challenge is a canonical Fr element (< R).
        let max_challenge = &two_pow_248 - BigUint::from(1u8);
        assert!(
            &max_challenge < r,
            "the largest 31-byte challenge must be < R (canonical scalar)"
        );
        // (c) sigma_challenge_scalar is identity-on-bytes and never reduces: for any 31-byte e,
        //     from_bytes_be(e) == sigma_challenge_scalar(e) and is < 2^248 < R.
        let e_bytes = vec![0xffu8; SIGMA_CHALLENGE_BYTES];
        let e_scalar = sigma_challenge_scalar(&e_bytes);
        assert_eq!(e_scalar, BigUint::from_bytes_be(&e_bytes));
        assert!(
            e_scalar < two_pow_248,
            "a 31-byte challenge is always < 2^248"
        );
        // (d) low31 of a digest drops the top byte -> always 31 bytes / < 2^248.
        let digest = Sha256::digest(b"sigma_verify:v1 injectivity probe");
        let c = sigma_low31(&digest);
        assert_eq!(c.len(), SIGMA_CHALLENGE_BYTES);
        assert!(BigUint::from_bytes_be(c) < two_pow_248);
        // (e) the classic alias pair (e, e+R): e+R needs >= 32 bytes, so it can NEVER be a 31-byte
        //     challenge -> the two can never collide on a 31-byte value (the alias is killed).
        let e_plus_r = &max_challenge + r;
        assert!(
            e_plus_r.to_bytes_be().len() > SIGMA_CHALLENGE_BYTES,
            "e+R must not fit in 31 bytes, so it can never alias the 31-byte challenge e"
        );
    }

    // -----------------------------------------------------------------------
    // FINDING #2 (DoS): a tiny proposition + huge mismatched proof is rejected
    // by the structural bound BEFORE the recursive proof parse / curve work.
    // -----------------------------------------------------------------------
    // The BN254 G1 generator (1, 2) as a canonical 64-byte point (a valid on-curve pk).
    fn gen_pk_hex() -> String {
        format!("0x{:064x}{:064x}", 1u8, 2u8)
    }

    // A structurally-valid 31-byte challenge / 32-byte response leaf proof node.
    fn dummy_leaf_proof() -> String {
        format!(
            r#"{{"type":"dlog","e":"0x{:062x}","z":"0x{:064x}"}}"#,
            1u8, 1u8
        )
    }

    #[test]
    fn sigma_tiny_prop_huge_proof_is_rejected_fast() {
        use crate::value::decode_value;
        // Proposition: a single dlog leaf (1 node, depth 1) — what the gas layer charges for.
        let prop_json = format!(r#"{{"type":"dlog","pk":"{}"}}"#, gen_pk_hex());
        let prop_v = decode_value(&serde_json::from_str::<serde_json::Value>(&prop_json).unwrap());
        // Proof: a wide OR with 5000 children — vastly exceeds the proposition's single node.
        let child = dummy_leaf_proof();
        let children: Vec<String> = (0..5000).map(|_| child.clone()).collect();
        let huge_proof_json = format!(
            r#"{{"type":"or","e":"0x{:062x}","children":[{}]}}"#,
            1u8,
            children.join(",")
        );
        let proof_v =
            decode_value(&serde_json::from_str::<serde_json::Value>(&huge_proof_json).unwrap());
        let msg_v = Value::Str("0x6869".into());
        let res = sigma_verify(&[prop_v, proof_v, msg_v]);
        assert!(
            res.is_err(),
            "tiny proposition + huge mismatched proof must be a hard error (DoS bound), got {res:?}"
        );
        let e = res.unwrap_err();
        assert!(
            e.contains("DoS bound") || e.contains("exceeds the allowed structure"),
            "must be rejected by the structural DoS bound, got: {e}"
        );
    }

    #[test]
    fn sigma_deeply_nested_proof_is_rejected_by_depth_cap() {
        use crate::value::decode_value;
        // Proposition: a single dlog leaf (depth 1) -> the proof's allowed depth bound is 1.
        let prop_json = format!(r#"{{"type":"dlog","pk":"{}"}}"#, gen_pk_hex());
        let prop_v = decode_value(&serde_json::from_str::<serde_json::Value>(&prop_json).unwrap());
        // Nest 8 AND nodes around a leaf -> depth 9, far beyond the proposition's depth of 1
        // (and well within serde_json's parse recursion limit). Rejected by the depth bound.
        let mut nested = dummy_leaf_proof();
        for _ in 0..8 {
            nested = format!(
                r#"{{"type":"and","e":"0x{:062x}","children":[{nested}]}}"#,
                1u8
            );
        }
        let proof_v = decode_value(&serde_json::from_str::<serde_json::Value>(&nested).unwrap());
        let msg_v = Value::Str("0x6869".into());
        let res = sigma_verify(&[prop_v, proof_v, msg_v]);
        assert!(
            res.is_err(),
            "deeply-nested proof beyond the proposition depth must be a hard error (DoS depth cap)"
        );
        assert!(
            res.unwrap_err().contains("exceeds the allowed structure"),
            "must be rejected by the structural DoS bound"
        );
    }
}
