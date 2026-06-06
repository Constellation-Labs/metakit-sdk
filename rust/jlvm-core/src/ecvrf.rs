//! `ecvrf_verify`: ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381).
//!
//! Byte-for-byte PORT of the Scala
//! `io.constellationnetwork.metagraph_sdk.crypto.vrf.MiraclEcVrf25519`. Both
//! conform to the published RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI ciphersuite
//! and are anchored on the OFFICIAL RFC 9381 Appendix B.3 test vectors
//! (Examples 16, 17, 18): the generated proofs (pi) match those vectors
//! byte-for-byte.
//!
//! No third-party Rust VRF crate matches this exact ciphersuite: the public
//! crates implement either the batch-friendly ELL2 variant (suite 0x04) or an
//! older draft without the `zero_string` (0x00) suffix in hash_to_curve /
//! hash_points / proof_to_hash. So we port the Scala directly, using
//! `curve25519-dalek` only for the group/scalar arithmetic and the RFC 8032
//! little-endian point codec (`CompressedEdwardsY`). Every domain separator,
//! suffix, truncation and rejection rule is reproduced from the Scala
//! line-for-line; the RFC 9381 Appendix B.3 vectors are the anchor and are
//! asserted byte-for-byte (both verify AND generate) in the unit tests.
//!
//! Suite parameters (mirroring the Scala object constants):
//!   - suite_string = 0x03
//!   - EC group G = Ed25519 (RFC 8032), cofactor = 8
//!   - qLen = 32, ptLen = 32, n = 16 (c is 16 bytes), hLen = 64
//!   - Hash = SHA-512
//!   - hash_to_curve = try_and_increment (RFC 9381 §5.4.1.1)
//!   - nonce = ECVRF_nonce_generation_RFC8032 (§5.4.2.2)
//!   - challenge = ECVRF_challenge_generation (§5.4.3): hashes FIVE points with
//!     the public key Y first: suite||0x02||Y||H||Gamma||U||V||0x00
//!   - zero_string (0x00) suffix in hash_to_curve / hash_points / proof_to_hash
//!
//! Proof format: 80 bytes = Gamma(32) || c(16) || s(32), all LE.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

/// suite_string = 0x03 (ECVRF-EDWARDS25519-SHA512-TAI).
const SUITE_STRING: u8 = 0x03;
/// Encoded point length (ptLen = qLen = 32).
pub const POINT_BYTES: usize = 32;
/// Scalar length (qLen = 32).
pub const SCALAR_BYTES: usize = 32;
/// Challenge length (n = 16 for Ed25519).
const C_BYTES: usize = 16;
/// Proof length: Gamma(32) || c(16) || s(32) = 80 bytes.
pub const PROOF_BYTES: usize = POINT_BYTES + C_BYTES + SCALAR_BYTES;

/// Ed25519 field prime p = 2^255 - 19, little-endian (32 bytes). Used to reject
/// non-canonical y encodings (`y >= p`), matching the Scala strict decoder.
const FIELD_MODULUS_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, //
];

// ===========================================================================
// Public verifier surface (mirrors MiraclEcVrf25519.vrfVerify / vrfProofToHash).
// ===========================================================================

/// Verify a VRF proof. `public_key` is 32 bytes, `proof` is 80 bytes.
///
/// Mirrors `MiraclEcVrf25519.vrfVerify`: any structural failure (bad length,
/// undecodable point, non-canonical scalar) yields `false` (NOT an error -- the
/// opcode boundary in `CryptoOps` does the width checks and surfaces width
/// errors; a well-formed-but-wrong proof simply verifies to `false`).
pub fn vrf_verify(public_key: &[u8], message: &[u8], proof: &[u8]) -> bool {
    if public_key.len() != POINT_BYTES || proof.len() != PROOF_BYTES {
        return false;
    }
    let y_point = match bytes_to_point(public_key) {
        Some(p) => p,
        None => return false,
    };
    let (gamma_point, c, s) = match decode_proof(proof) {
        Some(t) => t,
        None => return false,
    };
    // H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    let h_point = match hash_to_curve(public_key, message) {
        Some(h) => h,
        None => return false,
    };
    // U = [s]*B - [c]*Y
    let u_point = basepoint_mul(&s) - point_mul(&y_point, &c);
    // V = [s]*H - [c]*Gamma
    let v_point = point_mul(&h_point, &s) - point_mul(&gamma_point, &c);
    // c' = ECVRF_challenge_generation(Y, H, Gamma, U, V) (RFC 9381 §5.4.3);
    // valid iff c == c' on the first 16 little-endian bytes.
    let c_prime = hash_points(&y_point, &h_point, &gamma_point, &u_point, &v_point);
    scalar_equals_16(&c, &c_prime)
}

/// Extract the VRF output hash (beta) from an 80-byte proof, or `None`.
///
/// Mirrors `MiraclEcVrf25519.vrfProofToHash`:
///   beta = SHA-512(suite_string || 0x03 || point_to_string([cofactor]*Gamma) || 0x00)
pub fn vrf_proof_to_hash(proof: &[u8]) -> Option<Vec<u8>> {
    if proof.len() != PROOF_BYTES {
        return None;
    }
    let gamma_point = bytes_to_point(&proof[0..POINT_BYTES])?;
    // [8]*Gamma
    let cofactor_gamma = gamma_point.mul_by_cofactor();
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING]);
    hasher.update([0x03u8]);
    hasher.update(point_to_bytes(&cofactor_gamma));
    hasher.update([0x00u8]);
    Some(hasher.finalize().to_vec())
}

/// Derive the Ed25519 public key from a 32-byte secret seed.
///
/// Mirrors `MiraclEcVrf25519.getVerificationKey`.
pub fn get_verification_key(secret_key: &[u8]) -> Option<[u8; POINT_BYTES]> {
    if secret_key.len() != 32 {
        return None;
    }
    let hashed_sk = Sha512::digest(secret_key);
    let x = clamped_scalar(&hashed_sk[0..32]);
    Some(point_to_bytes(&basepoint_mul(&x)))
}

/// Generate an 80-byte VRF proof (Gamma || c || s) for a 32-byte secret seed.
///
/// Mirrors `MiraclEcVrf25519.vrfProof` and conforms to RFC 9381 §5.4.3
/// (5-point ECVRF_challenge_generation with the public key Y hashed first).
/// Returns `None` only on a bad key length or a hash-to-curve failure.
pub fn vrf_prove(secret_key: &[u8], message: &[u8]) -> Option<[u8; PROOF_BYTES]> {
    if secret_key.len() != 32 {
        return None;
    }
    // 1. Derive x (secret scalar) and Y (public key) per RFC 8032 §5.1.5.
    let hashed_sk = Sha512::digest(secret_key);
    let x = clamped_scalar(&hashed_sk[0..32]);
    let y_point = basepoint_mul(&x);
    let y_bytes = point_to_bytes(&y_point);

    // 2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string).
    let h_point = hash_to_curve(&y_bytes, message)?;
    let h_bytes = point_to_bytes(&h_point);

    // 3. Gamma = [x]*H.
    let gamma_point = point_mul(&h_point, &x);

    // 4. k = ECVRF_nonce_generation_RFC8032(SK, h_string).
    let k = nonce_generation(&hashed_sk, &h_bytes);

    // 5. c = ECVRF_challenge_generation(Y, H, Gamma, [k]*B, [k]*H) (§5.4.3).
    let k_b = basepoint_mul(&k);
    let k_h = point_mul(&h_point, &k);
    let c = hash_points(&y_point, &h_point, &gamma_point, &k_b, &k_h);

    // 6. s = (k + c*x) mod L.
    let s = k + c * x;

    // 7. pi = point_to_string(Gamma) || int_to_string(c, 16) || int_to_string(s, 32).
    let mut proof = [0u8; PROOF_BYTES];
    proof[0..POINT_BYTES].copy_from_slice(&point_to_bytes(&gamma_point));
    proof[POINT_BYTES..POINT_BYTES + C_BYTES].copy_from_slice(&scalar_to_le_bytes(&c)[0..C_BYTES]);
    proof[POINT_BYTES + C_BYTES..PROOF_BYTES].copy_from_slice(&scalar_to_le_bytes(&s));
    Some(proof)
}

// ===========================================================================
// RFC 8032 point encode / decode (the compatibility-critical part).
// ===========================================================================

/// point_to_string: 32-byte little-endian y with x's LSB in bit 255.
///
/// `CompressedEdwardsY` IS exactly this RFC 8032 encoding. The identity (y = 1,
/// x = 0) compresses to `0x01` followed by zeros, matching the Scala special
/// case for `is_infinity`.
fn point_to_bytes(point: &EdwardsPoint) -> [u8; POINT_BYTES] {
    point.compress().to_bytes()
}

/// string_to_point: parse y (LE, bit 255 = x sign), recover the point.
///
/// Adds the Scala's strict rejections on top of dalek's `decompress`:
///   - reject `y >= p` (non-canonical encoding); dalek does NOT do this.
///   - reject the identity / infinity result.
///
/// dalek already enforces the QR existence and the sign selection (including the
/// `x == 0 && sign == 1` rejection), exactly like the Scala.
fn bytes_to_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    if bytes.len() != POINT_BYTES {
        return None;
    }
    // Reject y >= p (clear the sign bit first, compare the 255-bit y LE).
    let mut y = [0u8; POINT_BYTES];
    y.copy_from_slice(bytes);
    y[31] &= 0x7f;
    if !le_lt(&y, &FIELD_MODULUS_LE) {
        return None;
    }
    let mut buf = [0u8; POINT_BYTES];
    buf.copy_from_slice(bytes);
    let point = CompressedEdwardsY(buf).decompress()?;
    if point == EdwardsPoint::identity() {
        None
    } else {
        Some(point)
    }
}

/// Lexicographic little-endian `a < b` for fixed-width 32-byte arrays.
fn le_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

// ===========================================================================
// Scalar arithmetic (mod L), little-endian on the wire.
// ===========================================================================

/// [e]*B (basepoint mul).
fn basepoint_mul(e: &Scalar) -> EdwardsPoint {
    EdwardsPoint::mul_base(e)
}

/// [e]*P (variable-base mul).
fn point_mul(p: &EdwardsPoint, e: &Scalar) -> EdwardsPoint {
    p * e
}

/// Compare two challenge scalars on their first 16 little-endian bytes.
fn scalar_equals_16(a: &Scalar, b: &Scalar) -> bool {
    a.as_bytes()[0..C_BYTES] == b.as_bytes()[0..C_BYTES]
}

/// Build a canonical scalar from up to 32 little-endian bytes WITHOUT reduction.
///
/// Mirrors the Scala `bigFromLe` followed by canonical-scalar handling: the
/// caller guarantees the value is `< L` (decode_proof rejects `s >= L`; the
/// 16-byte challenge `c < 2^128 < L`). Returns `None` if the value is `>= L`
/// (non-canonical), matching the Scala's `BIG.comp(_, order) >= 0` rejection.
fn scalar_from_le_canonical(le: &[u8]) -> Option<Scalar> {
    let mut buf = [0u8; 32];
    buf[..le.len()].copy_from_slice(le);
    // `from_canonical_bytes` returns None iff buf encodes a value >= L.
    Option::<Scalar>::from(Scalar::from_canonical_bytes(buf))
}

/// Build a scalar from a 16-byte little-endian challenge (always `< 2^128 < L`,
/// so always canonical).
fn scalar_from_c16(le16: &[u8]) -> Scalar {
    let mut buf = [0u8; 32];
    buf[..C_BYTES].copy_from_slice(&le16[..C_BYTES]);
    // Always canonical (< 2^128 < L); unwrap is safe.
    Option::<Scalar>::from(Scalar::from_canonical_bytes(buf))
        .expect("16-byte LE challenge is always < L")
}

/// Serialize a scalar as 32 little-endian bytes (curve25519-dalek's canonical
/// encoding). Mirrors the Scala `scalarToLeBytes(_, 32)`.
fn scalar_to_le_bytes(s: &Scalar) -> [u8; SCALAR_BYTES] {
    s.to_bytes()
}

/// RFC 8032 clamp on the low 32 bytes of SHA-512(seed), reduced mod L. Mirrors
/// the Scala `clampedScalar`: clear bottom 3 bits, clear top bit, set
/// second-highest bit, then reduce mod L.
fn clamped_scalar(low32: &[u8]) -> Scalar {
    let mut pruned = [0u8; 32];
    pruned.copy_from_slice(&low32[..32]);
    pruned[0] &= 0xf8;
    pruned[31] &= 0x7f;
    pruned[31] |= 0x40;
    Scalar::from_bytes_mod_order(pruned)
}

/// k = string_to_int(SHA-512(...)) mod L from a 64-byte little-endian input.
/// Mirrors the Scala `reduceWideLe`.
fn reduce_wide_le(wide64: &[u8]) -> Scalar {
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&wide64[..64]);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// k = ECVRF_nonce_generation_RFC8032(SK, h_string) (RFC 9381 §5.4.2.2):
/// SHA-512(hashed_sk[32..64] || h_string) mod L. Mirrors the Scala
/// `nonceGeneration`.
fn nonce_generation(hashed_sk: &[u8], h_bytes: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(&hashed_sk[32..64]);
    hasher.update(h_bytes);
    reduce_wide_le(&hasher.finalize())
}

// ===========================================================================
// ECVRF helpers (mirror the Scala exactly).
// ===========================================================================

/// hash_to_curve = try_and_increment (RFC 9381 §5.4.1.1, draft-10).
///
///   for ctr in 0..256:
///     hash = SHA-512(suite || 0x01 || pk || alpha || ctr || 0x00)
///     P    = string_to_point(hash[0..32])
///     if P decodes AND point_to_string(P) is not all-zero:
///       return [8]*P   (clear cofactor)
fn hash_to_curve(public_key: &[u8], alpha: &[u8]) -> Option<EdwardsPoint> {
    for ctr in 0u16..256 {
        let mut hasher = Sha512::new();
        hasher.update([SUITE_STRING]);
        hasher.update([0x01u8]); // one_string
        hasher.update(public_key);
        hasher.update(alpha);
        hasher.update([ctr as u8]); // ctr_string
        hasher.update([0x00u8]); // zero_string (draft-10)
        let hash = hasher.finalize();
        if let Some(point) = bytes_to_point(&hash[0..32]) {
            // Scala also guards against an all-zero point encoding; bytes_to_point
            // already rejects the identity, but keep the explicit check to mirror
            // the reference exactly.
            if point_to_bytes(&point).iter().any(|&b| b != 0) {
                return Some(point.mul_by_cofactor());
            }
        }
    }
    None
}

/// ECVRF_challenge_generation (RFC 9381 §5.4.3): hashes FIVE points with the
/// public key Y first.
///
/// c = SHA-512(suite || 0x02 || Y || H || Gamma || U || V || 0x00)[0..15] as a LE int.
fn hash_points(
    y: &EdwardsPoint,
    h: &EdwardsPoint,
    gamma: &EdwardsPoint,
    u: &EdwardsPoint,
    v: &EdwardsPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING]);
    hasher.update([0x02u8]);
    hasher.update(point_to_bytes(y));
    hasher.update(point_to_bytes(h));
    hasher.update(point_to_bytes(gamma));
    hasher.update(point_to_bytes(u));
    hasher.update(point_to_bytes(v));
    hasher.update([0x00u8]);
    let hash = hasher.finalize();
    // First 16 bytes as a little-endian integer (< 2^128 < L).
    scalar_from_c16(&hash[0..C_BYTES])
}

/// Decode an 80-byte proof into (Gamma, c, s). `s` must be a canonical scalar
/// (`< L`); `c` is the 16-byte LE challenge. Mirrors the Scala `decodeProof`.
fn decode_proof(proof: &[u8]) -> Option<(EdwardsPoint, Scalar, Scalar)> {
    if proof.len() != PROOF_BYTES {
        return None;
    }
    let gamma_point = bytes_to_point(&proof[0..POINT_BYTES])?;
    let c = scalar_from_c16(&proof[POINT_BYTES..POINT_BYTES + C_BYTES]);
    // s must be canonical (< L) for a valid proof.
    let s = scalar_from_le_canonical(&proof[POINT_BYTES + C_BYTES..PROOF_BYTES])?;
    Some((gamma_point, c, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Full RFC 9381 Appendix B.3 (ECVRF-EDWARDS25519-SHA512-TAI) conformance for
    /// one example: derive the public key, GENERATE the proof and confirm it is
    /// byte-identical to the published pi (the hard proof of RFC conformance),
    /// verify the published pi, and confirm proof_to_hash(pi) == the published
    /// beta.
    fn check_rfc_example(
        sk_hex: &str,
        pk_hex: &str,
        alpha_hex: &str,
        pi_hex: &str,
        beta_hex: &str,
    ) {
        let sk = hx(sk_hex);
        let pk = hx(pk_hex);
        let alpha = hx(alpha_hex);
        let pi = hx(pi_hex);

        // Public key derivation.
        let vk = get_verification_key(&sk).expect("key derivation");
        assert_eq!(hex_of(&vk), pk_hex, "verification key must match RFC PK");

        // GENERATE: produced pi must equal the official published pi byte-for-byte.
        let produced = vrf_prove(&sk, &alpha).expect("prove");
        assert_eq!(
            hex_of(&produced),
            pi_hex,
            "generated pi must be byte-identical to the RFC 9381 published pi"
        );

        // VERIFY the published pi.
        assert!(
            vrf_verify(&pk, &alpha, &pi),
            "RFC 9381 published pi must verify"
        );

        // beta = proof_to_hash(pi).
        let beta = vrf_proof_to_hash(&pi).expect("valid proof yields beta");
        assert_eq!(
            hex_of(&beta),
            beta_hex,
            "beta must match RFC 9381 published beta"
        );
    }

    /// RFC 9381 Appendix B.3 Example 16 (empty message).
    #[test]
    fn rfc9381_tai_example16() {
        check_rfc_example(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        );
    }

    /// RFC 9381 Appendix B.3 Example 17 (one-byte message). The hard anchor.
    #[test]
    fn rfc9381_tai_example17() {
        check_rfc_example(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        );
    }

    /// RFC 9381 Appendix B.3 Example 18 (two-byte message).
    #[test]
    fn rfc9381_tai_example18() {
        check_rfc_example(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        );
    }

    /// Tampered gamma (first proof byte flipped) ⇒ invalid. Derived from the
    /// official RFC 9381 Example 17 pi.
    #[test]
    fn tampered_gamma_invalid() {
        let pk = hx("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let alpha = hx("72");
        let proof = hx("0c141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02");
        assert!(!vrf_verify(&pk, &alpha, &proof));
    }

    /// Tampered scalar s (last proof byte flipped) ⇒ invalid. Derived from the
    /// official RFC 9381 Example 17 pi.
    #[test]
    fn tampered_s_invalid() {
        let pk = hx("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let alpha = hx("72");
        let proof = hx("f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b03");
        assert!(!vrf_verify(&pk, &alpha, &proof));
    }

    /// Roundtrip on a non-RFC key: prove then verify.
    #[test]
    fn prove_then_verify_roundtrip() {
        let sk = hx("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
        let msg = hx("48656c6c6f2c20565246210a"); // "Hello, VRF!\n"
        let vk = get_verification_key(&sk).unwrap();
        let pi = vrf_prove(&sk, &msg).unwrap();
        assert!(vrf_verify(&vk, &msg, &pi));
        // Wrong message must fail.
        assert!(!vrf_verify(&vk, &hx("00"), &pi));
    }
}
