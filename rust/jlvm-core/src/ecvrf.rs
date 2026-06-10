//! `ecvrf_verify`: ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 suite 0x03).
//!
//! Byte-for-byte PORT of the Scala
//! `io.constellationnetwork.metagraph_sdk.crypto.vrf.MiraclEcVrf25519`, which is
//! itself byte-identical to tessellation-nakamoto's elisabeth-based
//! `EcVrf25519` and to the RFC 9381 Appendix B.1 known-answer vectors.
//!
//! No third-party Rust VRF crate matches this exact ciphersuite: the public
//! crates implement either the batch-friendly ELL2 variant (suite 0x04) or an
//! older draft without the draft-10 `zero_string` (0x00) suffix in
//! hash_to_curve / hash_points / proof_to_hash. So we port the Scala directly,
//! using `curve25519-dalek` only for the group/scalar arithmetic and the
//! RFC 8032 little-endian point codec (`CompressedEdwardsY`). Every domain
//! separator, suffix, truncation and rejection rule is reproduced from the
//! Scala line-for-line; the RFC 9381 vector (pk `3d40..`, alpha `72`, beta
//! `eb44..`) is the anchor and is asserted in the unit tests.
//!
//! Suite parameters (mirroring the Scala object constants):
//!   - suite_string = 0x03
//!   - EC group G = Ed25519 (RFC 8032), cofactor = 8
//!   - qLen = 32, ptLen = 32, n = 16 (c is 16 bytes), hLen = 64
//!   - Hash = SHA-512
//!   - hash_to_curve = try_and_increment (RFC 9381 §5.4.1.1)
//!   - nonce = ECVRF_nonce_generation_RFC8032 (§5.4.2.2)
//!   - draft-10 zero_string (0x00) suffix in hash_to_curve / hash_points /
//!     proof_to_hash
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
    // c' = ECVRF_hash_points(H, Gamma, U, V); valid iff c == c' on the first 16
    // little-endian bytes.
    let c_prime = hash_points(&h_point, &gamma_point, &u_point, &v_point);
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

// NOTE: the proving-side `reduce_wide_le` (k = SHA-512(...) mod L) and
// `nonce_generation` are intentionally omitted -- verification never derives the
// nonce. This module is a verifier-only port of `MiraclEcVrf25519`.

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

/// c = SHA-512(suite || 0x02 || P1 || P2 || P3 || P4 || 0x00)[0..15] as a LE int.
fn hash_points(
    p1: &EdwardsPoint,
    p2: &EdwardsPoint,
    p3: &EdwardsPoint,
    p4: &EdwardsPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING]);
    hasher.update([0x02u8]);
    hasher.update(point_to_bytes(p1));
    hasher.update(point_to_bytes(p2));
    hasher.update(point_to_bytes(p3));
    hasher.update(point_to_bytes(p4));
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

    /// RFC 9381 Appendix B.1, ECVRF-EDWARDS25519-SHA512-TAI test vector 2
    /// (also the strengthened shared vector). This is the hard anchor.
    #[test]
    fn rfc9381_tai_vector2() {
        let pk = hx("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let alpha = hx("72");
        let proof = hx("f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593f7eaf3eb2f1a968cba3f6e23b386aeeaab7b1ea44a256e811892e13eeae7c9f6ea8992557453eac11c4d5476b1f35a08");
        assert!(
            vrf_verify(&pk, &alpha, &proof),
            "RFC 9381 TAI vector 2 must verify"
        );
        let beta = vrf_proof_to_hash(&proof).expect("valid proof yields beta");
        assert_eq!(
            hex_of(&beta),
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"
        );
    }

    /// RFC 9381 Appendix B.1 test vector 1 (empty message).
    #[test]
    fn rfc9381_tai_vector1() {
        let pk = hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let alpha: Vec<u8> = vec![];
        let proof = hx("8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f5e8bd1839b414219e8626d393787a192241fc442e6569e96c462f62b8079b9ed83ff2ee21c90c7c398802fdeebea4001");
        assert!(vrf_verify(&pk, &alpha, &proof));
        let beta = vrf_proof_to_hash(&proof).unwrap();
        assert_eq!(
            hex_of(&beta),
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
        );
    }

    /// RFC 9381 Appendix B.1 test vector 3 (two-byte message).
    #[test]
    fn rfc9381_tai_vector3() {
        let pk = hx("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let alpha = hx("af82");
        let proof = hx("9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80e29dc513c01c3a980e0e545bcd848222d08a6c3e3665ff5a4cab13a643bef812e284c6b2ee063a2cb4f456794723ad0a");
        assert!(vrf_verify(&pk, &alpha, &proof));
        let beta = vrf_proof_to_hash(&proof).unwrap();
        assert_eq!(
            hex_of(&beta),
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"
        );
    }

    /// Tampered gamma (first proof byte flipped) ⇒ invalid.
    #[test]
    fn tampered_gamma_invalid() {
        let pk = hx("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let alpha = hx("72");
        let proof = hx("0c141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593f7eaf3eb2f1a968cba3f6e23b386aeeaab7b1ea44a256e811892e13eeae7c9f6ea8992557453eac11c4d5476b1f35a08");
        assert!(!vrf_verify(&pk, &alpha, &proof));
    }

    /// Tampered scalar s (last proof byte flipped) ⇒ invalid.
    #[test]
    fn tampered_s_invalid() {
        let pk = hx("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let alpha = hx("72");
        let proof = hx("f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593f7eaf3eb2f1a968cba3f6e23b386aeeaab7b1ea44a256e811892e13eeae7c9f6ea8992557453eac11c4d5476b1f35a09");
        assert!(!vrf_verify(&pk, &alpha, &proof));
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
