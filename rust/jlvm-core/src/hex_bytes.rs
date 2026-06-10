//! Shared hex-encoding codec for the JLVM crypto opcodes.
//!
//! Byte-for-byte port of the Scala
//! `io.constellationnetwork.metagraph_sdk.json_logic.ops.HexBytes`.
//!
//! Convention (implemented exactly):
//!   - All byte / field arguments and returns are lowercase, `0x`-prefixed,
//!     big-endian hex strings.
//!   - There is NO new JLVM value type; bytes are a validated special-case of
//!     `Str`, parsed and validated only at the opcode boundary.
//!   - Every malformed input (bad hex, wrong width, non-canonical field element,
//!     ...) returns an `Err(String)` -- this codec NEVER panics to the caller.
//!
//! Validation rules:
//!   - The string must match `^0x[0-9a-f]*$` (lowercase only, `0x` prefix
//!     mandatory, hex body may be empty for arbitrary-width byte args).
//!   - The hex body must have even length (whole bytes).
//!   - When an expected byte width is supplied, the decoded length must equal it.
//!   - Field elements ([`parse_fr`]) are exactly 32 bytes AND must be canonical,
//!     i.e. the big-endian value is strictly `< R` (the BN254 / alt_bn128 scalar
//!     field modulus). Non-canonical 32-byte values are rejected.

use num_bigint::BigUint;
use num_traits::Zero;
use std::sync::OnceLock;

/// Byte width of a BN254 Fr field element.
pub const FR_BYTES: usize = 32;

/// Byte width of a single BN254 (alt_bn128) base-field coordinate.
pub const FQ_BYTES: usize = 32;

/// Byte width of a serialized BN254 G1 point (`x || y`, 32B each).
pub const G1_BYTES: usize = 64;

/// Byte width of a 256-bit big-endian scalar (e.g. a Schnorr response `s`).
pub const SCALAR_BYTES: usize = 32;

/// The BN254 / alt_bn128 scalar field modulus R (shared with `Poseidon.R`).
pub fn modulus() -> &'static BigUint {
    poseidon_bn254::modulus()
}

/// The BN254 / alt_bn128 base-field (Fp) modulus P.
pub fn base_field_modulus() -> &'static BigUint {
    static P: OnceLock<BigUint> = OnceLock::new();
    P.get_or_init(|| {
        BigUint::parse_bytes(
            b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .expect("valid BN254 Fp modulus")
    })
}

/// Lowercase-hex / `0x`-prefix validation: `^0x[0-9a-f]*$`.
fn is_valid_hex(hex: &str) -> bool {
    match hex.strip_prefix("0x") {
        Some(body) => body
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        None => false,
    }
}

/// Parse and validate a lowercase `0x`-prefixed hex string into raw bytes
/// (big-endian).
///
/// * `expected_len` -- if `Some(n)`, the decoded byte length must equal `n`; if
///   `None`, any even-length body is accepted (arbitrary-width bytes).
/// * `role` -- human-readable name of the argument, used only in error messages.
pub fn parse_bytes(hex: &str, expected_len: Option<usize>, role: &str) -> Result<Vec<u8>, String> {
    if !is_valid_hex(hex) {
        return Err(format!(
            "{role}: malformed hex (expected lowercase ^0x[0-9a-f]*$): '{hex}'"
        ));
    }
    let body = &hex[2..];
    // Mirrors Scala's `body.length % 2 == 0` check (even-length = whole bytes).
    #[allow(clippy::manual_is_multiple_of)]
    if body.len() % 2 != 0 {
        return Err(format!(
            "{role}: odd-length hex body ({} nibbles): '{hex}'",
            body.len()
        ));
    }
    let bytes = decode_unchecked(body);
    if let Some(n) = expected_len {
        if bytes.len() != n {
            return Err(format!("{role}: expected {n} bytes, got {}", bytes.len()));
        }
    }
    Ok(bytes)
}

/// Parse a 32-byte hex string into a canonical BN254 Fr field element
/// (`0 <= value < R`). Rejects wrong width and non-canonical values.
pub fn parse_fr(hex: &str, role: &str) -> Result<BigUint, String> {
    let bytes = parse_bytes(hex, Some(FR_BYTES), role)?;
    let value = BigUint::from_bytes_be(&bytes);
    if &value < modulus() {
        Ok(value)
    } else {
        Err(format!(
            "{role}: not a canonical BN254 field element (must be < modulus): {value}"
        ))
    }
}

/// Parse a 64-byte hex string into a BN254 G1 affine coordinate pair `(x, y)`.
/// Each 32-byte half is validated as a canonical Fq element (`< P`). The
/// all-zero point `(0, 0)` is the EVM point-at-infinity and is accepted here;
/// on-curve membership is enforced by the caller.
pub fn parse_g1(hex: &str, role: &str) -> Result<(BigUint, BigUint), String> {
    let bytes = parse_bytes(hex, Some(G1_BYTES), role)?;
    let x = BigUint::from_bytes_be(&bytes[0..FQ_BYTES]);
    let y = BigUint::from_bytes_be(&bytes[FQ_BYTES..G1_BYTES]);
    let p = base_field_modulus();
    if &x >= p {
        return Err(format!("{role}: x not in base field (>= P): {x}"));
    }
    if &y >= p {
        return Err(format!("{role}: y not in base field (>= P): {y}"));
    }
    Ok((x, y))
}

/// Parse a 32-byte hex string into a non-negative big-endian scalar with NO
/// field-canonicity constraint (any 256-bit value is accepted). Used for
/// Schnorr responses and similar values that are reduced mod the group order
/// by the consuming primitive.
pub fn parse_scalar(hex: &str, role: &str) -> Result<BigUint, String> {
    let bytes = parse_bytes(hex, Some(SCALAR_BYTES), role)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Encode raw bytes as a lowercase `0x`-prefixed hex string (exactly
/// `bytes.len()` bytes wide).
pub fn encode_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Encode a non-negative big integer as a `0x`-prefixed, big-endian,
/// zero-padded hex of `width` bytes. Errors if it does not fit.
pub fn encode_uint(value: &BigUint, width: usize, role: &str) -> Result<String, String> {
    let raw = if value.is_zero() {
        String::from("0")
    } else {
        value.to_str_radix(16)
    };
    if raw.len() > width * 2 {
        return Err(format!(
            "{role}: value {value} does not fit in {width} bytes"
        ));
    }
    let padded = format!("{:0>width$}", raw, width = width * 2);
    Ok(format!("0x{padded}"))
}

/// Encode a canonical Fr element as a 32-byte `0x`-prefixed hex string.
pub fn encode_fr(value: &BigUint) -> Result<String, String> {
    encode_uint(value, FR_BYTES, "encodeFr")
}

/// Encode a BN254 G1 point `(x, y)` as a 64-byte `0x`-hex string
/// (`x || y`, 32B each).
pub fn encode_g1(x: &BigUint, y: &BigUint) -> Result<String, String> {
    let xs = encode_uint(x, FQ_BYTES, "encodeG1.x")?;
    let ys = encode_uint(y, FQ_BYTES, "encodeG1.y")?;
    Ok(format!("0x{}{}", &xs[2..], &ys[2..]))
}

// Body is guaranteed even-length and all `[0-9a-f]` by the time this is called.
fn decode_unchecked(body: &str) -> Vec<u8> {
    (0..body.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&body[i..i + 2], 16).expect("validated hex"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_uppercase_and_missing_prefix() {
        assert!(parse_bytes("0xAB", None, "t").is_err());
        assert!(parse_bytes("ab", None, "t").is_err());
        assert!(parse_bytes("0xabc", None, "t").is_err()); // odd
        assert!(parse_bytes("0xabcd", None, "t").is_ok());
    }

    #[test]
    fn fr_canonicity() {
        // R itself is non-canonical.
        let r_hex = encode_uint(modulus(), 32, "r").unwrap();
        assert!(parse_fr(&r_hex, "fr").is_err());
        // R - 1 is canonical.
        let r_minus_1 = modulus() - 1u32;
        let h = encode_uint(&r_minus_1, 32, "r").unwrap();
        assert_eq!(parse_fr(&h, "fr").unwrap(), r_minus_1);
    }

    #[test]
    fn encode_roundtrip() {
        let v = BigUint::from(0x115cc0f5u64);
        let h = encode_fr(&v).unwrap();
        assert_eq!(h.len(), 66);
        assert_eq!(parse_fr(&h, "fr").unwrap(), v);
    }
}
