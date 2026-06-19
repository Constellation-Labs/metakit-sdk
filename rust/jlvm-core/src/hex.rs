//! The `hex_to_int` opcode.
//!
//! Parses a `0x`-prefixed, lowercase, big-endian hex string into raw bytes
//! (reusing the shared crypto [`crate::hex_bytes::parse_bytes`] codec) and
//! interprets those bytes as an UNSIGNED big-endian integer, returning an
//! arbitrary-precision [`Value::Int`]. Byte-for-byte aligned with the Scala
//! `json_logic.ops` `hex_to_int` and the TypeScript `hex-ops.ts`.
//!
//! The result is ALWAYS non-negative. Whatever the reused parser accepts
//! (`0x` prefix, lowercase, even-length body) is inherited; an empty body
//! (`"0x"`) decodes to zero. Malformed hex (odd-length body, non-hex chars)
//! and a non-string / wrong-arity argument propagate as the standard
//! `Err(String)` opcode error.

use crate::hex_bytes as hb;
use crate::value::Value;
use num_bigint::{BigInt, Sign};

/// `hex_to_int`: arity-1, string-only. Reuses the arbitrary-width hex byte
/// parser (the same one `ecvrf_verify`'s alpha arg uses) and folds the bytes
/// big-endian into a non-negative `BigInt`.
pub fn hex_to_int(values: &[Value]) -> Result<Value, String> {
    match values {
        [hex_v] => {
            let hex = match hex_v {
                Value::Str(s) => s.as_str(),
                other => {
                    return Err(format!(
                        "hex_to_int: expected a hex string, got {}",
                        other.tag()
                    ))
                }
            };
            let bytes = hb::parse_bytes(hex, None, "hex_to_int")?;
            // Unsigned big-endian: empty bytes -> 0; Sign::Plus keeps it non-negative.
            Ok(Value::Int(BigInt::from_bytes_be(Sign::Plus, &bytes)))
        }
        _ => Err(format!(
            "hex_to_int: expected exactly one hex-string argument, got {values:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::pow::Pow;

    fn run(hex: &str) -> Result<BigInt, String> {
        match hex_to_int(&[Value::Str(hex.to_string())])? {
            Value::Int(i) => Ok(i),
            other => panic!("hex_to_int returned a non-int: {other:?}"),
        }
    }

    #[test]
    fn canonical_conformance_vectors() {
        assert_eq!(run("0x").unwrap(), BigInt::from(0));
        assert_eq!(run("0x00").unwrap(), BigInt::from(0));
        assert_eq!(run("0xff").unwrap(), BigInt::from(255));
        assert_eq!(run("0x0100").unwrap(), BigInt::from(256));
        assert_eq!(run("0x00ff").unwrap(), BigInt::from(255));
        assert_eq!(run("0xdeadbeef").unwrap(), BigInt::from(3_735_928_559u64));
        // 2^64 - 1 (proves the result exceeds i64 / f64 exact range).
        assert_eq!(
            run("0xffffffffffffffff").unwrap(),
            BigInt::from(18_446_744_073_709_551_615u64)
        );
        // 2^64.
        assert_eq!(
            run("0x010000000000000000").unwrap(),
            BigInt::from(2).pow(64u32)
        );
        // 64-byte all-ones -> 2^512 - 1. Express the bound, do not transcribe it.
        let all_ones = format!("0x{}", "f".repeat(128));
        assert_eq!(run(&all_ones).unwrap(), BigInt::from(2).pow(512u32) - 1);
    }

    #[test]
    fn result_is_always_non_negative() {
        use num_traits::Signed;
        assert!(!run("0xffffffffffffffff").unwrap().is_negative());
        assert!(!run("0x80").unwrap().is_negative()); // high bit set -> still +128
        assert_eq!(run("0x80").unwrap(), BigInt::from(128));
    }

    #[test]
    fn error_vectors() {
        assert!(run("0xfff").is_err()); // odd-length body
        assert!(run("0xzz").is_err()); // non-hex chars
        assert!(run("0xAB").is_err()); // uppercase rejected by the shared codec
        assert!(run("ab").is_err()); // missing 0x prefix

        // Non-string argument.
        assert!(hex_to_int(&[Value::Int(BigInt::from(5))]).is_err());
        // Wrong arity.
        assert!(hex_to_int(&[]).is_err());
        assert!(hex_to_int(&[Value::Str("0x00".into()), Value::Str("0x01".into())]).is_err());
    }
}
