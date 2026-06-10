//! RFC 8785 (JCS) canonical JSON serialization for JLVM values.
//!
//! This is the byte-for-byte interop boundary. It mirrors metakit's
//! `std.JsonCanonicalizer`:
//!   * Object keys are sorted by their UTF-16 code units (the JCS rule).
//!   * Strings use the JCS escaping set (\n \b \f \r \t \" \\, and \u00XX for the
//!     remaining C0 controls), everything else verbatim.
//!   * Numbers serialize as the ECMAScript shortest double via `ryu-js` (the same
//!     algorithm the Scala DoubleSerializerImpl implements with `ecmaMode = true`).
//!
//! IMPORTANT number semantics: the Scala canonicalizer serializes every JSON number
//! through `num.toDouble` first (see `NumberToJson.serializeNumber(num.toDouble)`).
//! That means even IntValue goes through f64 at the canonical boundary. We replicate
//! this exactly so the bytes match.

use crate::value::Value;

/// Canonicalize a JLVM value to RFC 8785 canonical JSON bytes.
///
/// Returns `Err` when a number does not survive the f64 boundary (NaN/Infinity,
/// e.g. `Int(10^999)` from `{"pow":[10,999]}`): the Scala canonicalizer raises a
/// catchable error there, so we surface a normal `Err` instead of aborting.
pub fn canonicalize(v: &Value) -> Result<Vec<u8>, String> {
    Ok(canonicalize_string(v)?.into_bytes())
}

/// Canonicalize to a UTF-8 string. Same error contract as [`canonicalize`].
pub fn canonicalize_string(v: &Value) -> Result<String, String> {
    let mut out = String::new();
    encode(v, &mut out)?;
    Ok(out)
}

fn encode(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => {
            // Match Scala: numbers go through Double first, then ECMAScript-shortest.
            let d = crate::ratio::Ratio::from_bigint(i.clone()).to_f64();
            out.push_str(&serialize_number(d)?);
        }
        Value::Float(r) => {
            let d = r.to_f64();
            out.push_str(&serialize_number(d)?);
        }
        Value::Str(s) => serialize_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, el) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(el, out)?;
            }
            out.push(']');
        }
        Value::Map(m) => {
            let mut entries: Vec<&(String, Value)> = m.iter().collect();
            entries.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push('{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize_string(k, out);
                out.push(':');
                encode(val, out)?;
            }
            out.push('}');
        }
        // FunctionValue encodes to null (matches the circe encoder).
        Value::Function(_) => out.push_str("null"),
    }
    Ok(())
}

/// Canonicalize a raw `serde_json::Value` to RFC 8785 canonical JSON bytes.
///
/// This is the circe-`Json` analogue of [`canonicalize`]: the Scala
/// `JsonBinaryHasher` canonicalizes a circe `Json` (the proof-value bridge does
/// `jlv.asJson` first). Numbers route through `f64` exactly like the JLVM-value
/// path and like Scala's `NumberToJson.serializeNumber(num.toDouble)`, so the
/// emitted bytes match the Scala hasher pre-image. Used by the auth-DB opcodes
/// for value digests and node-commitment digests.
/// Same error contract as [`canonicalize`]. NOTE: `serde_json::Number` (without
/// the `arbitrary_precision` feature) cannot represent NaN/Infinity, so for this
/// entry point the `Err` arm is unreachable in practice; it exists so no panic
/// path remains.
pub fn canonicalize_json(v: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    encode_json(v, &mut out)?;
    Ok(out.into_bytes())
}

fn encode_json(v: &serde_json::Value, out: &mut String) -> Result<(), String> {
    use serde_json::Value as J;
    match v {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Number(n) => {
            // Match Scala: every JSON number goes through Double first, then
            // ECMAScript-shortest. serde_json without arbitrary_precision keeps
            // numbers as i64/u64/f64; `as_f64` reproduces `num.toDouble` and is
            // always Some(finite) for such numbers.
            let d = n
                .as_f64()
                .ok_or_else(|| "non-f64 JSON number in canonicalizer".to_string())?;
            out.push_str(&serialize_number(d)?);
        }
        J::String(s) => serialize_string(s, out),
        J::Array(arr) => {
            out.push('[');
            for (i, el) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_json(el, out)?;
            }
            out.push(']');
        }
        J::Object(m) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = m.iter().collect();
            entries.sort_by(|a, b| utf16_cmp(a.0, b.0));
            out.push('{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize_string(k, out);
                out.push(':');
                encode_json(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// ECMAScript shortest-double formatting. `0.0` (and `-0.0`) render as `"0"`, matching
/// `NumberToJson.serializeNumber` which special-cases zero. ryu-js implements the same
/// ECMAScript Number::toString algorithm the Scala DoubleSerializerImpl ports.
///
/// NaN/Infinity (e.g. a huge exact integer that overflows the f64 boundary) is a
/// normal `Err`, mirroring the Scala canonicalizer which raises a catchable error.
fn serialize_number(value: f64) -> Result<String, String> {
    if value == 0.0 {
        return Ok("0".to_string());
    }
    if value.is_nan() || value.is_infinite() {
        return Err("NaN/Infinity not allowed in canonical JSON".to_string());
    }
    let mut buf = ryu_js::Buffer::new();
    Ok(buf.format(value).to_string())
}

/// JCS string escaping. Mirrors `JsonCanonicalizer.escapeChar`.
fn serialize_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two strings by their UTF-16 code units, as required by RFC 8785 key
/// ordering. Mirrors the Scala `TreeOrderedMap` comparator (UTF-16BE byte compare).
///
/// Exposed `pub(crate)` so the evaluator can reuse the exact same key ordering for
/// object-form `let` bindings (crypto-determinism: object-let must evaluate bindings
/// in the SAME order the canonicalizer emits keys, byte-identical across Scala/Rust/TS).
pub(crate) fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            },
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}
