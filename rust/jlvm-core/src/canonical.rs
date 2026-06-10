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
pub fn canonicalize(v: &Value) -> Vec<u8> {
    let mut out = String::new();
    encode(v, &mut out);
    out.into_bytes()
}

/// Canonicalize to a UTF-8 string.
pub fn canonicalize_string(v: &Value) -> String {
    let mut out = String::new();
    encode(v, &mut out);
    out
}

fn encode(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => {
            // Match Scala: numbers go through Double first, then ECMAScript-shortest.
            let d = crate::ratio::Ratio::from_bigint(i.clone()).to_f64();
            out.push_str(&serialize_number(d));
        }
        Value::Float(r) => {
            let d = r.to_f64();
            out.push_str(&serialize_number(d));
        }
        Value::Str(s) => serialize_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, el) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(el, out);
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
                encode(val, out);
            }
            out.push('}');
        }
        // FunctionValue encodes to null (matches the circe encoder).
        Value::Function(_) => out.push_str("null"),
    }
}

/// ECMAScript shortest-double formatting. `0.0` (and `-0.0`) render as `"0"`, matching
/// `NumberToJson.serializeNumber` which special-cases zero. ryu-js implements the same
/// ECMAScript Number::toString algorithm the Scala DoubleSerializerImpl ports.
fn serialize_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_nan() || value.is_infinite() {
        // The Scala code raises here; in the VM these never occur on the exact path.
        panic!("NaN/Infinity not allowed in canonical JSON");
    }
    let mut buf = ryu_js::Buffer::new();
    buf.format(value).to_string()
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
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
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
