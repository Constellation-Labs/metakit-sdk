//! The JSON Logic value model.
//!
//! Mirrors `io.constellationnetwork.metagraph_sdk.json_logic.core.JsonLogicValue`:
//! NullValue, BoolValue, IntValue(BigInt), FloatValue(exact Ratio), StrValue,
//! ArrayValue, MapValue, and FunctionValue. Map insertion order is preserved (via a
//! Vec of pairs) so that structural comparison and non-canonical rendering match the
//! reference implementations; RFC 8785 canonicalization re-sorts keys regardless.

use crate::expression::Expression;
use crate::ratio::Ratio;
use num_bigint::BigInt;

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Int(BigInt),
    Float(Ratio),
    Str(String),
    Array(Vec<Value>),
    /// Insertion-ordered string-keyed map.
    Map(Vec<(String, Value)>),
    /// Unevaluated callback body (used by map/filter/reduce/if/etc.).
    Function(Box<Expression>),
}

impl Value {
    /// The `tag` used by the `typeof` operator. Mirrors `JsonLogicValue.tag`.
    pub fn tag(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "string",
            Value::Array(_) => "array",
            Value::Map(_) => "map",
            Value::Function(_) => "function",
        }
    }

    /// Truthiness. Mirrors `JsonLogicValue.isTruthy`.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(i) => !i.eq(&BigInt::from(0)),
            Value::Float(r) => !r.numerator.eq(&BigInt::from(0)),
            Value::Str(s) => !s.is_empty(),
            Value::Array(v) => !v.is_empty(),
            Value::Map(m) => !m.is_empty(),
            Value::Function(_) => false,
        }
    }

    pub fn int_from_i64(i: i64) -> Value {
        Value::Int(BigInt::from(i))
    }

    pub fn map_get<'a>(&'a self, key: &str) -> Option<&'a Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn map_contains(&self, key: &str) -> bool {
        matches!(self, Value::Map(m) if m.iter().any(|(k, _)| k == key))
    }

    /// Structural (deep) equality. Used by `===`/`!==` for collections and by `in`,
    /// `unique`, `intersect`. Mirrors `eqJsonLogicValue` / `strictEquals`.
    pub fn deep_eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.deep_eq(y))
            }
            (Value::Map(a), Value::Map(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                a.iter().all(|(k, v)| match other.map_get(k) {
                    Some(bv) => v.deep_eq(bv),
                    None => false,
                }) && b.iter().all(|(k, _)| self.map_contains(k))
            }
            _ => false,
        }
    }
}

/// Decode a `serde_json::Value` into a JLVM `Value`. Mirrors `decodeJsonLogicValue`:
/// a JSON number becomes IntValue when integral, else FloatValue (exact decimal).
pub fn decode_value(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => number_to_value(n),
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(decode_value).collect()),
        serde_json::Value::Object(obj) => Value::Map(
            obj.iter()
                .map(|(k, v)| (k.clone(), decode_value(v)))
                .collect(),
        ),
    }
}

/// Number -> Value following circe: integral => IntValue, else FloatValue from the
/// exact decimal representation. We use the JSON number's textual form to preserve
/// arbitrary precision (serde_json's `Number` keeps the original text when the
/// `arbitrary_precision` feature is off it still exposes via Display).
pub fn number_to_value(n: &serde_json::Number) -> Value {
    let s = n.to_string();
    // Integral if there is no '.', 'e', or 'E'.
    if let Some(r) = Ratio::parse_decimal(&s) {
        if r.is_integer() {
            Value::Int(r.numerator)
        } else {
            Value::Float(r)
        }
    } else {
        // Fallback (should not happen for valid JSON numbers).
        Value::Null
    }
}

/// Encode a `Value` to a `serde_json::Value` following `encodeJsonLogicValue`:
/// IntValue -> JSON integer; FloatValue -> JSON number from its decimal form;
/// Map/Array recurse; FunctionValue -> null.
pub fn encode_value(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(i) => {
            // Use the integer's textual form to preserve arbitrary precision. Parse it
            // back through serde_json so we get a proper JSON number token.
            serde_json::from_str(&i.to_string()).unwrap_or(serde_json::Value::Null)
        }
        Value::Float(r) => {
            // circe encodes FloatValue via `value.toBigDecimal` -> JSON number. We use
            // the exact plain-decimal expansion. (For structural comparison this is
            // parsed back to f64; for canonical bytes we go through ryu-js separately.)
            let s = r.to_plain_string();
            serde_json::from_str(&s).unwrap_or(serde_json::Value::Null)
        }
        Value::Str(s) => serde_json::Value::String(s.clone()),
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(encode_value).collect()),
        Value::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in m {
                obj.insert(k.clone(), encode_value(val));
            }
            serde_json::Value::Object(obj)
        }
        Value::Function(_) => serde_json::Value::Null,
    }
}
