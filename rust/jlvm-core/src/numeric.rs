//! Unified numeric handling. Mirrors `json_logic.ops.NumericOps`.
//!
//! All arithmetic is exact (rational). A result is IntValue only when neither operand
//! was a float and the result is integral; otherwise FloatValue.

use crate::ratio::Ratio;
use crate::value::Value;
use num_bigint::BigInt;

#[derive(Clone, Debug)]
pub enum Numeric {
    Int(BigInt),
    Float(Ratio),
}

impl Numeric {
    pub fn to_ratio(&self) -> Ratio {
        match self {
            Numeric::Int(i) => Ratio::from_bigint(i.clone()),
            Numeric::Float(r) => r.clone(),
        }
    }

    pub fn is_float(&self) -> bool {
        matches!(self, Numeric::Float(_))
    }

    pub fn to_value(&self) -> Value {
        match self {
            Numeric::Int(i) => Value::Int(i.clone()),
            Numeric::Float(r) => Value::Float(r.clone()),
        }
    }
}

/// Promote a value to a numeric type with JS-style coercion. Mirrors `promoteToNumeric`.
pub fn promote_to_numeric(value: &Value) -> Result<Numeric, String> {
    match value {
        Value::Int(i) => Ok(Numeric::Int(i.clone())),
        Value::Float(r) => Ok(Numeric::Float(r.clone())),
        Value::Bool(b) => Ok(Numeric::Int(BigInt::from(if *b { 1 } else { 0 }))),
        Value::Null => Ok(Numeric::Int(BigInt::from(0))),
        Value::Str(s) => {
            if s.is_empty() {
                Ok(Numeric::Int(BigInt::from(0)))
            } else if let Some(i) = parse_bigint(s) {
                Ok(Numeric::Int(i))
            } else if let Some(r) = Ratio::parse_decimal(s) {
                Ok(Numeric::Float(r))
            } else {
                Err(format!("Cannot convert string '{}' to number", s))
            }
        }
        Value::Array(list) => match list.as_slice() {
            [] => Ok(Numeric::Int(BigInt::from(0))),
            [single] => promote_to_numeric(single),
            _ => Err("Cannot convert multi-element array to number".into()),
        },
        Value::Map(m) => match m.as_slice() {
            [] => Ok(Numeric::Int(BigInt::from(0))),
            [(_, v)] => promote_to_numeric(v),
            _ => Err("Cannot convert multi-key object to number".into()),
        },
        Value::Function(_) => Err("Cannot convert function to number".into()),
    }
}

/// `BigInt(s)` parse: strict integer, allowing a leading sign. Mirrors Scala's BigInt(s).
pub fn parse_bigint(s: &str) -> Option<BigInt> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let body = t.strip_prefix(['+', '-']).unwrap_or(t);
    if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    BigInt::parse_bytes(t.as_bytes(), 10)
}

/// Combine two numerics with an exact-rational op, typing the result. Mirrors
/// `combineNumeric`.
pub fn combine_numeric<F>(op: F, left: &Numeric, right: &Numeric) -> Value
where
    F: Fn(&Ratio, &Ratio) -> Ratio,
{
    let result = op(&left.to_ratio(), &right.to_ratio());
    if !left.is_float() && !right.is_float() && result.is_integer() {
        Value::Int(result.numerator)
    } else {
        Value::Float(result)
    }
}

/// Reduce a list of values with an exact-rational op. Mirrors `reduceNumeric`.
pub fn reduce_numeric<F>(values: &[Value], op: F) -> Result<Value, String>
where
    F: Fn(&Ratio, &Ratio) -> Ratio,
{
    if values.is_empty() {
        return Err("Cannot reduce empty list".into());
    }
    let numerics: Vec<Numeric> = values
        .iter()
        .map(promote_to_numeric)
        .collect::<Result<Vec<_>, _>>()?;
    let has_float = numerics.iter().any(|n| n.is_float());
    let mut iter = numerics.iter().map(|n| n.to_ratio());
    let mut acc = iter.next().unwrap();
    for r in iter {
        acc = op(&acc, &r);
    }
    if !has_float && acc.is_integer() {
        Ok(Value::Int(acc.numerator))
    } else {
        Ok(Value::Float(acc))
    }
}

/// Exact comparison of two numerics. Mirrors `compareNumeric`.
pub fn compare_numeric(left: &Numeric, right: &Numeric) -> std::cmp::Ordering {
    left.to_ratio().cmp(&right.to_ratio())
}
