//! Loose-equality coercion. Mirrors `json_logic.ops.CoercionOps`.

use crate::numeric::parse_bigint;
use crate::ratio::Ratio;
use crate::value::Value;
use num_bigint::BigInt;

const MAX_NUMERIC_STRING_LENGTH: usize = 1000;

#[derive(Clone, Debug)]
pub enum Coerced {
    Null,
    Bool(bool),
    Int(BigInt),
    Float(Ratio),
    Str(String),
}

/// Coerce a value to a primitive. Mirrors `coerceToPrimitive`. Note the JS-flavored
/// rules: empty string -> Int(0); numeric strings -> Int when they parse as BigInt.
pub fn coerce_to_primitive(value: &Value) -> Result<Coerced, String> {
    match value {
        Value::Null => Ok(Coerced::Null),
        Value::Bool(b) => Ok(Coerced::Bool(*b)),
        Value::Int(i) => Ok(Coerced::Int(i.clone())),
        Value::Float(r) => Ok(Coerced::Float(r.clone())),
        Value::Str(s) => {
            if s.is_empty() {
                Ok(Coerced::Int(BigInt::from(0)))
            } else {
                match safe_parse_bigint(s) {
                    Some(i) => Ok(Coerced::Int(i)),
                    None => Ok(Coerced::Str(s.clone())),
                }
            }
        }
        Value::Function(_) => Err("Cannot coerce FunctionValue to a primitive".into()),
        Value::Array(elems) => match elems.as_slice() {
            [] => Ok(Coerced::Int(BigInt::from(0))),
            [single] => coerce_to_primitive(single),
            _ => Err("Cannot coerce multi-element array to a single primitive".into()),
        },
        Value::Map(m) => match m.as_slice() {
            [] => Ok(Coerced::Int(BigInt::from(0))),
            [(_, v)] => coerce_to_primitive(v),
            _ => Err("Cannot coerce multi-key object to a single primitive".into()),
        },
    }
}

fn safe_parse_bigint(s: &str) -> Option<BigInt> {
    if s.len() > MAX_NUMERIC_STRING_LENGTH {
        None
    } else {
        parse_bigint(s)
    }
}

fn safe_parse_decimal(s: &str) -> Option<Ratio> {
    if s.len() > MAX_NUMERIC_STRING_LENGTH {
        None
    } else {
        Ratio::parse_decimal(s)
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    // Mirrors Scala's String.toBooleanOption: only the exact lowercase "true"/"false".
    match s {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Compare two coerced values for loose equality. Mirrors `compareCoercedValues`.
pub fn compare_coerced(l: &Coerced, r: &Coerced) -> Result<bool, String> {
    use Coerced::*;
    let res = match (l, r) {
        (Null, Null) => true,
        (Null, _) => false,
        (_, Null) => false,
        (Bool(lb), Bool(rb)) => lb == rb,
        (Bool(lb), Int(ri)) => {
            if *lb {
                *ri == BigInt::from(1)
            } else {
                *ri == BigInt::from(0)
            }
        }
        (Int(li), Bool(rb)) => {
            if *rb {
                *li == BigInt::from(1)
            } else {
                *li == BigInt::from(0)
            }
        }
        (Bool(lb), Float(rf)) => Ratio::from_i64(if *lb { 1 } else { 0 }) == *rf,
        (Float(lf), Bool(rb)) => *lf == Ratio::from_i64(if *rb { 1 } else { 0 }),
        (Bool(lb), Str(rs)) => parse_bool(rs) == Some(*lb),
        (Str(ls), Bool(rb)) => parse_bool(ls) == Some(*rb),
        (Int(li), Int(ri)) => li == ri,
        (Int(li), Float(rf)) => Ratio::from_bigint(li.clone()) == *rf,
        (Float(lf), Int(ri)) => *lf == Ratio::from_bigint(ri.clone()),
        (Float(lf), Float(rf)) => lf == rf,
        (Int(li), Str(rs)) => safe_parse_bigint(rs).as_ref() == Some(li),
        (Str(ls), Int(ri)) => safe_parse_bigint(ls).as_ref() == Some(ri),
        (Float(lf), Str(rs)) => safe_parse_decimal(rs).as_ref() == Some(lf),
        (Str(ls), Float(rf)) => safe_parse_decimal(ls).as_ref() == Some(rf),
        (Str(ls), Str(rs)) => ls == rs,
    };
    Ok(res)
}
