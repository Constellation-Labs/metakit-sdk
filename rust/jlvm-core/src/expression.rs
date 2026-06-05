//! The JLVM expression model and its JSON decoder.
//!
//! Mirrors `io.constellationnetwork.metagraph_sdk.json_logic.core.JsonLogicExpression`
//! and the TypeScript `codec.ts`. Operator-tag detection, the `var` forms, array-syntax
//! operators, and object-syntax operators are all handled here.

use crate::ops::is_known_operator;
use crate::ratio::Ratio;
use crate::value::Value;

#[derive(Clone, Debug)]
pub enum Expression {
    /// A literal value.
    Const(Value),
    /// An array of sub-expressions (evaluated element-wise).
    Array(Vec<Expression>),
    /// An object literal whose values are sub-expressions.
    Map(Vec<(String, Expression)>),
    /// `{"var": key}` / `{"var": [key, default]}`. The key is either a static path
    /// (Left) or a sub-expression that evaluates to the path (Right).
    Var { key: VarKey, default: Option<Value> },
    /// `{"op": [args...]}`.
    Apply { op: String, args: Vec<Expression> },
}

#[derive(Clone, Debug)]
pub enum VarKey {
    Path(String),
    Expr(Box<Expression>),
}

/// Decode a `serde_json::Value` into an Expression. Mirrors `decodeJsonLogicExpr`.
pub fn decode_expression(json: &serde_json::Value) -> Result<Expression, String> {
    match json {
        serde_json::Value::Null => Ok(Expression::Const(Value::Null)),
        serde_json::Value::Bool(b) => Ok(Expression::Const(Value::Bool(*b))),
        serde_json::Value::Number(_) => Ok(Expression::Const(crate::value::decode_value(json))),
        serde_json::Value::String(s) => Ok(Expression::Const(Value::Str(s.clone()))),
        serde_json::Value::Array(arr) => decode_array_expression(arr),
        serde_json::Value::Object(obj) => decode_object_expression(obj),
    }
}

fn decode_array_expression(arr: &[serde_json::Value]) -> Result<Expression, String> {
    if arr.is_empty() {
        return Ok(Expression::Array(Vec::new()));
    }
    if let serde_json::Value::String(first) = &arr[0] {
        if first == "var" {
            return decode_var_from_array(&arr[1..]);
        }
        if is_known_operator(first) {
            let args = arr[1..]
                .iter()
                .map(decode_expression)
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Expression::Apply { op: first.clone(), args });
        }
    }
    let elems = arr.iter().map(decode_expression).collect::<Result<Vec<_>, _>>()?;
    Ok(Expression::Array(elems))
}

fn decode_var_from_array(args: &[serde_json::Value]) -> Result<Expression, String> {
    if args.is_empty() {
        return Err("`var` operation requires at least one argument".into());
    }
    let key = decode_var_key(&args[0])?;
    let default = args.get(1).map(crate::value::decode_value);
    Ok(Expression::Var { key, default })
}

fn decode_object_expression(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Expression, String> {
    if obj.is_empty() {
        return Ok(Expression::Const(Value::Map(Vec::new())));
    }
    if obj.len() == 1 {
        let (key, value) = obj.iter().next().unwrap();
        if key.is_empty() || key == "var" {
            return decode_var_object(value);
        }
        if is_known_operator(key) {
            let args = decode_operator_args(value)?;
            return Ok(Expression::Apply { op: key.clone(), args });
        }
    }
    // Otherwise: a MapExpression (values are sub-expressions). If every value decodes
    // to a Const, Scala collapses to ConstExpression(MapValue); behaviorally identical
    // for evaluation, so we keep the MapExpression form (it evaluates element-wise).
    let mut entries: Vec<(String, Expression)> = Vec::new();
    for (k, v) in obj.iter() {
        entries.push((k.clone(), decode_expression(v)?));
    }
    Ok(Expression::Map(entries))
}

/// `{"op": value}` arg parsing. Mirrors `decodeOperatorArgs`: an array is a list of
/// args; anything else is a single arg.
fn decode_operator_args(value: &serde_json::Value) -> Result<Vec<Expression>, String> {
    match value {
        serde_json::Value::Array(arr) => {
            arr.iter().map(decode_expression).collect::<Result<Vec<_>, _>>()
        }
        other => Ok(vec![decode_expression(other)?]),
    }
}

fn decode_var_object(value: &serde_json::Value) -> Result<Expression, String> {
    match value {
        serde_json::Value::String(s) => {
            Ok(Expression::Var { key: VarKey::Path(s.clone()), default: None })
        }
        serde_json::Value::Number(n) => {
            Ok(Expression::Var { key: VarKey::Path(n.to_string()), default: None })
        }
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                return Err("`var` array cannot be empty".into());
            }
            let key = decode_var_key(&arr[0])?;
            let default = arr.get(1).map(crate::value::decode_value);
            Ok(Expression::Var { key, default })
        }
        other => {
            // Nested expression as a dynamic path.
            Ok(Expression::Var { key: VarKey::Expr(Box::new(decode_expression(other)?)), default: None })
        }
    }
}

fn decode_var_key(json: &serde_json::Value) -> Result<VarKey, String> {
    match json {
        serde_json::Value::String(s) => Ok(VarKey::Path(s.clone())),
        serde_json::Value::Number(n) => Ok(VarKey::Path(n.to_string())),
        other => Ok(VarKey::Expr(Box::new(decode_expression(other)?))),
    }
}

/// Encode an Expression back to JSON. Mirrors `encodeJsonLogicExpr`. Provided for
/// completeness / round-tripping.
pub fn encode_expression(expr: &Expression) -> serde_json::Value {
    match expr {
        Expression::Const(v) => crate::value::encode_value(v),
        Expression::Array(list) => {
            serde_json::Value::Array(list.iter().map(encode_expression).collect())
        }
        Expression::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                obj.insert(k.clone(), encode_expression(v));
            }
            serde_json::Value::Object(obj)
        }
        Expression::Var { key, default } => {
            let key_json = match key {
                VarKey::Path(s) => serde_json::Value::String(s.clone()),
                VarKey::Expr(e) => encode_expression(e),
            };
            let var_value = match default {
                None => key_json,
                Some(d) => serde_json::Value::Array(vec![key_json, crate::value::encode_value(d)]),
            };
            let mut obj = serde_json::Map::new();
            obj.insert("var".to_string(), var_value);
            serde_json::Value::Object(obj)
        }
        Expression::Apply { op, args } => {
            let mut obj = serde_json::Map::new();
            obj.insert(
                op.clone(),
                serde_json::Value::Array(args.iter().map(encode_expression).collect()),
            );
            serde_json::Value::Object(obj)
        }
    }
}

/// Helper used by the value-decoding fast path: try parsing a numeric string into a
/// Ratio (re-exported for tests).
pub fn parse_decimal(s: &str) -> Option<Ratio> {
    Ratio::parse_decimal(s)
}
