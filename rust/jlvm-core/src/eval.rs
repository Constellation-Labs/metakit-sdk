//! The evaluator. Mirrors `JsonLogicRuntime.evaluate` + `JsonLogicSemantics`.
//!
//! Uses ordinary recursion (Rust's native stack is large; the conformance programs are
//! shallow). The control-flow operators `if` and `let` are handled specially, matching
//! the Scala runtime; everything else first evaluates its (non-callback) arguments and
//! then dispatches to the corresponding handler.

use crate::coercion::{coerce_to_primitive, compare_coerced};
use crate::expression::{Expression, VarKey};
use crate::numeric::{
    combine_numeric, compare_numeric, promote_to_numeric, reduce_numeric, Numeric,
};
use crate::ops::is_callback_arg;
use crate::ratio::Ratio;
use crate::value::Value;
use num_bigint::BigInt;
use num_traits::Signed;
use std::cmp::Ordering;

const MAX_SAFE_EXPONENT: i64 = 999;

/// Evaluate an expression against `data` and an optional context. The top-level entry
/// point uses `data` as the variable root and `ctx = None`.
pub fn evaluate(expr: &Expression, data: &Value) -> Result<Value, String> {
    let ev = Evaluator { vars: data };
    ev.eval(expr, None)
}

struct Evaluator<'a> {
    vars: &'a Value,
}

impl<'a> Evaluator<'a> {
    fn eval(&self, expr: &Expression, ctx: Option<&Value>) -> Result<Value, String> {
        match expr {
            Expression::Const(v) => Ok(v.clone()),
            Expression::Array(elems) => {
                let mut out = Vec::with_capacity(elems.len());
                for e in elems {
                    out.push(self.eval(e, ctx)?);
                }
                Ok(Value::Array(out))
            }
            Expression::Map(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (k, e) in entries {
                    out.push((k.clone(), self.eval(e, ctx)?));
                }
                Ok(Value::Map(out))
            }
            Expression::Var { key, default } => {
                let key_str = match key {
                    VarKey::Path(s) => s.clone(),
                    VarKey::Expr(e) => match self.eval(e, ctx)? {
                        Value::Str(name) => name,
                        Value::Array(items) => match items.first() {
                            Some(Value::Str(name)) => name.clone(),
                            _ => return Err(format!("Got non-string input: {:?}", items)),
                        },
                        v => return Err(format!("Got non-string input: {:?}", v)),
                    },
                };
                self.lookup_var(&key_str, default.as_ref(), ctx)
            }
            Expression::Apply { op, args } => self.eval_apply(op, args, ctx),
        }
    }

    /// Variable lookup with dot-path traversal and default handling. Mirrors
    /// `getVar` + `lookupVar`.
    fn lookup_var(
        &self,
        key: &str,
        default: Option<&Value>,
        ctx: Option<&Value>,
    ) -> Result<Value, String> {
        let raw = self.get_var(key, ctx)?;
        // Apply default only when key is non-empty and the lookup produced Null.
        if !key.is_empty() && matches!(raw, Value::Null) {
            if let Some(d) = default {
                return Ok(d.clone());
            }
        }
        Ok(raw)
    }

    fn get_var(&self, key: &str, ctx: Option<&Value>) -> Result<Value, String> {
        if key.is_empty() {
            return Ok(ctx.cloned().unwrap_or_else(|| self.vars.clone()));
        }
        if key.ends_with('.') {
            return Ok(Value::Null);
        }
        // Combine base (vars) with the context overlay. Mirrors `combineState`.
        let combined = self.combine_state(ctx);
        let mut cur = combined;
        for seg in key.split('.') {
            cur = get_child(&cur, seg);
        }
        Ok(cur)
    }

    /// Mirrors `combineState`: arrays/maps merge, primitives/null leave base unchanged,
    /// other combinations replace base with ctx.
    fn combine_state(&self, ctx: Option<&Value>) -> Value {
        match ctx {
            None => self.vars.clone(),
            Some(Value::Null) => self.vars.clone(),
            Some(c) if is_primitive(c) => self.vars.clone(),
            Some(Value::Array(r)) => match self.vars {
                Value::Array(l) => {
                    let mut v = l.clone();
                    v.extend(r.clone());
                    Value::Array(v)
                }
                _ => Value::Array(r.clone()),
            },
            Some(Value::Map(r)) => match self.vars {
                Value::Map(l) => Value::Map(merge_maps(l, r)),
                _ => Value::Map(r.clone()),
            },
            Some(c) => c.clone(),
        }
    }

    fn eval_apply(
        &self,
        op: &str,
        args: &[Expression],
        ctx: Option<&Value>,
    ) -> Result<Value, String> {
        match op {
            "if" => return self.eval_if(args, ctx),
            "let" => return self.eval_let(args, ctx),
            _ => {}
        }
        // Evaluate args, wrapping callback positions as FunctionValue.
        let mut values: Vec<Value> = Vec::with_capacity(args.len());
        for (idx, arg) in args.iter().enumerate() {
            if is_callback_arg(op, idx) {
                match arg {
                    Expression::Const(Value::Function(f)) => {
                        values.push(Value::Function(f.clone()))
                    }
                    other => values.push(Value::Function(Box::new(other.clone()))),
                }
            } else {
                values.push(self.eval(arg, ctx)?);
            }
        }
        self.apply_op(op, values, ctx)
    }

    /// Lazy if/else chain. Mirrors the runtime's `evaluateIfElse`.
    fn eval_if(&self, args: &[Expression], ctx: Option<&Value>) -> Result<Value, String> {
        let mut rest = args;
        loop {
            match rest {
                [] => return Err("If/else requires at least one argument".into()),
                [cond, then, tail @ ..] => {
                    let c = self.eval(cond, ctx)?;
                    if c.is_truthy() {
                        return self.eval(then, ctx);
                    }
                    match tail {
                        [] => return Ok(Value::Null),
                        [else_branch] => return self.eval(else_branch, ctx),
                        _ => {
                            rest = tail;
                        }
                    }
                }
                [_] => return Err("If/else malformed: condition without then-branch".into()),
            }
        }
    }

    /// `{"let": [[[name, expr], ...], result]}` with sequential, scope-aware bindings.
    /// Mirrors the runtime's let handling.
    fn eval_let(&self, args: &[Expression], ctx: Option<&Value>) -> Result<Value, String> {
        let (bindings, result_expr) = match args {
            [Expression::Array(bindings), result] => (bindings, result),
            [Expression::Map(entries), result] => {
                // Convenience object form `{"let": [{name: expr}, result]}` as used by
                // the conformance vectors. Each entry becomes a binding.
                //
                // Crypto-determinism: object-form bindings are evaluated in RFC-8785
                // sorted-key order (UTF-16 code units), the SAME ordering the JSON
                // canonicalizer uses for object keys, so all three impls (Scala/Rust/TS)
                // are byte-identical. We reuse `canonical::utf16_cmp` (the comparator that
                // backs `canonicalize`) rather than serde_json's incidental key order.
                // Bindings are then evaluated sequentially, each seeing prior ones in
                // scope. Array-form `let` keeps explicit insertion order (handled below).
                let mut sorted: Vec<&(String, Expression)> = entries.iter().collect();
                sorted.sort_by(|a, b| crate::canonical::utf16_cmp(&a.0, &b.0));
                let mut acc: Vec<(String, Value)> = Vec::new();
                for (name, value_expr) in sorted {
                    let binding_ctx = self.let_ctx(ctx, &acc);
                    let v = self.eval(value_expr, binding_ctx.as_ref())?;
                    acc.push((name.clone(), v));
                }
                let result_ctx = self.let_ctx(ctx, &acc).unwrap_or(Value::Map(acc));
                return self.eval(result, Some(&result_ctx));
            }
            _ => return Err("let requires [[bindings...], resultExpr]".into()),
        };

        let mut acc: Vec<(String, Value)> = Vec::new();
        for binding in bindings {
            match binding {
                Expression::Array(pair) => match pair.as_slice() {
                    [Expression::Const(Value::Str(name)), value_expr] => {
                        let binding_ctx = self.let_ctx(ctx, &acc);
                        let v = self.eval(value_expr, binding_ctx.as_ref())?;
                        acc.push((name.clone(), v));
                    }
                    _ => return Err(format!("let binding must be [name, expr], got: {:?}", pair)),
                },
                other => {
                    return Err(format!(
                        "let binding must be [name, expr], got: {:?}",
                        other
                    ))
                }
            }
        }
        let result_ctx = self.let_ctx(ctx, &acc).unwrap_or(Value::Map(acc));
        self.eval(result_expr, Some(&result_ctx))
    }

    /// Build the let context overlay from the current ctx and accumulated bindings.
    /// Mirrors the runtime's letCtx construction.
    fn let_ctx(&self, ctx: Option<&Value>, acc: &[(String, Value)]) -> Option<Value> {
        match ctx {
            Some(Value::Map(existing)) => Some(Value::Map(merge_maps(existing, acc))),
            Some(other) => {
                let mut m: Vec<(String, Value)> = acc.to_vec();
                m.push((String::new(), other.clone()));
                Some(Value::Map(m))
            }
            None => {
                if acc.is_empty() {
                    None
                } else {
                    Some(Value::Map(acc.to_vec()))
                }
            }
        }
    }

    // --- operator dispatch ---------------------------------------------------

    fn apply_op(&self, op: &str, values: Vec<Value>, ctx: Option<&Value>) -> Result<Value, String> {
        match op {
            "==" => self.op_eq(values),
            "===" => self.op_eq_strict(values),
            "!=" => self.op_neq(values),
            "!==" => self.op_neq_strict(values),
            "!" => self.op_not(values),
            "!!" => self.op_truthy(values),
            "or" => self.op_or(values),
            "and" => self.op_and(values),
            "<" => self.op_cmp(values, Ordering::Less, false),
            "<=" => self.op_cmp(values, Ordering::Less, true),
            ">" => self.op_cmp_gt(values, false),
            ">=" => self.op_cmp_gt(values, true),
            "%" => self.op_modulo(values),
            "max" => self.op_minmax(values, true),
            "min" => self.op_minmax(values, false),
            "+" => self.op_add(values),
            "*" => self.op_times(values),
            "-" => self.op_minus(values),
            "/" => self.op_div(values),
            "merge" => self.op_merge(values),
            "in" => self.op_in(values),
            "intersect" => self.op_intersect(values),
            "cat" => self.op_cat(values),
            "substr" => self.op_substr(values),
            "map" => self.op_map(values),
            "filter" => self.op_filter(values),
            "reduce" => self.op_reduce(values),
            "all" => self.op_all(values),
            "none" => self.op_none(values),
            "some" => self.op_some(values),
            "values" => self.op_map_values(values),
            "keys" => self.op_map_keys(values),
            "get" => self.op_get(values),
            "count" => self.op_count(values),
            "length" => self.op_length(values),
            "find" => self.op_find(values),
            "lower" => self.op_lower(values),
            "upper" => self.op_upper(values),
            "join" => self.op_join(values),
            "split" => self.op_split(values),
            "default" => self.op_default(values),
            "unique" => self.op_unique(values),
            "slice" => self.op_slice(values),
            "reverse" => self.op_reverse(values),
            "flatten" => self.op_flatten(values),
            "trim" => self.op_trim(values),
            "startsWith" => self.op_starts_with(values),
            "endsWith" => self.op_ends_with(values),
            "abs" => self.op_abs(values),
            "round" => self.op_round(values),
            "floor" => self.op_floor(values),
            "ceil" => self.op_ceil(values),
            "pow" => self.op_pow(values),
            "has" => self.op_has(values),
            "entries" => self.op_entries(values),
            "typeof" => self.op_typeof(values),
            "exists" => self.op_exists(values),
            "missing" => self.op_missing(values, ctx),
            "missing_some" => self.op_missing_some(values, ctx),
            // ZK / crypto (Tier 1). These are pure precompiles over already-parsed
            // hex args; they delegate to `crate::crypto`, byte-matching Scala CryptoOps.
            "poseidon" => crate::crypto::poseidon(&values),
            "pmt_verify" => crate::crypto::pmt_verify(&values),
            "schnorr_verify" => crate::crypto::schnorr_verify(&values),
            // Auth-DB ZK verifiers (Tier 2a). Pure ports of the Scala AuthDbOps
            // F-handlers over the SMT / MPT primitives; their JSON proofs are
            // already-parsed JLVM values, bridged to circe-JSON for hashing /
            // decoding. Byte-matching `AuthDbOps`.
            "smt_verify" => crate::auth_db::smt_verify(&values),
            "mpt_verify" => crate::auth_db::mpt_verify(&values),
            "mpt_prefix_verify" => crate::auth_db::mpt_prefix_verify(&values),
            // BN254 (alt_bn128) curve ops + ECVRF (Tier 2b). Pure ports of the
            // Scala CryptoOps bn254Add / bn254Mul / bn254Pairing / ecVrfVerify
            // over Bn254.scala + MiraclEcVrf25519. EIP-196/197 encoding;
            // ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381). Byte-matching CryptoOps.
            "bn254_add" => crate::crypto::bn254_add(&values),
            "bn254_mul" => crate::crypto::bn254_mul(&values),
            "bn254_pairing" => crate::crypto::bn254_pairing(&values),
            "ecvrf_verify" => crate::crypto::ecvrf_verify(&values),
            // SP1 Groth16-BN254 verifier (Tier 3a). Pure port of the Scala
            // CryptoOps.groth16Verify over Sp1Groth16Verifier + Groth16Verifier
            // (SP1 groth16 circuit v6.1.0). Byte-matching CryptoOps.
            "groth16_verify" => crate::crypto::groth16_verify(&values),
            // BLS12-381 signatures (Tier 3b). Pure port of the Scala
            // CryptoOps.blsVerify / blsAggregateVerify over Bls12381
            // (BouncyCastle 1.85 BLS12_381ProofOfPossession), backed by blst's
            // min_pk module. Eth2 / IETF PoP ciphersuite (minimal-pubkey-size,
            // DST BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_). Byte-matching.
            "bls_verify" => crate::crypto::bls_verify(&values),
            "bls_aggregate_verify" => crate::crypto::bls_aggregate_verify(&values),
            other => Err(format!("Unsupported operator: {}", other)),
        }
    }

    // --- equality ------------------------------------------------------------

    fn op_eq(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [l, r] => {
                let lc = coerce_to_primitive(l)?;
                let rc = coerce_to_primitive(r)?;
                Ok(Value::Bool(compare_coerced(&lc, &rc)?))
            }
            _ => Err(format!("Unexpected input for `==` got {:?}", values)),
        }
    }

    fn op_neq(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [l, r] => {
                let lc = coerce_to_primitive(l)?;
                let rc = coerce_to_primitive(r)?;
                Ok(Value::Bool(!compare_coerced(&lc, &rc)?))
            }
            _ => Err(format!("Unexpected input for `!=` got {:?}", values)),
        }
    }

    fn op_eq_strict(&self, values: Vec<Value>) -> Result<Value, String> {
        let result = match values.as_slice() {
            [Value::Null, Value::Null] => true,
            [Value::Bool(l), Value::Bool(r)] => l == r,
            [Value::Str(l), Value::Str(r)] => l == r,
            [Value::Int(l), Value::Int(r)] => l == r,
            [Value::Float(l), Value::Float(r)] => l == r,
            [a @ Value::Array(_), b @ Value::Array(_)] => a.deep_eq(b),
            [a @ Value::Map(_), b @ Value::Map(_)] => a.deep_eq(b),
            _ => false,
        };
        Ok(Value::Bool(result))
    }

    fn op_neq_strict(&self, values: Vec<Value>) -> Result<Value, String> {
        // SPEC DIVERGENCE (intentional): the Scala `handleNEqStrictOp` only negates for
        // matching-type pairs and returns `false` for every mismatched-type pair via its
        // `case _ => false`. That makes `1 !== "1"` evaluate to `false` in Scala, even
        // though `1 === "1"` is `false` (so the two are NOT strictly equal). The shared
        // conformance vector expects `true`, and the TypeScript reference implements
        // `!==` as `!strictEquals(a, b)`. We follow the oracle / TS here: `!==` is the
        // exact negation of `===`. See the report for details.
        let eq = match values.as_slice() {
            [Value::Null, Value::Null] => true,
            [Value::Bool(l), Value::Bool(r)] => l == r,
            [Value::Str(l), Value::Str(r)] => l == r,
            [Value::Int(l), Value::Int(r)] => l == r,
            [Value::Float(l), Value::Float(r)] => l == r,
            [a @ Value::Array(_), b @ Value::Array(_)] => a.deep_eq(b),
            [a @ Value::Map(_), b @ Value::Map(_)] => a.deep_eq(b),
            _ => false,
        };
        Ok(Value::Bool(!eq))
    }

    // --- logical -------------------------------------------------------------

    fn op_not(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [v] => Ok(Value::Bool(!v.is_truthy())),
            _ => Err(format!("Unexpected input for `!` got {:?}", values)),
        }
    }

    fn op_truthy(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [v] => Ok(Value::Bool(v.is_truthy())),
            _ => Err(format!("Unexpected input for `!!` got {:?}", values)),
        }
    }

    fn op_or(&self, values: Vec<Value>) -> Result<Value, String> {
        if values.is_empty() {
            return Ok(Value::Bool(false));
        }
        for v in &values {
            if v.is_truthy() {
                return Ok(v.clone());
            }
        }
        Ok(values.into_iter().last().unwrap())
    }

    fn op_and(&self, values: Vec<Value>) -> Result<Value, String> {
        // Mirrors handleAndOp fold: returns first falsy, else the last element; true if empty.
        let mut acc = Value::Bool(true);
        for el in values {
            if !acc.is_truthy() {
                return Ok(acc);
            }
            if !el.is_truthy() {
                return Ok(el);
            }
            acc = el;
        }
        Ok(acc)
    }

    // --- comparison ----------------------------------------------------------

    fn op_cmp(&self, values: Vec<Value>, want: Ordering, or_equal: bool) -> Result<Value, String> {
        let test = |a: &Value, b: &Value| -> Result<bool, String> {
            let an = promote_to_numeric(a)?;
            let bn = promote_to_numeric(b)?;
            let ord = compare_numeric(&an, &bn);
            Ok(ord == want || (or_equal && ord == Ordering::Equal))
        };
        match values.as_slice() {
            [l, r] => Ok(Value::Bool(test(l, r)?)),
            [a, b, c] => Ok(Value::Bool(test(a, b)? && test(b, c)?)),
            _ => Err(format!("Unexpected input for comparison got {:?}", values)),
        }
    }

    fn op_cmp_gt(&self, values: Vec<Value>, or_equal: bool) -> Result<Value, String> {
        // `>` and `>=` are binary-only in the Scala semantics.
        let test = |a: &Value, b: &Value| -> Result<bool, String> {
            let an = promote_to_numeric(a)?;
            let bn = promote_to_numeric(b)?;
            let ord = compare_numeric(&an, &bn);
            Ok(ord == Ordering::Greater || (or_equal && ord == Ordering::Equal))
        };
        match values.as_slice() {
            [l, r] => Ok(Value::Bool(test(l, r)?)),
            _ => Err(format!("Unexpected input for comparison got {:?}", values)),
        }
    }

    // --- arithmetic ----------------------------------------------------------

    fn op_modulo(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [l, r] => {
                let ln = promote_to_numeric(l)?;
                let rn = promote_to_numeric(r)?;
                if rn.to_ratio().is_zero() {
                    return Err("Division by zero in modulo operation".into());
                }
                Ok(combine_numeric(|a, b| a.rem(b), &ln, &rn))
            }
            _ => Err(format!("Unexpected input for `%` got {:?}", values)),
        }
    }

    fn op_minmax(&self, values: Vec<Value>, is_max: bool) -> Result<Value, String> {
        let list: &[Value] = match values.as_slice() {
            [Value::Array(arr)] => arr,
            _ => &values,
        };
        if list.is_empty() {
            return Err("min/max: list cannot be empty".into());
        }
        let numerics: Vec<Numeric> = list
            .iter()
            .map(promote_to_numeric)
            .collect::<Result<Vec<_>, _>>()?;
        let has_float = numerics.iter().any(|n| n.is_float());
        let mut acc = numerics[0].to_ratio();
        for n in &numerics[1..] {
            let r = n.to_ratio();
            acc = if is_max {
                acc.max_ratio(&r)
            } else {
                acc.min_ratio(&r)
            };
        }
        if !has_float && acc.is_integer() {
            Ok(Value::Int(acc.numerator))
        } else {
            Ok(Value::Float(acc))
        }
    }

    fn op_add(&self, values: Vec<Value>) -> Result<Value, String> {
        let list: &[Value] = match values.as_slice() {
            [Value::Array(arr)] => arr,
            _ => &values,
        };
        if list.is_empty() {
            return Err("`+`: list cannot be empty".into());
        }
        // Single string arg: coerce-to-number (unary plus). Mirrors handleAddOp.
        if list.len() == 1 {
            if let Value::Str(_) = &list[0] {
                return Ok(promote_to_numeric(&list[0])?.to_value());
            }
        }
        reduce_numeric(list, |a, b| a.add(b))
    }

    fn op_times(&self, values: Vec<Value>) -> Result<Value, String> {
        let list: &[Value] = match values.as_slice() {
            [Value::Array(arr)] => arr,
            _ => &values,
        };
        if list.is_empty() {
            return Err("`*`: list cannot be empty".into());
        }
        reduce_numeric(list, |a, b| a.mul(b))
    }

    fn op_minus(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [v] => {
                let n = promote_to_numeric(v)?;
                Ok(combine_numeric(
                    |a, _| Ratio::zero().sub(a),
                    &n,
                    &Numeric::Int(BigInt::from(0)),
                ))
            }
            [l, r] => {
                let ln = promote_to_numeric(l)?;
                let rn = promote_to_numeric(r)?;
                Ok(combine_numeric(|a, b| a.sub(b), &ln, &rn))
            }
            _ => Err(format!("Unexpected input for `-` got {:?}", values)),
        }
    }

    fn op_div(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [l, r] => {
                let ln = promote_to_numeric(l)?;
                let rn = promote_to_numeric(r)?;
                if rn.to_ratio().is_zero() {
                    return Err("Division by zero".into());
                }
                Ok(combine_numeric(|a, b| a.div(b), &ln, &rn))
            }
            _ => Err(format!("Unexpected input for `/` got {:?}", values)),
        }
    }

    fn op_abs(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Int(v)] => Ok(Value::Int(v.abs())),
            [Value::Float(v)] => Ok(Value::Float(v.abs())),
            [v] => match promote_to_numeric(v)? {
                Numeric::Int(n) => Ok(Value::Int(n.abs())),
                Numeric::Float(n) => Ok(Value::Float(n.abs())),
            },
            _ => Err(format!("Unexpected input to abs, got {:?}", values)),
        }
    }

    fn op_round(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Int(v)] => Ok(Value::Int(v.clone())),
            [Value::Float(v)] => Ok(Value::Int(v.round_half_up())),
            [v] => match promote_to_numeric(v)? {
                Numeric::Int(n) => Ok(Value::Int(n)),
                Numeric::Float(n) => Ok(Value::Int(n.round_half_up())),
            },
            _ => Err(format!("Unexpected input to round, got {:?}", values)),
        }
    }

    fn op_floor(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Int(v)] => Ok(Value::Int(v.clone())),
            [Value::Float(v)] => Ok(Value::Int(v.floor())),
            [v] => match promote_to_numeric(v)? {
                Numeric::Int(n) => Ok(Value::Int(n)),
                Numeric::Float(n) => Ok(Value::Int(n.floor())),
            },
            _ => Err(format!("Unexpected input to floor, got {:?}", values)),
        }
    }

    fn op_ceil(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Int(v)] => Ok(Value::Int(v.clone())),
            [Value::Float(v)] => Ok(Value::Int(v.ceil())),
            [v] => match promote_to_numeric(v)? {
                Numeric::Int(n) => Ok(Value::Int(n)),
                Numeric::Float(n) => Ok(Value::Int(n.ceil())),
            },
            _ => Err(format!("Unexpected input to ceil, got {:?}", values)),
        }
    }

    fn op_pow(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Int(base), Value::Int(exp)]
                if !exp.is_negative() && exp <= &BigInt::from(MAX_SAFE_EXPONENT) =>
            {
                let e = bigint_to_u32(exp).ok_or("exponent out of range")?;
                Ok(Value::Int(base.pow(e)))
            }
            [Value::Int(_), Value::Int(exp)] if exp > &BigInt::from(MAX_SAFE_EXPONENT) => {
                Err(format!(
                    "Exponent {} exceeds maximum safe value {}",
                    exp, MAX_SAFE_EXPONENT
                ))
            }
            [base, exp] => {
                let base_num = promote_to_numeric(base)?;
                let exp_num = promote_to_numeric(exp)?;
                let e = match exp_num.to_ratio().to_bigint_exact() {
                    None => {
                        return Err(format!(
                        "Exponent must be an integer for deterministic exponentiation, got {:?}",
                        exp_num.to_value()
                    ))
                    }
                    Some(e) => e,
                };
                if e.abs() > BigInt::from(MAX_SAFE_EXPONENT) {
                    return Err(format!(
                        "Exponent magnitude {} exceeds maximum safe value {}",
                        e.abs(),
                        MAX_SAFE_EXPONENT
                    ));
                }
                let br = base_num.to_ratio();
                if e.is_negative() && br.numerator.eq(&BigInt::from(0)) {
                    return Err("Zero cannot be raised to a negative power".into());
                }
                let powed = if !e.is_negative() {
                    br.pow(bigint_to_u32(&e).ok_or("exponent out of range")?)
                } else {
                    br.inverse()
                        .pow(bigint_to_u32(&(-e.clone())).ok_or("exponent out of range")?)
                };
                let result = if !base_num.is_float() && !e.is_negative() && powed.is_integer() {
                    Value::Int(powed.numerator)
                } else {
                    Value::Float(powed)
                };
                Ok(result)
            }
            _ => Err(format!("Unexpected input to pow, got {:?}", values)),
        }
    }

    // --- collections / strings ----------------------------------------------

    fn op_merge(&self, values: Vec<Value>) -> Result<Value, String> {
        // All maps -> merged map; else flatten one level.
        if !values.is_empty() && values.iter().all(|v| matches!(v, Value::Map(_))) {
            let mut acc: Vec<(String, Value)> = Vec::new();
            for v in &values {
                if let Value::Map(m) = v {
                    acc = merge_maps(&acc, m);
                }
            }
            return Ok(Value::Map(acc));
        }
        let list: Vec<Value> = match values.as_slice() {
            [Value::Array(arr)] => arr.clone(),
            _ => values,
        };
        let mut flattened: Vec<Value> = Vec::new();
        for el in list {
            match el {
                Value::Array(inner) => flattened.extend(inner),
                other => flattened.push(other),
            }
        }
        Ok(Value::Array(flattened))
    }

    fn op_in(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Null, _] => Ok(Value::Bool(false)),
            [to_find, Value::Str(s)] if is_primitive(to_find) => {
                let needle = stringify_primitive(to_find);
                Ok(Value::Bool(s.contains(&needle)))
            }
            [to_find, Value::Array(arr)] => Ok(Value::Bool(arr.iter().any(|x| x.deep_eq(to_find)))),
            _ => Err(format!("Unexpected input to `in` got {:?}", values)),
        }
    }

    fn op_intersect(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Null, _] => Ok(Value::Bool(true)),
            [Value::Array(_), Value::Null] => Ok(Value::Bool(false)),
            [Value::Array(to_find), Value::Array(arr)] => {
                let all = to_find.iter().all(|x| arr.iter().any(|y| y.deep_eq(x)));
                Ok(Value::Bool(all))
            }
            _ => Err(format!(
                "Unexpected input to `intersect`: expected two arrays, got {:?}",
                values
            )),
        }
    }

    fn op_cat(&self, values: Vec<Value>) -> Result<Value, String> {
        let mut out = String::new();
        for v in &values {
            match v {
                Value::Null => {}
                Value::Function(_) | Value::Array(_) | Value::Map(_) => {
                    return Err(format!("Unexpected input for `cat` got {:?}", v))
                }
                Value::Bool(b) => out.push_str(&b.to_string()),
                Value::Int(i) => out.push_str(&i.to_string()),
                Value::Float(r) => out.push_str(&r.to_plain_string()),
                Value::Str(s) => out.push_str(s),
            }
        }
        Ok(Value::Str(out))
    }

    fn op_substr(&self, values: Vec<Value>) -> Result<Value, String> {
        // Indices are over UTF-16 code units, matching Scala String semantics.
        let (s, start, length): (&str, i64, i64) = match values.as_slice() {
            [Value::Str(s), Value::Int(start)] => {
                let st = bigint_to_i64(start).ok_or("substr start out of range")?;
                let len = s.encode_utf16().count() as i64;
                (s, st, len)
            }
            [Value::Str(s), Value::Int(start), Value::Int(length)] => {
                let st = bigint_to_i64(start).ok_or("substr start out of range")?;
                let ln = bigint_to_i64(length).ok_or("substr length out of range")?;
                (s, st, ln)
            }
            _ => return Err(format!("Unexpected input to `substr` got {:?}", values)),
        };
        let units: Vec<u16> = s.encode_utf16().collect();
        let str_len = units.len() as i64;
        let raw_start = if start < 0 { str_len + start } else { start };
        let start_idx = raw_start.max(0).min(str_len);
        let end_idx = if length >= 0 {
            (start_idx + length).min(str_len)
        } else {
            (str_len + length).max(0)
        };
        let sub = if start_idx >= str_len || end_idx <= start_idx {
            String::new()
        } else {
            String::from_utf16_lossy(&units[start_idx as usize..end_idx as usize])
        };
        Ok(Value::Str(sub))
    }

    fn op_map(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr), Value::Function(expr)] => {
                let mut out = Vec::with_capacity(arr.len());
                for el in arr {
                    out.push(self.eval(expr, Some(el))?);
                }
                Ok(Value::Array(out))
            }
            _ => Err(format!("Unexpected input to map, got {:?}", values)),
        }
    }

    fn op_filter(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr), Value::Function(expr)] => {
                let mut out = Vec::new();
                for el in arr {
                    if self.eval(expr, Some(el))?.is_truthy() {
                        out.push(el.clone());
                    }
                }
                Ok(Value::Array(out))
            }
            _ => Err(format!("Unexpected input to filter, got {:?}", values)),
        }
    }

    fn op_reduce(&self, values: Vec<Value>) -> Result<Value, String> {
        let (arr, expr, init): (&[Value], &Expression, Option<Value>) = match values.as_slice() {
            [Value::Array(arr), Value::Function(expr)] => (arr, expr, None),
            [Value::Array(arr), Value::Function(expr), init] if is_primitive(init) => {
                (arr, expr, Some(init.clone()))
            }
            _ => return Err(format!("Unexpected input to reduce, got {:?}", values)),
        };
        let (start, mut acc): (usize, Value) = match init {
            Some(v) => (0, v),
            None => {
                if arr.is_empty() {
                    return Ok(Value::Null);
                }
                (1, arr[0].clone())
            }
        };
        for item in &arr[start..] {
            let ctx = Value::Map(vec![
                ("current".to_string(), item.clone()),
                ("accumulator".to_string(), acc.clone()),
            ]);
            acc = self.eval(expr, Some(&ctx))?;
        }
        Ok(acc)
    }

    fn op_all(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Null, Value::Function(_)] => Ok(Value::Bool(false)),
            [Value::Array(arr), Value::Function(expr)] => {
                // Mirrors handleAllOp: empty array -> forall over empty -> true? No:
                // Scala maps each element to a bool then `forall(identity)`. For the
                // empty array that is `true`, BUT the conformance vector expects `false`
                // for all-on-empty. The Scala semantics reach this via the empty-array
                // case: traverse over Nil yields Nil, forall(identity) == true. However
                // the test vector for `all([],...)` expects false. We replicate the
                // OBSERVED reference behavior: empty array -> false.
                if arr.is_empty() {
                    return Ok(Value::Bool(false));
                }
                for el in arr {
                    if !self.eval(expr, Some(el))?.is_truthy() {
                        return Ok(Value::Bool(false));
                    }
                }
                Ok(Value::Bool(true))
            }
            _ => Err(format!("Unexpected input to all, got {:?}", values)),
        }
    }

    fn op_none(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr), Value::Function(expr)] => {
                for el in arr {
                    if self.eval(expr, Some(el))?.is_truthy() {
                        return Ok(Value::Bool(false));
                    }
                }
                Ok(Value::Bool(true))
            }
            _ => Err(format!("Unexpected input to none, got {:?}", values)),
        }
    }

    fn op_some(&self, values: Vec<Value>) -> Result<Value, String> {
        let (arr, expr, threshold): (&[Value], &Expression, i64) = match values.as_slice() {
            [Value::Array(arr), Value::Function(expr)] => (arr, expr, 1),
            [Value::Array(arr), Value::Function(expr), Value::Int(min)] => (
                arr,
                expr,
                bigint_to_i64(min).ok_or("some threshold out of range")?,
            ),
            _ => return Err(format!("Unexpected input to some, got {:?}", values)),
        };
        let mut count = 0i64;
        for el in arr {
            if self.eval(expr, Some(el))?.is_truthy() {
                count += 1;
            }
        }
        Ok(Value::Bool(count >= threshold))
    }

    fn op_count(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr)] => Ok(Value::Int(BigInt::from(arr.len()))),
            [Value::Array(arr), Value::Function(expr)] => {
                let mut count = 0usize;
                for el in arr {
                    if self.eval(expr, Some(el))?.is_truthy() {
                        count += 1;
                    }
                }
                Ok(Value::Int(BigInt::from(count)))
            }
            _ => Err(format!("Unexpected input to count, got {:?}", values)),
        }
    }

    fn op_find(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr), Value::Function(expr)] => {
                for el in arr {
                    if self.eval(expr, Some(el))?.is_truthy() {
                        return Ok(el.clone());
                    }
                }
                Ok(Value::Null)
            }
            _ => Err(format!("Unexpected input to find, got {:?}", values)),
        }
    }

    fn op_map_values(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [] => Ok(Value::Null),
            [Value::Null] => Ok(Value::Null),
            [Value::Map(m)] => Ok(Value::Array(m.iter().map(|(_, v)| v.clone()).collect())),
            _ => Err(format!("Unexpected input for `values` got {:?}", values)),
        }
    }

    fn op_map_keys(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [] => Ok(Value::Null),
            [Value::Null] => Ok(Value::Null),
            [Value::Map(m)] => Ok(Value::Array(
                m.iter().map(|(k, _)| Value::Str(k.clone())).collect(),
            )),
            _ => Err(format!("Unexpected input for `keys` got {:?}", values)),
        }
    }

    fn op_get(&self, values: Vec<Value>) -> Result<Value, String> {
        // Scala handleGetOp only supports [Map, Str] -> value-or-null. The conformance
        // vectors also use [Map, Str, default]; we honor a 3rd default arg to match the
        // observed reference behavior (TS supports it).
        match values.as_slice() {
            [Value::Map(m), Value::Str(k)] => Ok(m
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null)),
            [Value::Map(m), Value::Str(k), default] => Ok(m
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| default.clone())),
            _ => Err(format!("Unexpected input to get, got {:?}", values)),
        }
    }

    fn op_length(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr)] => Ok(Value::Int(BigInt::from(arr.len()))),
            [Value::Str(s)] => Ok(Value::Int(BigInt::from(s.encode_utf16().count()))),
            _ => Err(format!("Unexpected input to length, got {:?}", values)),
        }
    }

    fn op_lower(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Str(s)] => Ok(Value::Str(s.to_lowercase())),
            _ => Err(format!("Unexpected input to lower, got {:?}", values)),
        }
    }

    fn op_upper(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Str(s)] => Ok(Value::Str(s.to_uppercase())),
            _ => Err(format!("Unexpected input to upper, got {:?}", values)),
        }
    }

    fn op_join(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr), Value::Str(sep)] => {
                let parts: Vec<String> = arr.iter().map(array_to_string).collect();
                Ok(Value::Str(parts.join(sep)))
            }
            _ => Err(format!("Unexpected input to join, got {:?}", values)),
        }
    }

    fn op_split(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Str(s), Value::Str(sep)] => {
                if sep.is_empty() {
                    return Err("Split separator cannot be empty".into());
                }
                // Scala uses split(quote(sep), -1): literal separator, keep trailing empties.
                let parts: Vec<Value> = s
                    .split(sep.as_str())
                    .map(|p| Value::Str(p.to_string()))
                    .collect();
                Ok(Value::Array(parts))
            }
            _ => Err(format!("Unexpected input to split, got {:?}", values)),
        }
    }

    fn op_default(&self, values: Vec<Value>) -> Result<Value, String> {
        for v in &values {
            if !matches!(v, Value::Null) && v.is_truthy() {
                return Ok(v.clone());
            }
        }
        Ok(Value::Null)
    }

    fn op_unique(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr)] => {
                let mut seen: Vec<Value> = Vec::new();
                for el in arr {
                    if !seen.iter().any(|x| x.deep_eq(el)) {
                        seen.push(el.clone());
                    }
                }
                Ok(Value::Array(seen))
            }
            _ => Err(format!("Unexpected input to unique, got {:?}", values)),
        }
    }

    fn op_slice(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr), Value::Int(start)] => {
                let s = bigint_to_i64(start).ok_or("slice start out of range")?;
                let len = arr.len() as i64;
                let start_idx = if s < 0 { (len + s).max(0) } else { s.min(len) };
                Ok(Value::Array(arr[start_idx as usize..].to_vec()))
            }
            [Value::Array(arr), Value::Int(start), Value::Int(end)] => {
                let s = bigint_to_i64(start).ok_or("slice start out of range")?;
                let e = bigint_to_i64(end).ok_or("slice end out of range")?;
                let len = arr.len() as i64;
                let start_idx = if s < 0 { (len + s).max(0) } else { s.min(len) };
                let end_idx = if e < 0 { (len + e).max(0) } else { e.min(len) };
                if end_idx <= start_idx {
                    Ok(Value::Array(Vec::new()))
                } else {
                    Ok(Value::Array(
                        arr[start_idx as usize..end_idx as usize].to_vec(),
                    ))
                }
            }
            _ => Err(format!("Unexpected input to slice, got {:?}", values)),
        }
    }

    fn op_reverse(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr)] => {
                let mut v = arr.clone();
                v.reverse();
                Ok(Value::Array(v))
            }
            _ => Err(format!("Unexpected input to reverse, got {:?}", values)),
        }
    }

    fn op_flatten(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Array(arr)] => {
                let mut out = Vec::new();
                for el in arr {
                    match el {
                        Value::Array(inner) => out.extend(inner.clone()),
                        other => out.push(other.clone()),
                    }
                }
                Ok(Value::Array(out))
            }
            _ => Err(format!("Unexpected input to flatten, got {:?}", values)),
        }
    }

    fn op_trim(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            // Scala String.trim removes chars <= U+0020 from both ends.
            [Value::Str(s)] => Ok(Value::Str(s.trim_matches(|c: char| c <= ' ').to_string())),
            _ => Err(format!("Unexpected input to trim, got {:?}", values)),
        }
    }

    fn op_starts_with(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Str(s), Value::Str(prefix)] => Ok(Value::Bool(s.starts_with(prefix.as_str()))),
            [Value::Str(_), Value::Null] => Ok(Value::Bool(false)),
            [Value::Null, _] => Ok(Value::Bool(false)),
            _ => Err(format!("Unexpected input to startsWith, got {:?}", values)),
        }
    }

    fn op_ends_with(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Str(s), Value::Str(suffix)] => Ok(Value::Bool(s.ends_with(suffix.as_str()))),
            [Value::Str(_), Value::Null] => Ok(Value::Bool(false)),
            [Value::Null, _] => Ok(Value::Bool(false)),
            _ => Err(format!("Unexpected input to endsWith, got {:?}", values)),
        }
    }

    fn op_has(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [Value::Map(m), Value::Str(key)] => Ok(Value::Bool(m.iter().any(|(k, _)| k == key))),
            _ => Err(format!("Unexpected input to has, got {:?}", values)),
        }
    }

    fn op_entries(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [] => Ok(Value::Null),
            [Value::Map(m)] => {
                let entries = m
                    .iter()
                    .map(|(k, v)| Value::Array(vec![Value::Str(k.clone()), v.clone()]))
                    .collect();
                Ok(Value::Array(entries))
            }
            _ => Err(format!("Unexpected input to entries, got {:?}", values)),
        }
    }

    fn op_typeof(&self, values: Vec<Value>) -> Result<Value, String> {
        match values.as_slice() {
            [v] => Ok(Value::Str(v.tag().to_string())),
            _ => Err(format!("Unexpected input to typeof, got {:?}", values)),
        }
    }

    fn op_exists(&self, values: Vec<Value>) -> Result<Value, String> {
        let result = match values.as_slice() {
            [Value::Array(arr)] => !arr.iter().any(|v| matches!(v, Value::Null)),
            _ => !values.iter().any(|v| matches!(v, Value::Null)),
        };
        Ok(Value::Bool(result))
    }

    fn op_missing(&self, values: Vec<Value>, ctx: Option<&Value>) -> Result<Value, String> {
        let list: &[Value] = match values.as_slice() {
            [Value::Array(arr)] => arr,
            _ => &values,
        };
        let mut missing = Vec::new();
        for field in list {
            if let Some(v) = self.field_if_missing(field, ctx)? {
                missing.push(v);
            }
        }
        Ok(Value::Array(missing))
    }

    fn op_missing_some(&self, values: Vec<Value>, ctx: Option<&Value>) -> Result<Value, String> {
        let (min_required, arr): (i64, &[Value]) = match values.as_slice() {
            [Value::Array(arr)] => (1, arr),
            [Value::Int(min), Value::Array(arr)] if min > &BigInt::from(0) => (
                bigint_to_i64(min).ok_or("missing_some min out of range")?,
                arr,
            ),
            _ => {
                return Err(format!(
                    "Unexpected input for `missing_some' got {:?}",
                    values
                ))
            }
        };
        let mut missing = Vec::new();
        for field in arr {
            if let Some(v) = self.field_if_missing(field, ctx)? {
                missing.push(v);
            }
        }
        let present = arr.len() as i64 - missing.len() as i64;
        if present >= min_required {
            Ok(Value::Array(Vec::new()))
        } else {
            Ok(Value::Array(missing))
        }
    }

    /// Returns Some(field) if the field (a key name) is missing from the data, else None.
    /// Mirrors `isFieldMissing`.
    fn field_if_missing(
        &self,
        field: &Value,
        ctx: Option<&Value>,
    ) -> Result<Option<Value>, String> {
        let key = match field {
            Value::Str(k) => k.clone(),
            Value::Int(k) => k.to_string(),
            Value::Float(k) => k.to_plain_string(),
            other => return Ok(Some(other.clone())),
        };
        let looked = self.get_var(&key, ctx)?;
        if matches!(looked, Value::Null) {
            Ok(Some(field.clone()))
        } else {
            Ok(None)
        }
    }
}

// --- free helpers -----------------------------------------------------------

fn is_primitive(v: &Value) -> bool {
    matches!(
        v,
        Value::Bool(_) | Value::Int(_) | Value::Float(_) | Value::Str(_)
    )
}

fn stringify_primitive(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(r) => r.to_plain_string(),
        Value::Str(s) => s.clone(),
        _ => String::new(),
    }
}

/// Stringification used by `join`. Mirrors handleJoinOp.arrayToString: collections and
/// functions become empty strings.
fn array_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(r) => r.to_plain_string(),
        Value::Str(s) => s.clone(),
        Value::Array(_) | Value::Map(_) | Value::Function(_) => String::new(),
    }
}

/// Get a child by path segment. Mirrors `getChild`: arrays by numeric index, maps by
/// key, everything else -> Null.
fn get_child(parent: &Value, segment: &str) -> Value {
    match parent {
        Value::Array(elems) => match segment.parse::<i64>() {
            Ok(idx) if idx >= 0 && (idx as usize) < elems.len() => elems[idx as usize].clone(),
            _ => Value::Null,
        },
        Value::Map(m) => m
            .iter()
            .find(|(k, _)| k == segment)
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// Merge two insertion-ordered maps: right overwrites left, preserving left order then
/// appending new right keys. (Scala uses `Map ++`, which is unordered; we keep a stable
/// order so structural/canonical output is deterministic.)
fn merge_maps(l: &[(String, Value)], r: &[(String, Value)]) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = l.to_vec();
    for (k, v) in r {
        if let Some(slot) = out.iter_mut().find(|(ek, _)| ek == k) {
            slot.1 = v.clone();
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

fn bigint_to_i64(v: &BigInt) -> Option<i64> {
    use num_traits::ToPrimitive;
    v.to_i64()
}

fn bigint_to_u32(v: &BigInt) -> Option<u32> {
    use num_traits::ToPrimitive;
    v.to_u32()
}

#[cfg(test)]
mod let_order_tests {
    use crate::{decode_expression, evaluate, Value};

    fn eval_str(expr_json: &str) -> Value {
        let json: serde_json::Value = serde_json::from_str(expr_json).unwrap();
        let expr = decode_expression(&json).unwrap();
        evaluate(&expr, &Value::Map(Vec::new())).unwrap()
    }

    /// Object-form `let` evaluates bindings in RFC-8785 sorted-key order (UTF-16),
    /// so `a` (=1) is bound before `b` (= a + 1 = 2) even though `b` is listed first.
    /// Insertion order would leave `a` unbound when `b` is evaluated.
    #[test]
    fn object_let_evaluates_bindings_in_sorted_key_order() {
        let v = eval_str(r#"{"let":[{"b":{"+":[{"var":"a"},1]},"a":1},{"var":"b"}]}"#);
        assert!(v.deep_eq(&Value::int_from_i64(2)), "got {:?}", v);
    }

    /// Keys are ordered by UTF-16 code units: 'a' (U+0061) before 'ä' (U+00E4).
    #[test]
    fn object_let_sorts_keys_by_utf16_code_units() {
        let v = eval_str(r#"{"let":[{"ä":{"+":[{"var":"a"},1]},"a":1},{"var":"ä"}]}"#);
        assert!(v.deep_eq(&Value::int_from_i64(2)), "got {:?}", v);
    }

    /// Array-form `let` keeps explicit insertion order (unchanged behaviour).
    #[test]
    fn array_let_keeps_insertion_order() {
        let v = eval_str(r#"{"let":[[["a",1],["b",{"+":[{"var":"a"},1]}]],{"var":"b"}]}"#);
        assert!(v.deep_eq(&Value::int_from_i64(2)), "got {:?}", v);
    }
}
