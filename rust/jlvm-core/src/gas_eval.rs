//! The gas-metered evaluator. Mirrors the Scala gas-aware stack
//! (`JsonLogicEvaluator.evaluateWithGas` -> `GasAwareSemantics` over the
//! tail-recursive `JsonLogicRuntime`) and must reproduce its reported
//! `gasUsed` EXACTLY — the shared vectors (`shared/gas_test_vectors.json`,
//! enforced by `tests/gas_differential.rs`) pin the equivalence.
//!
//! # Charging contract (normative per metakit PR #37)
//!
//! - Every operator application consumes EXACTLY ONCE from the shared gas
//!   counter: `base(op) + depth_penalty(new_depth) + input_scaled(op, args)`,
//!   atomically BEFORE the primitive runs (so out-of-gas fires before any
//!   input-scaled work: pairings, BLS aggregation, proof folds, string
//!   building), plus an output-scaled residual AFTER the primitive for
//!   split / merge / flatten / slice / substr only. Children pay for
//!   themselves while they are evaluated; ancestors never re-charge their
//!   subtree.
//! - `new_depth` = max(argument metric depths) + 1, where the metric depth
//!   propagates exactly as the Scala `GasMetrics` bookkeeping does (see
//!   "Metric-depth propagation" below).
//! - Variable lookups consume `var_access + #path_segments` once at lookup
//!   time, where the segment count follows Java `String.split("\\.")`
//!   semantics (trailing empty segments dropped; the empty key counts 1).
//!   A lookup that CANNOT afford its charge is swallowed by the runtime
//!   into the var default (or null) and consumes nothing — evaluation
//!   continues. This mirrors the Scala runtime, which treats a failed
//!   `getVar` as "missing variable".
//! - The lazily-evaluated `if` and `let` charge their flat base cost
//!   (`if_else`) exactly once per node at the dispatch site, BEFORE any
//!   child is evaluated and before argument-shape validation, with NO
//!   depth penalty: the penalty's input everywhere else is
//!   max(evaluated-argument metric depths) + 1, which is undefined at the
//!   lazy dispatch site (children unevaluated; if/let are depth-transparent
//!   in the metrics flow). Lazy evaluation is unchanged: the condition /
//!   bindings / taken branch pay for themselves, untaken branches pay
//!   nothing.
//! - Reported gas-used is the gas-counter delta. All cost arithmetic is u64
//!   saturating.
//!
//! # Metric-depth propagation (feeds ancestors' depth penalties)
//!
//! Mirroring the Scala `ResultContext.WithGas` metrics flow through the
//! tail-recursive runtime:
//!
//! - constants and wrapped callbacks: depth 0;
//! - var lookups (both key forms): depth 0;
//! - ARRAY literals: max of element depths; OBJECT literals: depth 0 (the
//!   runtime rebuilds the map with `pure`, dropping element metrics);
//! - `if`: the taken branch's depth (condition metrics dropped); untaken
//!   chain with no else: depth 0;
//! - `let`: the result expression's depth (binding metrics dropped);
//! - operator applications: `new_depth`, except the callback ops whose
//!   handlers keep per-run metrics — `map`, `reduce`, `all`, `none` — which
//!   yield `max(new_depth, max(run depths))`, where each callback run is
//!   wrapped at `semantics_depth + 2` (the Scala `evaluateGasAware` boundary
//!   applies `withDepth(d + 1)` with `d = current + 1`). The handlers for
//!   `filter` / `some` / `find` / `count` drop run metrics (Scala uses
//!   `extractValue`), so they yield exactly `new_depth`.

use std::cell::Cell;
use std::fmt;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::eval::Evaluator;
use crate::expression::{Expression, VarKey};
use crate::gas::GasConfig;
use crate::ops::is_callback_arg;
use crate::value::Value;

/// Total gas consumed by an evaluation (the gas-counter delta).
pub type GasUsed = u64;

/// Metered-evaluation error: gas exhaustion is DISTINCT from ordinary
/// evaluation failure, mirroring Scala's `GasExhaustedException` subtype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasError {
    /// The gas counter could not afford a charge. `required` is the cost of
    /// the charge that failed; `available` the gas remaining at that point.
    Exhausted { required: u64, available: u64 },
    /// Ordinary (non-gas) evaluation failure.
    Eval(String),
}

impl fmt::Display for GasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GasError::Exhausted {
                required,
                available,
            } => write!(
                f,
                "Gas exhausted: required {}, available {}",
                required, available
            ),
            GasError::Eval(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for GasError {}

/// Evaluate `expr` against `data` under `gas_limit` with the default gas
/// schedule, returning the result value and the exact gas consumed.
pub fn evaluate_with_gas(
    expr: &Expression,
    data: &Value,
    gas_limit: u64,
) -> Result<(Value, GasUsed), GasError> {
    evaluate_with_gas_config(expr, data, gas_limit, &GasConfig::default())
}

/// [`evaluate_with_gas`] with an explicit gas schedule.
pub fn evaluate_with_gas_config(
    expr: &Expression,
    data: &Value,
    gas_limit: u64,
    config: &GasConfig,
) -> Result<(Value, GasUsed), GasError> {
    let metered = Metered {
        inner: Evaluator::new(data),
        config,
        remaining: Cell::new(gas_limit),
        rec_depth: Cell::new(0),
    };
    let (value, _depth) = metered.eval_gas_aware(expr, None, 0)?;
    Ok((value, gas_limit - metered.remaining.get()))
}

struct Metered<'a> {
    inner: Evaluator<'a>,
    config: &'a GasConfig,
    remaining: Cell<u64>,
    /// Current `eval` recursion depth, guarded by [`crate::eval::MAX_EVAL_DEPTH`]
    /// IDENTICALLY to the un-metered evaluator. Distinct from both the gas
    /// metric depth and `sem_depth` (which only advances at callback
    /// boundaries) — this counts every recursive `eval` step.
    rec_depth: Cell<u32>,
}

/// An evaluated value together with its metric depth (see module docs).
type Outcome = Result<(Value, u32), GasError>;

impl<'a> Metered<'a> {
    /// Atomically consume `cost` or fail with the distinct exhaustion error.
    /// Mirrors `GasLimit.consume` via the shared `Ref`.
    fn consume(&self, cost: u64) -> Result<(), GasError> {
        let available = self.remaining.get();
        if available >= cost {
            self.remaining.set(available - cost);
            Ok(())
        } else {
            Err(GasError::Exhausted {
                required: cost,
                available,
            })
        }
    }

    /// One `evaluateGasAware` boundary: a full runtime run at semantics depth
    /// `depth`, with the result's metric depth raised to at least `depth + 1`
    /// (Scala's `withDepth(depth + 1)`). Used for the top-level entry and for
    /// every callback run (at `semantics depth + 1`).
    fn eval_gas_aware(&self, expr: &Expression, ctx: Option<&Value>, depth: u32) -> Outcome {
        let (value, metric_depth) = self.eval(expr, ctx, depth)?;
        Ok((value, metric_depth.max(depth + 1)))
    }

    /// The runtime: expression traversal at semantics depth `sem_depth`
    /// (`GasAwareSemantics.currentDepth`, advanced only across callback
    /// boundaries). Mirrors `JsonLogicRuntime.evaluate`. Depth-guarded by
    /// [`crate::eval::MAX_EVAL_DEPTH`], identically to the un-metered
    /// evaluator (a normal `GasError::Eval`, distinct from gas exhaustion).
    fn eval(&self, expr: &Expression, ctx: Option<&Value>, sem_depth: u32) -> Outcome {
        let depth = self.rec_depth.get();
        if depth >= crate::eval::MAX_EVAL_DEPTH {
            return Err(GasError::Eval(format!(
                "Recursion depth limit exceeded ({})",
                crate::eval::MAX_EVAL_DEPTH
            )));
        }
        self.rec_depth.set(depth + 1);
        let result = self.eval_node(expr, ctx, sem_depth);
        self.rec_depth.set(depth);
        result
    }

    fn eval_node(&self, expr: &Expression, ctx: Option<&Value>, sem_depth: u32) -> Outcome {
        match expr {
            Expression::Const(v) => Ok((v.clone(), 0)),
            Expression::Array(elems) => {
                let mut out = Vec::with_capacity(elems.len());
                let mut max_depth = 0u32;
                for e in elems {
                    let (v, d) = self.eval(e, ctx, sem_depth)?;
                    max_depth = max_depth.max(d);
                    out.push(v);
                }
                Ok((Value::Array(out), max_depth))
            }
            Expression::Map(entries) => {
                // Element charges apply, but the runtime rebuilds the map with
                // `pure`: the literal's metric depth is 0.
                let mut out = Vec::with_capacity(entries.len());
                for (k, e) in entries {
                    let (v, _d) = self.eval(e, ctx, sem_depth)?;
                    out.push((k.clone(), v));
                }
                Ok((Value::Map(out), 0))
            }
            Expression::Var { key, default } => {
                let key_str = match key {
                    VarKey::Path(s) => s.clone(),
                    VarKey::Expr(e) => {
                        // The key expression's metrics are dropped by the
                        // runtime (only its gas consumption remains).
                        let (kv, _d) = self.eval(e, ctx, sem_depth)?;
                        match kv {
                            Value::Str(name) => name,
                            Value::Array(items) => match items.first() {
                                Some(Value::Str(name)) => name.clone(),
                                _ => {
                                    return Err(GasError::Eval(format!(
                                        "Got non-string input: {:?}",
                                        items
                                    )))
                                }
                            },
                            v => {
                                return Err(GasError::Eval(format!(
                                    "Got non-string input: {:?}",
                                    v
                                )))
                            }
                        }
                    }
                };
                self.metered_lookup(&key_str, default.as_ref(), ctx)
            }
            Expression::Apply { op, args } => match op.as_str() {
                "if" => self.eval_if(args, ctx, sem_depth),
                "let" => self.eval_let(args, ctx, sem_depth),
                _ => self.eval_apply(op, args, ctx, sem_depth),
            },
        }
    }

    /// Metered variable lookup: charge `var_access + #segments` ONCE, then look
    /// up. A lookup that cannot afford the charge consumes nothing and is
    /// swallowed into the default (or null) — the runtime treats a failed
    /// `getVar` as a missing variable and evaluation CONTINUES. Result metric
    /// depth is always 0.
    fn metered_lookup(&self, key: &str, default: Option<&Value>, ctx: Option<&Value>) -> Outcome {
        let cost = self
            .config
            .var_access
            .saturating_add(java_split_dot_segments(key));
        if self.consume(cost).is_err() {
            // Swallowed: nothing was consumed; missing-variable semantics.
            return Ok((default.cloned().unwrap_or(Value::Null), 0));
        }
        let raw = self.inner.get_var(key, ctx).map_err(GasError::Eval)?;
        let value = if !key.is_empty() && matches!(raw, Value::Null) {
            default.cloned().unwrap_or(Value::Null)
        } else {
            raw
        };
        Ok((value, 0))
    }

    /// Lazy if/else chain. The `if` node itself charges its flat base cost
    /// once at dispatch — no depth penalty (undefined at the lazy dispatch
    /// site), before the arg-count check, mirroring the Scala runtime's
    /// `chargeBaseThen` wrapping. The condition's metric depth is dropped;
    /// the taken branch's flows through.
    fn eval_if(&self, args: &[Expression], ctx: Option<&Value>, sem_depth: u32) -> Outcome {
        self.consume(self.config.if_else)?;
        if args.len() < 2 {
            return Err(GasError::Eval(format!(
                "Invalid arguments for if/else operation: expected at least 2 args, got {}",
                args.len()
            )));
        }
        let mut rest = args;
        loop {
            match rest {
                [cond, then, tail @ ..] => {
                    let (c, _d) = self.eval(cond, ctx, sem_depth)?;
                    if c.is_truthy() {
                        return self.eval(then, ctx, sem_depth);
                    }
                    match tail {
                        [] => return Ok((Value::Null, 0)),
                        [else_branch] => return self.eval(else_branch, ctx, sem_depth),
                        _ => rest = tail,
                    }
                }
                _ => {
                    return Err(GasError::Eval(
                        "If/else malformed: no remaining expressions".into(),
                    ))
                }
            }
        }
    }

    /// `let` with sequential scope-aware bindings. The `let` node itself
    /// charges its flat base cost once at dispatch — no depth penalty
    /// (undefined at the lazy dispatch site), before binding-shape
    /// validation, mirroring the Scala runtime's `chargeBaseThen` wrapping.
    /// Binding metric depths are dropped; the result expression's flows
    /// through. Mirrors the runtime's let handling (both surface forms;
    /// object-form bindings in RFC-8785 sorted-key order).
    fn eval_let(&self, args: &[Expression], ctx: Option<&Value>, sem_depth: u32) -> Outcome {
        self.consume(self.config.if_else)?;
        enum Bindings<'b> {
            Sorted(Vec<&'b (String, Expression)>),
            Pairs(&'b [Expression]),
        }
        let (bindings, result_expr) = match args {
            [Expression::Array(bindings), result] => (Bindings::Pairs(bindings), result),
            [Expression::Map(entries), result] => {
                let mut sorted: Vec<&(String, Expression)> = entries.iter().collect();
                sorted.sort_by(|a, b| crate::canonical::utf16_cmp(&a.0, &b.0));
                (Bindings::Sorted(sorted), result)
            }
            _ => {
                return Err(GasError::Eval(
                    "let requires [[bindings...], resultExpr]".into(),
                ))
            }
        };

        let mut acc: Vec<(String, Value)> = Vec::new();
        let bind = |name: &str, value_expr: &Expression, acc: &mut Vec<(String, Value)>| {
            let binding_ctx = self.inner.let_ctx(ctx, acc);
            let (v, _d) = self.eval(value_expr, binding_ctx.as_ref(), sem_depth)?;
            acc.push((name.to_string(), v));
            Ok::<(), GasError>(())
        };
        match bindings {
            Bindings::Sorted(entries) => {
                for (name, value_expr) in entries {
                    bind(name, value_expr, &mut acc)?;
                }
            }
            Bindings::Pairs(pairs) => {
                for binding in pairs {
                    match binding {
                        Expression::Array(pair) => match pair.as_slice() {
                            [Expression::Const(Value::Str(name)), value_expr] => {
                                bind(name, value_expr, &mut acc)?;
                            }
                            _ => {
                                return Err(GasError::Eval(format!(
                                    "let binding must be [name, expr], got: {:?}",
                                    pair
                                )))
                            }
                        },
                        other => {
                            return Err(GasError::Eval(format!(
                                "let binding must be [name, expr], got: {:?}",
                                other
                            )))
                        }
                    }
                }
            }
        }
        let result_ctx = self.inner.let_ctx(ctx, &acc).unwrap_or(Value::Map(acc));
        self.eval(result_expr, Some(&result_ctx), sem_depth)
    }

    /// General operator application: evaluate args (wrapping callback
    /// positions, which carry metric depth 0), then charge-and-apply.
    fn eval_apply(
        &self,
        op: &str,
        args: &[Expression],
        ctx: Option<&Value>,
        sem_depth: u32,
    ) -> Outcome {
        let mut values: Vec<Value> = Vec::with_capacity(args.len());
        let mut arg_max_depth = 0u32;
        for (idx, arg) in args.iter().enumerate() {
            if is_callback_arg(op, idx) {
                match arg {
                    Expression::Const(Value::Function(f)) => {
                        values.push(Value::Function(f.clone()))
                    }
                    other => values.push(Value::Function(Box::new(other.clone()))),
                }
            } else {
                let (v, d) = self.eval(arg, ctx, sem_depth)?;
                arg_max_depth = arg_max_depth.max(d);
                values.push(v);
            }
        }
        self.apply_op(op, values, arg_max_depth, ctx, sem_depth)
    }

    /// The charge-once / pre-charge core. Mirrors `GasAwareSemantics.applyOp`.
    fn apply_op(
        &self,
        op: &str,
        values: Vec<Value>,
        arg_max_depth: u32,
        ctx: Option<&Value>,
        sem_depth: u32,
    ) -> Outcome {
        let base = self
            .config
            .op_base_cost(op)
            .ok_or_else(|| GasError::Eval(format!("Unsupported operator: {}", op)))?;
        let new_depth = arg_max_depth + 1;
        // Everything derivable from the (already evaluated, already paid-for)
        // inputs is pre-charged atomically BEFORE the primitive runs.
        let pre = base
            .saturating_add(self.config.depth_penalty(new_depth as u64))
            .saturating_add(self.input_scaled_cost(op, &values));
        self.consume(pre)?;

        let (result, runs_depth) = self.run_primitive(op, values, ctx, sem_depth)?;

        // Residual component only observable on the produced value; the work it
        // prices is bounded by inputs that were already paid for.
        self.consume(self.output_scaled_cost(op, &result))?;

        Ok((result, new_depth.max(runs_depth)))
    }

    /// Run the primitive for `op`. Callback ops are implemented here so their
    /// per-element runs charge the shared counter (each run is one
    /// `eval_gas_aware` boundary at `sem_depth + 1`); everything else is
    /// delegated verbatim to the un-metered evaluator. Returns the result and
    /// the propagated run depth (0 for ops that keep no run metrics).
    fn run_primitive(
        &self,
        op: &str,
        values: Vec<Value>,
        ctx: Option<&Value>,
        sem_depth: u32,
    ) -> Outcome {
        let cb_depth = sem_depth + 1;
        match (op, values.as_slice()) {
            ("map", [Value::Array(arr), Value::Function(expr)]) => {
                let mut out = Vec::with_capacity(arr.len());
                let mut runs_depth = 0u32;
                for el in arr {
                    let (v, d) = self.eval_gas_aware(expr, Some(el), cb_depth)?;
                    runs_depth = runs_depth.max(d);
                    out.push(v);
                }
                Ok((Value::Array(out), runs_depth))
            }
            ("filter", [Value::Array(arr), Value::Function(expr)]) => {
                // Run metrics dropped (Scala handleFilterOp uses extractValue).
                let mut out = Vec::new();
                for el in arr {
                    if self.eval_gas_aware(expr, Some(el), cb_depth)?.0.is_truthy() {
                        out.push(el.clone());
                    }
                }
                Ok((Value::Array(out), 0))
            }
            ("reduce", [Value::Array(_), Value::Function(_)])
            | ("reduce", [Value::Array(_), Value::Function(_), _]) => {
                let (arr, expr, init): (&[Value], &Expression, Option<&Value>) =
                    match values.as_slice() {
                        [Value::Array(arr), Value::Function(expr)] => (arr, expr, None),
                        [Value::Array(arr), Value::Function(expr), init] if is_primitive(init) => {
                            (arr, expr, Some(init))
                        }
                        _ => {
                            return Err(GasError::Eval(format!(
                                "Unexpected input to reduce, got {:?}",
                                values
                            )))
                        }
                    };
                let (start, mut acc): (usize, Value) = match init {
                    Some(v) => (0, v.clone()),
                    None => {
                        if arr.is_empty() {
                            return Ok((Value::Null, 0));
                        }
                        (1, arr[0].clone())
                    }
                };
                let mut runs_depth = 0u32;
                for item in &arr[start..] {
                    let run_ctx = Value::Map(vec![
                        ("current".to_string(), item.clone()),
                        ("accumulator".to_string(), acc.clone()),
                    ]);
                    let (v, d) = self.eval_gas_aware(expr, Some(&run_ctx), cb_depth)?;
                    runs_depth = runs_depth.max(d);
                    acc = v;
                }
                Ok((acc, runs_depth))
            }
            ("all", [Value::Null, Value::Function(_)]) => Ok((Value::Bool(false), 0)),
            ("all", [Value::Array(arr), Value::Function(expr)]) => {
                // Empty array -> false (JSON Logic reference behavior).
                if arr.is_empty() {
                    return Ok((Value::Bool(false), 0));
                }
                // NO short-circuit: Scala traverses (and charges) every element.
                let mut all_truthy = true;
                let mut runs_depth = 0u32;
                for el in arr {
                    let (v, d) = self.eval_gas_aware(expr, Some(el), cb_depth)?;
                    runs_depth = runs_depth.max(d);
                    all_truthy = all_truthy && v.is_truthy();
                }
                Ok((Value::Bool(all_truthy), runs_depth))
            }
            ("none", [Value::Array(arr), Value::Function(expr)]) => {
                // NO short-circuit, run metrics kept (Scala handleNoneOp maps in Result).
                let mut none_truthy = true;
                let mut runs_depth = 0u32;
                for el in arr {
                    let (v, d) = self.eval_gas_aware(expr, Some(el), cb_depth)?;
                    runs_depth = runs_depth.max(d);
                    none_truthy = none_truthy && !v.is_truthy();
                }
                Ok((Value::Bool(none_truthy), runs_depth))
            }
            ("some", [Value::Array(_), Value::Function(_)])
            | ("some", [Value::Array(_), Value::Function(_), Value::Int(_)]) => {
                let (arr, expr, threshold): (&[Value], &Expression, i64) = match values.as_slice() {
                    [Value::Array(arr), Value::Function(expr)] => (arr, expr, 1),
                    [Value::Array(arr), Value::Function(expr), Value::Int(min)] => (
                        arr,
                        expr,
                        min.to_i64()
                            .ok_or_else(|| GasError::Eval("some threshold out of range".into()))?,
                    ),
                    _ => unreachable!(),
                };
                // NO short-circuit; run metrics dropped (extractValue).
                let mut count = 0i64;
                for el in arr {
                    if self.eval_gas_aware(expr, Some(el), cb_depth)?.0.is_truthy() {
                        count += 1;
                    }
                }
                Ok((Value::Bool(count >= threshold), 0))
            }
            ("find", [Value::Array(arr), Value::Function(expr)]) => {
                // SHORT-CIRCUITS on the first match (Scala foldLeftM skips the
                // rest); run metrics dropped.
                for el in arr {
                    if self.eval_gas_aware(expr, Some(el), cb_depth)?.0.is_truthy() {
                        return Ok((el.clone(), 0));
                    }
                }
                Ok((Value::Null, 0))
            }
            ("count", [Value::Array(arr), Value::Function(expr)]) => {
                // NO short-circuit; run metrics dropped.
                let mut count = 0usize;
                for el in arr {
                    if self.eval_gas_aware(expr, Some(el), cb_depth)?.0.is_truthy() {
                        count += 1;
                    }
                }
                Ok((Value::Int(BigInt::from(count)), 0))
            }
            // Every other primitive (including 1-arg `count`, `missing` /
            // `missing_some` — whose internal lookups are UN-metered in Scala —
            // and all crypto opcodes) is exactly the un-metered evaluator's.
            _ => self
                .inner
                .apply_op(op, values, ctx)
                .map(|v| (v, 0))
                .map_err(GasError::Eval),
        }
    }

    /// Size-scaled cost derivable from the argument values ALONE, consumed
    /// BEFORE the primitive runs. Mirrors `GasAwareSemantics.getInputScaledCost`
    /// case-for-case. String lengths are UTF-16 code units (Scala `String.length`).
    fn input_scaled_cost(&self, op: &str, args: &[Value]) -> u64 {
        let c = self.config;
        match (op, args) {
            // cat output length == sum of the coerced input string lengths.
            ("cat", _) => c.size_cost(
                args.iter()
                    .map(coerced_string_length)
                    .fold(0u64, u64::saturating_add),
            ),
            // join output length == element lengths + separators.
            ("join", [Value::Array(arr), Value::Str(sep)]) => c.size_cost(
                arr.iter()
                    .map(coerced_string_length)
                    .fold(0u64, u64::saturating_add)
                    .saturating_add(
                        utf16_len(sep).saturating_mul(arr.len().saturating_sub(1) as u64),
                    ),
            ),
            ("entries", [Value::Map(m)]) => c.size_cost(2 * m.len() as u64),
            ("unique", [Value::Array(arr)]) => c.size_cost(arr.len() as u64),
            // pow charges |exponent|. (Scala uses BigInt.toLong, which WRAPS for
            // magnitudes beyond 2^63; we saturate instead — pow rejects any
            // exponent magnitude > 999 before computing, so the charge only
            // differs on programs that fail anyway.)
            ("pow", [_, Value::Int(exp)]) => bigint_magnitude_saturating(exp),
            ("pow", [_, Value::Float(exp)]) => bigint_magnitude_saturating(&exp.numerator),
            ("pow", _) => 0,
            ("+" | "*" | "-", [Value::Array(arr)]) => c.size_cost(arr.len() as u64),
            ("+" | "*" | "-", list) if list.len() > 1 => c.size_cost((list.len() - 1) as u64),
            ("+" | "*" | "-", _) => 0,
            (
                "map" | "filter" | "all" | "none" | "some" | "find" | "count",
                [Value::Array(arr), ..],
            ) => c.size_cost(arr.len() as u64),
            ("reverse", [Value::Array(arr)]) => c.size_cost(arr.len() as u64),
            ("in", [_, Value::Array(arr)]) => c.size_cost(arr.len() as u64),
            ("in", [_, Value::Str(s)]) => c.size_cost(utf16_len(s) / 10),
            ("intersect", [Value::Array(a), Value::Array(b)]) => {
                c.size_cost((a.len() as u64).saturating_add(b.len() as u64))
            }
            ("reduce", [Value::Array(arr), ..]) => c.size_cost(arr.len() as u64),
            ("max" | "min", [Value::Array(arr)]) => c.size_cost(arr.len() as u64),
            ("max" | "min", list) => c.size_cost(list.len() as u64),
            ("values" | "keys", [Value::Map(m)]) => c.size_cost(m.len() as u64),
            // poseidon scales with the number of inputs.
            ("poseidon", [Value::Array(arr)]) => {
                c.poseidon_per_input.saturating_mul(arr.len() as u64)
            }
            ("poseidon", list) => c.poseidon_per_input.saturating_mul(list.len() as u64),
            // pmt_verify scales with path length (= number of siblings).
            ("pmt_verify", [_, _, _, Value::Array(siblings)]) => {
                c.pmt_per_sibling.saturating_mul(siblings.len() as u64)
            }
            // bn254_pairing scales with the number of (G1, G2) pairs. A lone
            // array is the pairs list only when every element is itself a pair.
            ("bn254_pairing", [Value::Array(pairs)])
                if pairs.iter().all(|p| matches!(p, Value::Array(_))) =>
            {
                c.bn254_pairing_per_pair.saturating_mul(pairs.len() as u64)
            }
            ("bn254_pairing", list) => c.bn254_pairing_per_pair.saturating_mul(list.len() as u64),
            // bls_aggregate_verify scales with the number of public keys.
            ("bls_aggregate_verify", [Value::Array(pks), _, _]) => {
                c.bls_aggregate_per_key.saturating_mul(pks.len() as u64)
            }
            // smt_verify scales with the authentication-path depth.
            ("smt_verify", [_, Value::Map(proof)]) => match map_get(proof, "siblings") {
                Some(Value::Array(siblings)) => {
                    c.smt_per_sibling.saturating_mul(siblings.len() as u64)
                }
                _ => 0,
            },
            // mpt_verify scales with the number of nodes in the proof witness.
            ("mpt_verify", [_, _, _, Value::Map(proof)]) => match map_get(proof, "witness") {
                Some(Value::Array(witness)) => c.mpt_per_node.saturating_mul(witness.len() as u64),
                _ => 0,
            },
            // mpt_prefix_verify scales with the number of entries proven complete.
            ("mpt_prefix_verify", [_, _, Value::Map(entries), _]) => {
                c.mpt_prefix_per_entry.saturating_mul(entries.len() as u64)
            }
            // sigma_verify scales with the PROPOSITION-TREE shape: one per-leaf charge
            // per DLog / DHTuple leaf + one per-node charge per connective. Derived
            // from the first argument (the proposition tree) ALONE and pre-charged
            // BEFORE any curve arithmetic, so out-of-gas is raised before the per-leaf
            // scalar-mul work (the DoS bound). A malformed/non-tree first arg charges
            // 0 here and the verifier raises the encoding fault. Mirrors the Scala
            // `getInputScaledCost(SigmaVerifyOp)` / `sigmaPropShape` exactly.
            ("sigma_verify", [prop, _, _]) => {
                let (dlog_leaves, dhtuple_leaves, nodes) = sigma_prop_shape(prop);
                c.sigma_verify_per_dlog_leaf
                    .saturating_mul(dlog_leaves)
                    .saturating_add(
                        c.sigma_verify_per_dhtuple_leaf
                            .saturating_mul(dhtuple_leaves),
                    )
                    .saturating_add(c.sigma_verify_per_node.saturating_mul(nodes))
            }
            _ => 0,
        }
    }

    /// Residual size-scaled cost only observable on the PRODUCED value,
    /// consumed AFTER the primitive. Mirrors `getOutputScaledCost`.
    fn output_scaled_cost(&self, op: &str, result: &Value) -> u64 {
        let c = self.config;
        match (op, result) {
            ("split", Value::Array(arr)) => c.size_cost((arr.len() as u64).saturating_mul(2)),
            ("merge", Value::Array(arr)) => c.size_cost(arr.len() as u64),
            ("merge", Value::Map(m)) => c.size_cost(m.len() as u64),
            ("flatten", Value::Array(arr)) => c.size_cost(arr.len() as u64),
            ("slice", Value::Array(arr)) => c.size_cost(arr.len() as u64),
            ("substr", Value::Str(s)) => c.size_cost(utf16_len(s)),
            _ => 0,
        }
    }
}

// --- helpers -----------------------------------------------------------------

fn is_primitive(v: &Value) -> bool {
    matches!(
        v,
        Value::Bool(_) | Value::Int(_) | Value::Float(_) | Value::Str(_)
    )
}

fn map_get<'v>(m: &'v [(String, Value)], key: &str) -> Option<&'v Value> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Count `(dlog_leaves, dhtuple_leaves, connective_nodes)` in a `sigma_verify`
/// proposition tree, to pre-charge per-leaf / per-node gas from the shape.
/// Recognises the same node schema the verifier parses
/// (`{"type": dlog|dhtuple|and|or|threshold, ...}`); any unrecognised shape
/// contributes `(0, 0, 0)` (the verifier will raise the structural fault). A
/// connective counts as ONE node INCLUDING the root, then folds its `children`.
/// Bounded recursion over the already-materialised value tree — a byte-for-byte
/// mirror of the Scala `GasAwareSemantics.sigmaPropShape`.
fn sigma_prop_shape(v: &Value) -> (u64, u64, u64) {
    match v {
        Value::Map(m) => match map_get(m, "type") {
            Some(Value::Str(t)) if t == "dlog" => (1, 0, 0),
            Some(Value::Str(t)) if t == "dhtuple" => (0, 1, 0),
            Some(Value::Str(t)) if t == "and" || t == "or" || t == "threshold" => {
                let children = match map_get(m, "children") {
                    Some(Value::Array(cs)) => cs.as_slice(),
                    _ => &[],
                };
                children.iter().fold((0u64, 0u64, 1u64), |(d, t, n), c| {
                    let (cd, ct, cn) = sigma_prop_shape(c);
                    (d + cd, t + ct, n + cn)
                })
            }
            _ => (0, 0, 0),
        },
        _ => (0, 0, 0),
    }
}

fn utf16_len(s: &str) -> u64 {
    s.encode_utf16().count() as u64
}

/// Length of the string a value coerces to in `cat` / `join` (mirrors
/// `coercedStringLength`: collections / functions price at zero). String
/// lengths are UTF-16 code units, matching Scala `String.length`.
fn coerced_string_length(v: &Value) -> u64 {
    match v {
        Value::Null => 0,
        Value::Bool(b) => {
            if *b {
                4 // "true"
            } else {
                5 // "false"
            }
        }
        Value::Int(i) => i.to_string().len() as u64,
        Value::Float(r) => r.to_plain_string().len() as u64,
        Value::Str(s) => utf16_len(s),
        _ => 0,
    }
}

/// Number of path segments of a var key, with Java `String.split("\\.")`
/// semantics (the Scala meter charges `key.split("\\.").length`):
///   - the empty key splits to `[""]` -> 1 segment;
///   - trailing empty segments are dropped (`"a."` -> 1, `"."` -> 0);
///   - leading/inner empties are kept (`".a"` -> 2, `"a..b"` -> 3).
fn java_split_dot_segments(key: &str) -> u64 {
    if key.is_empty() {
        return 1;
    }
    let parts: Vec<&str> = key.split('.').collect();
    let mut n = parts.len();
    while n > 0 && parts[n - 1].is_empty() {
        n -= 1;
    }
    n as u64
}

/// |v| as u64, saturating at u64::MAX.
fn bigint_magnitude_saturating(v: &BigInt) -> u64 {
    v.magnitude().to_u64().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_expression, decode_value};

    fn run(expr_json: &str, data_json: &str, limit: u64) -> Result<(Value, u64), GasError> {
        let expr_v: serde_json::Value = serde_json::from_str(expr_json).unwrap();
        let data_v: serde_json::Value = serde_json::from_str(data_json).unwrap();
        let expr = decode_expression(&expr_v).unwrap();
        let data = decode_value(&data_v);
        evaluate_with_gas(&expr, &data, limit)
    }

    #[test]
    fn java_split_semantics() {
        assert_eq!(java_split_dot_segments(""), 1);
        assert_eq!(java_split_dot_segments("a"), 1);
        assert_eq!(java_split_dot_segments("a.b"), 2);
        assert_eq!(java_split_dot_segments("a.b.c"), 3);
        assert_eq!(java_split_dot_segments("a."), 1);
        assert_eq!(java_split_dot_segments("."), 0);
        assert_eq!(java_split_dot_segments(".a"), 2);
        assert_eq!(java_split_dot_segments("a..b"), 3);
    }

    #[test]
    fn sigma_prop_shape_counting() {
        let shape = |json: &str| {
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            sigma_prop_shape(&decode_value(&v))
        };
        // Leaves: one of their kind, no node.
        assert_eq!(shape(r#"{"type":"dlog","pk":"0x00"}"#), (1, 0, 0));
        assert_eq!(shape(r#"{"type":"dhtuple","g":"0x00"}"#), (0, 1, 0));
        // A connective counts as one node INCLUDING the root, then folds children.
        assert_eq!(
            shape(r#"{"type":"and","children":[{"type":"dlog"},{"type":"dhtuple"}]}"#),
            (1, 1, 1)
        );
        // OR ring n=3: 3 dlog leaves under 1 node.
        assert_eq!(
            shape(r#"{"type":"or","children":[{"type":"dlog"},{"type":"dlog"},{"type":"dlog"}]}"#),
            (3, 0, 1)
        );
        // THRESHOLD 2-of-3: same shape as the 3-leaf ring (k is irrelevant to the count).
        assert_eq!(
            shape(
                r#"{"type":"threshold","k":2,"children":[{"type":"dlog"},{"type":"dlog"},{"type":"dlog"}]}"#
            ),
            (3, 0, 1)
        );
        // Nested (A or B) and (C or D): 4 dlog leaves, 3 nodes (1 and + 2 or).
        assert_eq!(
            shape(
                r#"{"type":"and","children":[{"type":"or","children":[{"type":"dlog"},{"type":"dlog"}]},{"type":"or","children":[{"type":"dlog"},{"type":"dlog"}]}]}"#
            ),
            (4, 0, 3)
        );
        // Unrecognised / malformed shapes contribute nothing (verifier raises the fault).
        assert_eq!(
            shape(r#"{"type":"xor","children":[{"type":"dlog"}]}"#),
            (0, 0, 0)
        );
        assert_eq!(shape(r#"{"foo":"bar"}"#), (0, 0, 0));
        assert_eq!(shape(r#"42"#), (0, 0, 0));
        // Connective with no/absent children array: just the root node.
        assert_eq!(shape(r#"{"type":"and"}"#), (0, 0, 1));
    }

    #[test]
    fn constants_are_free() {
        assert_eq!(run("42", "{}", 10).unwrap().1, 0);
        assert_eq!(run("[1, 2, 3]", "{}", 10).unwrap().1, 0);
    }

    #[test]
    fn nested_arithmetic_charges_once_per_op() {
        // + base 5 + depth 5 + size 1 = 11; nested: 11 + (5 + 10 + 1) = 27.
        assert_eq!(run("{\"+\": [1, 2]}", "{}", 100).unwrap().1, 11);
        assert_eq!(
            run("{\"+\": [1, {\"+\": [2, 3]}]}", "{}", 100).unwrap().1,
            27
        );
    }

    #[test]
    fn oog_is_distinct_error() {
        match run("{\"+\": [1, {\"+\": [2, 3]}]}", "{}", 26) {
            Err(GasError::Exhausted { .. }) => {}
            other => panic!("expected Exhausted, got {:?}", other),
        }
    }

    #[test]
    fn gas_starved_var_lookup_is_swallowed() {
        // Lookup costs 3 (varAccess 2 + 1 segment) but only 2 remain: the
        // runtime swallows the failure into null and consumes nothing.
        let (v, used) = run("{\"var\": \"x\"}", "{\"x\": 42}", 2).unwrap();
        assert!(matches!(v, Value::Null));
        assert_eq!(used, 0);
    }

    #[test]
    fn unmetered_evaluate_is_untouched() {
        // The plain evaluator has no gas concept and runs arbitrarily deep work.
        let expr_v: serde_json::Value =
            serde_json::from_str("{\"+\": [1, {\"+\": [2, 3]}]}").unwrap();
        let expr = decode_expression(&expr_v).unwrap();
        let v = crate::evaluate(&expr, &Value::Map(Vec::new())).unwrap();
        assert!(v.deep_eq(&Value::int_from_i64(6)));
    }
}
