/**
 * The gas-metered evaluator. Port of rust/jlvm-core/src/gas_eval.rs, which
 * mirrors the Scala gas-aware stack (`JsonLogicEvaluator.evaluateWithGas` ->
 * `GasAwareSemantics` over the tail-recursive `JsonLogicRuntime`) and must
 * reproduce its reported `gasUsed` EXACTLY — the shared vectors
 * (`shared/gas_test_vectors.json`) pin the equivalence.
 *
 * # Charging contract (normative per metakit PR #37)
 *
 * - Every operator application consumes EXACTLY ONCE from the shared gas
 *   counter: `base(op) + depthPenalty(newDepth) + inputScaled(op, args)`,
 *   atomically BEFORE the primitive runs (so out-of-gas fires before any
 *   input-scaled work), plus an output-scaled residual AFTER the primitive
 *   for split / merge / flatten / slice / substr only. Children pay for
 *   themselves while they are evaluated; ancestors never re-charge their
 *   subtree.
 * - `newDepth` = max(argument metric depths) + 1, where the metric depth
 *   propagates exactly as the Scala `GasMetrics` bookkeeping does (see
 *   "Metric-depth propagation" below).
 * - Variable lookups consume `varAccess + #pathSegments` once at lookup time,
 *   where the segment count follows Java `String.split("\\.")` semantics
 *   (trailing empty segments dropped; the empty key counts 1). A lookup that
 *   CANNOT afford its charge is swallowed by the runtime into the var default
 *   (or null) and consumes nothing — evaluation continues.
 * - The lazily-evaluated `if` and `let` charge their flat base cost
 *   (`ifElse`) exactly once per node at the dispatch site, BEFORE any child
 *   is evaluated and before argument-shape validation, with NO depth penalty.
 *   Lazy evaluation is unchanged: untaken branches pay nothing.
 * - Reported gas-used is the gas-counter delta. All cost arithmetic is
 *   u64-saturating (bigint clamped at 2^64 - 1).
 *
 * # Metric-depth propagation (feeds ancestors' depth penalties)
 *
 * - constants and wrapped callbacks: depth 0;
 * - var lookups (both key forms): depth 0;
 * - ARRAY literals: max of element depths; OBJECT literals: depth 0;
 * - `if`: the taken branch's depth (condition metrics dropped); untaken chain
 *   with no else: depth 0;
 * - `let`: the result expression's depth (binding metrics dropped);
 * - operator applications: `newDepth`, except the callback ops whose handlers
 *   keep per-run metrics — `map`, `reduce`, `all`, `none` — which yield
 *   `max(newDepth, max(run depths))`, where each callback run is wrapped at
 *   `semanticsDepth + 2`. The handlers for `filter` / `some` / `find` /
 *   `count` drop run metrics, so they yield exactly `newDepth`.
 */

import type { JsonLogicExpression } from './expression';
import type { JsonLogicValue } from './value';
import {
  arrayValue,
  boolValue,
  functionValue,
  intValue,
  isTruthy,
  mapValue,
  nullValue,
} from './value';
import { Evaluator, isCallbackArg, MAX_EVAL_DEPTH } from './evaluator';
import { JsonLogicError, JsonLogicRuntimeError, type JsonLogicResult, ok, err } from './errors';

// ---------------------------------------------------------------------------
// u64-saturating bigint arithmetic
// ---------------------------------------------------------------------------

const U64_MAX = 2n ** 64n - 1n;

const sat = (v: bigint): bigint => (v > U64_MAX ? U64_MAX : v < 0n ? 0n : v);
const satAdd = (a: bigint, b: bigint): bigint => sat(a + b);
const satMul = (a: bigint, b: bigint): bigint => sat(a * b);

// ---------------------------------------------------------------------------
// Gas schedule (field-for-field mirror of Rust `GasConfig` / Scala defaults)
// ---------------------------------------------------------------------------

/**
 * The full gas schedule, field-for-field mirror of Rust `GasConfig`
 * (rust/jlvm-core/src/gas.rs) and the Scala `GasConfig` defaults. When one
 * side changes, the shared gas vectors catch the drift.
 */
export interface GasSchedule {
  readonly ifElse: bigint;
  readonly default: bigint;
  readonly not: bigint;
  readonly doubleNot: bigint;
  readonly or: bigint;
  readonly and: bigint;
  readonly eq: bigint;
  readonly eqStrict: bigint;
  readonly neq: bigint;
  readonly neqStrict: bigint;
  readonly lt: bigint;
  readonly leq: bigint;
  readonly gt: bigint;
  readonly geq: bigint;
  readonly add: bigint;
  readonly minus: bigint;
  readonly times: bigint;
  readonly div: bigint;
  readonly modulo: bigint;
  readonly max: bigint;
  readonly min: bigint;
  readonly abs: bigint;
  readonly round: bigint;
  readonly floor: bigint;
  readonly ceil: bigint;
  readonly pow: bigint;
  readonly map: bigint;
  readonly filter: bigint;
  readonly reduce: bigint;
  readonly merge: bigint;
  readonly all: bigint;
  readonly some: bigint;
  readonly none: bigint;
  readonly find: bigint;
  readonly count: bigint;
  readonly inOp: bigint;
  readonly intersect: bigint;
  readonly unique: bigint;
  readonly slice: bigint;
  readonly reverse: bigint;
  readonly flatten: bigint;
  readonly cat: bigint;
  readonly substr: bigint;
  readonly lower: bigint;
  readonly upper: bigint;
  readonly join: bigint;
  readonly split: bigint;
  readonly trim: bigint;
  readonly startsWith: bigint;
  readonly endsWith: bigint;
  readonly mapValues: bigint;
  readonly mapKeys: bigint;
  readonly get: bigint;
  readonly has: bigint;
  readonly entries: bigint;
  readonly length: bigint;
  readonly exists: bigint;
  readonly missing: bigint;
  readonly missingSome: bigint;
  readonly typeOf: bigint;
  readonly poseidon: bigint;
  readonly poseidonPerInput: bigint;
  readonly pmtVerify: bigint;
  readonly pmtPerSibling: bigint;
  readonly groth16Verify: bigint;
  readonly ecvrfVerify: bigint;
  readonly bn254Add: bigint;
  readonly bn254Mul: bigint;
  readonly bn254Pairing: bigint;
  readonly bn254PairingPerPair: bigint;
  readonly blsVerify: bigint;
  readonly blsAggregateVerify: bigint;
  readonly blsAggregatePerKey: bigint;
  readonly schnorrVerify: bigint;
  readonly smtVerify: bigint;
  readonly smtPerSibling: bigint;
  readonly mptVerify: bigint;
  readonly mptPerNode: bigint;
  readonly mptPrefixVerify: bigint;
  readonly mptPrefixPerEntry: bigint;
  readonly constCost: bigint;
  readonly varAccess: bigint;
  readonly depthPenaltyMultiplier: bigint;
  readonly collectionSizeMultiplier: bigint;
}

/** The default schedule — mirrors `GasConfig::default()` in Rust exactly. */
export const DEFAULT_GAS_SCHEDULE: GasSchedule = {
  ifElse: 10n,
  default: 5n,
  not: 1n,
  doubleNot: 1n,
  or: 2n,
  and: 2n,
  eq: 3n,
  eqStrict: 2n,
  neq: 3n,
  neqStrict: 2n,
  lt: 3n,
  leq: 3n,
  gt: 3n,
  geq: 3n,
  add: 5n,
  minus: 5n,
  times: 8n,
  div: 10n,
  modulo: 10n,
  max: 5n,
  min: 5n,
  abs: 2n,
  round: 3n,
  floor: 3n,
  ceil: 3n,
  pow: 20n,
  map: 10n,
  filter: 10n,
  reduce: 15n,
  merge: 5n,
  all: 10n,
  some: 10n,
  none: 10n,
  find: 10n,
  count: 5n,
  inOp: 8n,
  intersect: 15n,
  unique: 20n,
  slice: 5n,
  reverse: 5n,
  flatten: 10n,
  cat: 5n,
  substr: 8n,
  lower: 3n,
  upper: 3n,
  join: 10n,
  split: 15n,
  trim: 5n,
  startsWith: 5n,
  endsWith: 5n,
  mapValues: 5n,
  mapKeys: 5n,
  get: 3n,
  has: 3n,
  entries: 10n,
  length: 1n,
  exists: 5n,
  missing: 10n,
  missingSome: 15n,
  typeOf: 1n,
  poseidon: 150n,
  poseidonPerInput: 150n,
  pmtVerify: 200n,
  pmtPerSibling: 300n,
  groth16Verify: 250_000n,
  ecvrfVerify: 50_000n,
  bn254Add: 500n,
  bn254Mul: 40_000n,
  bn254Pairing: 45_000n,
  bn254PairingPerPair: 35_000n,
  blsVerify: 120_000n,
  blsAggregateVerify: 120_000n,
  blsAggregatePerKey: 15_000n,
  schnorrVerify: 45_000n,
  smtVerify: 500n,
  smtPerSibling: 400n,
  mptVerify: 500n,
  mptPerNode: 400n,
  mptPrefixVerify: 1_000n,
  mptPrefixPerEntry: 800n,
  constCost: 0n,
  varAccess: 2n,
  depthPenaltyMultiplier: 5n,
  collectionSizeMultiplier: 1n,
};

/** `depth * depthPenaltyMultiplier`, saturating. Mirrors `GasConfig::depth_penalty`. */
export const depthPenaltyOf = (c: GasSchedule, depth: bigint): bigint =>
  satMul(depth, c.depthPenaltyMultiplier);

/** `size * collectionSizeMultiplier`, saturating. Mirrors `GasConfig::size_cost`. */
export const sizeCostOf = (c: GasSchedule, size: bigint): bigint =>
  satMul(size, c.collectionSizeMultiplier);

/**
 * The flat base cost charged for an operator tag, before the depth penalty
 * and any input-scaled component. Mirrors Rust `GasConfig::op_base_cost`
 * (NOTE the Scala quirks, reproduced deliberately: `missing` charges the
 * `exists` cost, and `let` would charge the `if` cost — although the runtime
 * never routes `if`/`let` through `applyOp`, so neither base cost is ever
 * consumed in practice). Returns null for unknown operator tags.
 */
export const opBaseCost = (c: GasSchedule, op: string): bigint | null => {
  switch (op) {
    case 'missing':
      return c.exists; // Scala: MissingNoneOp -> config.exists
    case 'exists':
      return c.exists;
    case 'missing_some':
      return c.missingSome;
    case 'if':
      return c.ifElse;
    case 'let':
      return c.ifElse; // Scala: LetOp -> config.ifElse
    case '==':
      return c.eq;
    case '===':
      return c.eqStrict;
    case '!=':
      return c.neq;
    case '!==':
      return c.neqStrict;
    case '!':
      return c.not;
    case '!!':
      return c.doubleNot;
    case 'or':
      return c.or;
    case 'and':
      return c.and;
    case '<':
      return c.lt;
    case '<=':
      return c.leq;
    case '>':
      return c.gt;
    case '>=':
      return c.geq;
    case '%':
      return c.modulo;
    case 'max':
      return c.max;
    case 'min':
      return c.min;
    case '+':
      return c.add;
    case '*':
      return c.times;
    case '-':
      return c.minus;
    case '/':
      return c.div;
    case 'merge':
      return c.merge;
    case 'in':
      return c.inOp;
    case 'cat':
      return c.cat;
    case 'substr':
      return c.substr;
    case 'map':
      return c.map;
    case 'filter':
      return c.filter;
    case 'reduce':
      return c.reduce;
    case 'all':
      return c.all;
    case 'none':
      return c.none;
    case 'some':
      return c.some;
    case 'values':
      return c.mapValues;
    case 'keys':
      return c.mapKeys;
    case 'get':
      return c.get;
    case 'intersect':
      return c.intersect;
    case 'count':
      return c.count;
    case 'length':
      return c.length;
    case 'find':
      return c.find;
    case 'lower':
      return c.lower;
    case 'upper':
      return c.upper;
    case 'join':
      return c.join;
    case 'split':
      return c.split;
    case 'default':
      return c.default;
    case 'unique':
      return c.unique;
    case 'slice':
      return c.slice;
    case 'reverse':
      return c.reverse;
    case 'flatten':
      return c.flatten;
    case 'trim':
      return c.trim;
    case 'startsWith':
      return c.startsWith;
    case 'endsWith':
      return c.endsWith;
    case 'abs':
      return c.abs;
    case 'round':
      return c.round;
    case 'floor':
      return c.floor;
    case 'ceil':
      return c.ceil;
    case 'pow':
      return c.pow;
    case 'has':
      return c.has;
    case 'entries':
      return c.entries;
    case 'typeof':
      return c.typeOf;
    case 'poseidon':
      return c.poseidon;
    case 'pmt_verify':
      return c.pmtVerify;
    case 'groth16_verify':
      return c.groth16Verify;
    case 'ecvrf_verify':
      return c.ecvrfVerify;
    case 'bn254_add':
      return c.bn254Add;
    case 'bn254_mul':
      return c.bn254Mul;
    case 'bn254_pairing':
      return c.bn254Pairing;
    case 'bls_verify':
      return c.blsVerify;
    case 'bls_aggregate_verify':
      return c.blsAggregateVerify;
    case 'schnorr_verify':
      return c.schnorrVerify;
    case 'smt_verify':
      return c.smtVerify;
    case 'mpt_verify':
      return c.mptVerify;
    case 'mpt_prefix_verify':
      return c.mptPrefixVerify;
    default:
      return null;
  }
};

// ---------------------------------------------------------------------------
// Errors and results
// ---------------------------------------------------------------------------

/**
 * Gas exhaustion: DISTINCT from ordinary evaluation failure, mirroring Rust
 * `GasError::Exhausted` / Scala's `GasExhaustedException` subtype.
 */
export class GasExhaustedError extends JsonLogicError {
  constructor(
    public readonly required: bigint,
    public readonly available: bigint
  ) {
    super(`Gas exhausted: required ${required}, available ${available}`);
    this.name = 'GasExhaustedError';
  }
}

/** Successful metered evaluation: the value and the exact gas consumed. */
export interface GasMeteredResult {
  readonly value: JsonLogicValue;
  readonly gasUsed: bigint;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const isPrimitiveValue = (v: JsonLogicValue): boolean =>
  v.tag === 'bool' || v.tag === 'int' || v.tag === 'float' || v.tag === 'string';

/** UTF-16 code-unit length (Scala `String.length`). */
const utf16Len = (s: string): bigint => BigInt(s.length);

/**
 * Length of the string a value coerces to in `cat` / `join` (mirrors
 * `coercedStringLength`: collections / functions price at zero).
 */
const coercedStringLength = (v: JsonLogicValue): bigint => {
  switch (v.tag) {
    case 'null':
      return 0n;
    case 'bool':
      return v.value ? 4n : 5n; // "true" / "false"
    case 'int':
      return BigInt(v.value.toString().length);
    case 'float':
      return BigInt(v.value.toPlainString().length);
    case 'string':
      return utf16Len(v.value);
    default:
      return 0n;
  }
};

/**
 * Number of path segments of a var key, with Java `String.split("\\.")`
 * semantics (the Scala meter charges `key.split("\\.").length`):
 *   - the empty key splits to `[""]` -> 1 segment;
 *   - trailing empty segments are dropped (`"a."` -> 1, `"."` -> 0);
 *   - leading/inner empties are kept (`".a"` -> 2, `"a..b"` -> 3).
 */
export const javaSplitDotSegments = (key: string): bigint => {
  if (key.length === 0) {
    return 1n;
  }
  const parts = key.split('.');
  let n = parts.length;
  while (n > 0 && parts[n - 1].length === 0) {
    n--;
  }
  return BigInt(n);
};

/** |v| as u64, saturating at u64::MAX. Mirrors `bigint_magnitude_saturating`. */
const bigintMagnitudeSaturating = (v: bigint): bigint => sat(v < 0n ? -v : v);

const mapGet = (m: Map<string, JsonLogicValue>, key: string): JsonLogicValue | undefined =>
  m.get(key);

/** An evaluated value together with its metric depth (see module docs). */
type Outcome = readonly [JsonLogicValue, number];

// ---------------------------------------------------------------------------
// The metered evaluator
// ---------------------------------------------------------------------------

class Metered {
  private readonly inner: Evaluator;
  private remainingGas: bigint;
  /**
   * Current `eval` recursion depth, guarded by MAX_EVAL_DEPTH IDENTICALLY to
   * the un-metered evaluator. Distinct from both the gas metric depth and
   * `semDepth` (which only advances at callback boundaries) — this counts
   * every recursive `eval` step.
   */
  private recDepth = 0;

  constructor(
    data: JsonLogicValue,
    private readonly config: GasSchedule,
    gasLimit: bigint
  ) {
    this.inner = new Evaluator(data);
    this.remainingGas = gasLimit;
  }

  get remaining(): bigint {
    return this.remainingGas;
  }

  /** Atomically consume `cost` or throw the distinct exhaustion error. */
  private consume(cost: bigint): void {
    if (this.remainingGas >= cost) {
      this.remainingGas -= cost;
    } else {
      throw new GasExhaustedError(cost, this.remainingGas);
    }
  }

  /** Like consume, but reports whether the charge was affordable (no throw). */
  private tryConsume(cost: bigint): boolean {
    if (this.remainingGas >= cost) {
      this.remainingGas -= cost;
      return true;
    }
    return false;
  }

  /**
   * One `evaluateGasAware` boundary: a full runtime run at semantics depth
   * `depth`, with the result's metric depth raised to at least `depth + 1`
   * (Scala's `withDepth(depth + 1)`). Used for the top-level entry and for
   * every callback run (at `semantics depth + 1`).
   */
  evalGasAware(expr: JsonLogicExpression, ctx: JsonLogicValue | undefined, depth: number): Outcome {
    const [value, metricDepth] = this.eval(expr, ctx, depth);
    return [value, Math.max(metricDepth, depth + 1)];
  }

  /**
   * The runtime: expression traversal at semantics depth `semDepth`
   * (advanced only across callback boundaries). Depth-guarded by
   * MAX_EVAL_DEPTH, identically to the un-metered evaluator (a normal
   * evaluation error, distinct from gas exhaustion).
   */
  private eval(
    expr: JsonLogicExpression,
    ctx: JsonLogicValue | undefined,
    semDepth: number
  ): Outcome {
    if (this.recDepth >= MAX_EVAL_DEPTH) {
      throw new JsonLogicRuntimeError(`Recursion depth limit exceeded (${MAX_EVAL_DEPTH})`);
    }
    this.recDepth++;
    try {
      return this.evalNode(expr, ctx, semDepth);
    } finally {
      this.recDepth--;
    }
  }

  private evalNode(
    expr: JsonLogicExpression,
    ctx: JsonLogicValue | undefined,
    semDepth: number
  ): Outcome {
    switch (expr.tag) {
      case 'const':
        return [expr.value, 0];
      case 'array': {
        const out: JsonLogicValue[] = [];
        let maxDepth = 0;
        for (const e of expr.elements) {
          const [v, d] = this.eval(e, ctx, semDepth);
          maxDepth = Math.max(maxDepth, d);
          out.push(v);
        }
        return [arrayValue(out), maxDepth];
      }
      case 'map': {
        // Element charges apply, but the runtime rebuilds the map with
        // `pure`: the literal's metric depth is 0.
        const out = new Map<string, JsonLogicValue>();
        for (const [k, e] of expr.entries) {
          const [v] = this.eval(e, ctx, semDepth);
          out.set(k, v);
        }
        return [mapValue(out), 0];
      }
      case 'var': {
        let keyStr: string;
        if (typeof expr.path === 'string') {
          keyStr = expr.path;
        } else {
          // The key expression's metrics are dropped by the runtime (only its
          // gas consumption remains).
          const [kv] = this.eval(expr.path, ctx, semDepth);
          if (kv.tag === 'string') {
            keyStr = kv.value;
          } else if (kv.tag === 'array' && kv.value[0]?.tag === 'string') {
            keyStr = kv.value[0].value;
          } else {
            throw new JsonLogicRuntimeError('Got non-string input for var key');
          }
        }
        return this.meteredLookup(keyStr, expr.defaultValue, ctx);
      }
      case 'apply':
        if (expr.op === 'if') {
          return this.evalIf(expr.args, ctx, semDepth);
        }
        if (expr.op === 'let') {
          return this.evalLet(expr.args, ctx, semDepth);
        }
        return this.evalApply(expr.op, expr.args, ctx, semDepth);
    }
  }

  /**
   * Metered variable lookup: charge `varAccess + #segments` ONCE, then look
   * up. A lookup that cannot afford the charge consumes nothing and is
   * swallowed into the default (or null) — the runtime treats a failed
   * `getVar` as a missing variable and evaluation CONTINUES. Result metric
   * depth is always 0.
   */
  private meteredLookup(
    key: string,
    defaultValue: JsonLogicValue | undefined,
    ctx: JsonLogicValue | undefined
  ): Outcome {
    const cost = satAdd(this.config.varAccess, javaSplitDotSegments(key));
    if (!this.tryConsume(cost)) {
      // Swallowed: nothing was consumed; missing-variable semantics.
      return [defaultValue ?? nullValue(), 0];
    }
    const raw = this.inner.getVar(key, ctx);
    const value = key.length > 0 && raw.tag === 'null' ? (defaultValue ?? nullValue()) : raw;
    return [value, 0];
  }

  /**
   * Lazy if/else chain. The `if` node itself charges its flat base cost once
   * at dispatch — no depth penalty (undefined at the lazy dispatch site),
   * before the arg-count check. The condition's metric depth is dropped; the
   * taken branch's flows through.
   */
  private evalIf(
    args: JsonLogicExpression[],
    ctx: JsonLogicValue | undefined,
    semDepth: number
  ): Outcome {
    this.consume(this.config.ifElse);
    if (args.length < 2) {
      throw new JsonLogicRuntimeError(
        `Invalid arguments for if/else operation: expected at least 2 args, got ${args.length}`
      );
    }
    let rest = args;
    for (;;) {
      if (rest.length < 2) {
        throw new JsonLogicRuntimeError('If/else malformed: no remaining expressions');
      }
      const [cond, then, ...tail] = rest;
      const [c] = this.eval(cond, ctx, semDepth);
      if (isTruthy(c)) {
        return this.eval(then, ctx, semDepth);
      }
      if (tail.length === 0) {
        return [nullValue(), 0];
      }
      if (tail.length === 1) {
        return this.eval(tail[0], ctx, semDepth);
      }
      rest = tail;
    }
  }

  /**
   * `let` with sequential scope-aware bindings. The `let` node itself charges
   * its flat base cost once at dispatch — no depth penalty — before
   * binding-shape validation. Binding metric depths are dropped; the result
   * expression's flows through. Both surface forms; object-form bindings in
   * RFC-8785 sorted-key order (UTF-16 code units).
   */
  private evalLet(
    args: JsonLogicExpression[],
    ctx: JsonLogicValue | undefined,
    semDepth: number
  ): Outcome {
    this.consume(this.config.ifElse);
    if (args.length !== 2) {
      throw new JsonLogicRuntimeError('let requires [[bindings...], resultExpr]');
    }
    const [bindingsExpr, resultExpr] = args;

    const acc = new Map<string, JsonLogicValue>();
    const bind = (name: string, valueExpr: JsonLogicExpression): void => {
      const bindingCtx = this.inner.letCtx(ctx, acc);
      const [v] = this.eval(valueExpr, bindingCtx, semDepth);
      acc.set(name, v);
    };

    if (bindingsExpr.tag === 'map') {
      const sorted = [...bindingsExpr.entries].sort((a, b) =>
        a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0
      );
      for (const [name, valueExpr] of sorted) {
        bind(name, valueExpr);
      }
    } else if (bindingsExpr.tag === 'array') {
      for (const binding of bindingsExpr.elements) {
        if (
          binding.tag === 'array' &&
          binding.elements.length === 2 &&
          binding.elements[0].tag === 'const' &&
          binding.elements[0].value.tag === 'string'
        ) {
          bind(binding.elements[0].value.value, binding.elements[1]);
        } else {
          throw new JsonLogicRuntimeError('let binding must be [name, expr]');
        }
      }
    } else {
      throw new JsonLogicRuntimeError('let requires [[bindings...], resultExpr]');
    }

    const resultCtx = this.inner.letCtx(ctx, acc) ?? mapValue(acc);
    return this.eval(resultExpr, resultCtx, semDepth);
  }

  /**
   * General operator application: evaluate args (wrapping callback positions,
   * which carry metric depth 0), then charge-and-apply.
   */
  private evalApply(
    op: string,
    args: JsonLogicExpression[],
    ctx: JsonLogicValue | undefined,
    semDepth: number
  ): Outcome {
    const values: JsonLogicValue[] = [];
    let argMaxDepth = 0;
    for (let idx = 0; idx < args.length; idx++) {
      const arg = args[idx];
      if (isCallbackArg(op, idx)) {
        if (arg.tag === 'const' && arg.value.tag === 'function') {
          values.push(arg.value);
        } else {
          values.push(functionValue(arg));
        }
      } else {
        const [v, d] = this.eval(arg, ctx, semDepth);
        argMaxDepth = Math.max(argMaxDepth, d);
        values.push(v);
      }
    }
    return this.applyOp(op, values, argMaxDepth, ctx, semDepth);
  }

  /** The charge-once / pre-charge core. Mirrors `GasAwareSemantics.applyOp`. */
  private applyOp(
    op: string,
    values: JsonLogicValue[],
    argMaxDepth: number,
    ctx: JsonLogicValue | undefined,
    semDepth: number
  ): Outcome {
    const base = opBaseCost(this.config, op);
    if (base === null) {
      throw new JsonLogicRuntimeError(`Unsupported operator: ${op}`);
    }
    const newDepth = argMaxDepth + 1;
    // Everything derivable from the (already evaluated, already paid-for)
    // inputs is pre-charged atomically BEFORE the primitive runs.
    const pre = satAdd(
      satAdd(base, depthPenaltyOf(this.config, BigInt(newDepth))),
      this.inputScaledCost(op, values)
    );
    this.consume(pre);

    const [result, runsDepth] = this.runPrimitive(op, values, ctx, semDepth);

    // Residual component only observable on the produced value; the work it
    // prices is bounded by inputs that were already paid for.
    this.consume(this.outputScaledCost(op, result));

    return [result, Math.max(newDepth, runsDepth)];
  }

  /**
   * Run the primitive for `op`. Callback ops are implemented here so their
   * per-element runs charge the shared counter (each run is one
   * `evalGasAware` boundary at `semDepth + 1`); everything else is delegated
   * verbatim to the un-metered evaluator. Returns the result and the
   * propagated run depth (0 for ops that keep no run metrics).
   */
  private runPrimitive(
    op: string,
    values: JsonLogicValue[],
    ctx: JsonLogicValue | undefined,
    semDepth: number
  ): Outcome {
    const cbDepth = semDepth + 1;
    const two = values.length === 2;

    if (op === 'map' && two && values[0].tag === 'array' && values[1].tag === 'function') {
      const out: JsonLogicValue[] = [];
      let runsDepth = 0;
      for (const el of values[0].value) {
        const [v, d] = this.evalGasAware(values[1].expr, el, cbDepth);
        runsDepth = Math.max(runsDepth, d);
        out.push(v);
      }
      return [arrayValue(out), runsDepth];
    }

    if (op === 'filter' && two && values[0].tag === 'array' && values[1].tag === 'function') {
      // Run metrics dropped (Scala handleFilterOp uses extractValue).
      const out: JsonLogicValue[] = [];
      for (const el of values[0].value) {
        if (isTruthy(this.evalGasAware(values[1].expr, el, cbDepth)[0])) {
          out.push(el);
        }
      }
      return [arrayValue(out), 0];
    }

    if (
      op === 'reduce' &&
      (values.length === 2 || values.length === 3) &&
      values[0].tag === 'array' &&
      values[1].tag === 'function'
    ) {
      const arr = values[0].value;
      const expr = values[1].expr;
      let init: JsonLogicValue | undefined;
      if (values.length === 3) {
        if (!isPrimitiveValue(values[2])) {
          throw new JsonLogicRuntimeError('Unexpected input to reduce');
        }
        init = values[2];
      }
      let start: number;
      let acc: JsonLogicValue;
      if (init !== undefined) {
        start = 0;
        acc = init;
      } else {
        if (arr.length === 0) {
          return [nullValue(), 0];
        }
        start = 1;
        acc = arr[0];
      }
      let runsDepth = 0;
      for (let i = start; i < arr.length; i++) {
        const runCtx = mapValue(
          new Map<string, JsonLogicValue>([
            ['current', arr[i]],
            ['accumulator', acc],
          ])
        );
        const [v, d] = this.evalGasAware(expr, runCtx, cbDepth);
        runsDepth = Math.max(runsDepth, d);
        acc = v;
      }
      return [acc, runsDepth];
    }

    if (op === 'all' && two && values[0].tag === 'null' && values[1].tag === 'function') {
      return [boolValue(false), 0];
    }
    if (op === 'all' && two && values[0].tag === 'array' && values[1].tag === 'function') {
      // Empty array -> false (JSON Logic reference behavior).
      if (values[0].value.length === 0) {
        return [boolValue(false), 0];
      }
      // NO short-circuit: Scala traverses (and charges) every element.
      let allTruthy = true;
      let runsDepth = 0;
      for (const el of values[0].value) {
        const [v, d] = this.evalGasAware(values[1].expr, el, cbDepth);
        runsDepth = Math.max(runsDepth, d);
        allTruthy = allTruthy && isTruthy(v);
      }
      return [boolValue(allTruthy), runsDepth];
    }

    if (op === 'none' && two && values[0].tag === 'array' && values[1].tag === 'function') {
      // NO short-circuit, run metrics kept (Scala handleNoneOp maps in Result).
      let noneTruthy = true;
      let runsDepth = 0;
      for (const el of values[0].value) {
        const [v, d] = this.evalGasAware(values[1].expr, el, cbDepth);
        runsDepth = Math.max(runsDepth, d);
        noneTruthy = noneTruthy && !isTruthy(v);
      }
      return [boolValue(noneTruthy), runsDepth];
    }

    if (
      op === 'some' &&
      values[0]?.tag === 'array' &&
      values[1]?.tag === 'function' &&
      (values.length === 2 || (values.length === 3 && values[2].tag === 'int'))
    ) {
      const threshold = values.length === 3 && values[2].tag === 'int' ? values[2].value : 1n;
      if (threshold < -(2n ** 63n) || threshold > 2n ** 63n - 1n) {
        throw new JsonLogicRuntimeError('some threshold out of range');
      }
      // NO short-circuit; run metrics dropped (extractValue).
      let count = 0n;
      for (const el of values[0].value) {
        if (isTruthy(this.evalGasAware(values[1].expr, el, cbDepth)[0])) {
          count += 1n;
        }
      }
      return [boolValue(count >= threshold), 0];
    }

    if (op === 'find' && two && values[0].tag === 'array' && values[1].tag === 'function') {
      // SHORT-CIRCUITS on the first match; run metrics dropped.
      for (const el of values[0].value) {
        if (isTruthy(this.evalGasAware(values[1].expr, el, cbDepth)[0])) {
          return [el, 0];
        }
      }
      return [nullValue(), 0];
    }

    if (op === 'count' && two && values[0].tag === 'array' && values[1].tag === 'function') {
      // NO short-circuit; run metrics dropped.
      let count = 0n;
      for (const el of values[0].value) {
        if (isTruthy(this.evalGasAware(values[1].expr, el, cbDepth)[0])) {
          count += 1n;
        }
      }
      return [intValue(count), 0];
    }

    // Every other primitive (including 1-arg `count`, `missing` /
    // `missing_some` — whose internal lookups are UN-metered in Scala — and
    // all crypto opcodes) is exactly the un-metered evaluator's.
    return [this.inner.applyOp(op, values, ctx), 0];
  }

  /**
   * Size-scaled cost derivable from the argument values ALONE, consumed
   * BEFORE the primitive runs. Mirrors `GasAwareSemantics.getInputScaledCost`
   * case-for-case. String lengths are UTF-16 code units.
   */
  private inputScaledCost(op: string, args: JsonLogicValue[]): bigint {
    const c = this.config;
    const size = (n: bigint): bigint => sizeCostOf(c, n);

    switch (op) {
      case 'cat':
        // cat output length == sum of the coerced input string lengths.
        return size(args.map(coercedStringLength).reduce(satAdd, 0n));
      case 'join': {
        // join output length == element lengths + separators.
        if (args.length === 2 && args[0].tag === 'array' && args[1].tag === 'string') {
          const arr = args[0].value;
          const sep = args[1].value;
          const elems = arr.map(coercedStringLength).reduce(satAdd, 0n);
          const seps = satMul(utf16Len(sep), BigInt(Math.max(0, arr.length - 1)));
          return size(satAdd(elems, seps));
        }
        return 0n;
      }
      case 'entries':
        if (args.length === 1 && args[0].tag === 'map') {
          return size(2n * BigInt(args[0].value.size));
        }
        return 0n;
      case 'unique':
        if (args.length === 1 && args[0].tag === 'array') {
          return size(BigInt(args[0].value.length));
        }
        return 0n;
      case 'pow':
        // pow charges |exponent| (raw, no size multiplier), saturating.
        if (args.length === 2 && args[1].tag === 'int') {
          return bigintMagnitudeSaturating(args[1].value);
        }
        if (args.length === 2 && args[1].tag === 'float') {
          return bigintMagnitudeSaturating(args[1].value.numerator);
        }
        return 0n;
      case '+':
      case '*':
      case '-':
        if (args.length === 1 && args[0].tag === 'array') {
          return size(BigInt(args[0].value.length));
        }
        if (args.length > 1) {
          return size(BigInt(args.length - 1));
        }
        return 0n;
      case 'map':
      case 'filter':
      case 'all':
      case 'none':
      case 'some':
      case 'find':
      case 'count':
        if (args.length >= 1 && args[0].tag === 'array') {
          return size(BigInt(args[0].value.length));
        }
        return 0n;
      case 'reverse':
        if (args.length === 1 && args[0].tag === 'array') {
          return size(BigInt(args[0].value.length));
        }
        return 0n;
      case 'in':
        if (args.length === 2 && args[1].tag === 'array') {
          return size(BigInt(args[1].value.length));
        }
        if (args.length === 2 && args[1].tag === 'string') {
          return size(utf16Len(args[1].value) / 10n);
        }
        return 0n;
      case 'intersect':
        if (args.length === 2 && args[0].tag === 'array' && args[1].tag === 'array') {
          return size(satAdd(BigInt(args[0].value.length), BigInt(args[1].value.length)));
        }
        return 0n;
      case 'reduce':
        if (args.length >= 1 && args[0].tag === 'array') {
          return size(BigInt(args[0].value.length));
        }
        return 0n;
      case 'max':
      case 'min':
        if (args.length === 1 && args[0].tag === 'array') {
          return size(BigInt(args[0].value.length));
        }
        return size(BigInt(args.length));
      case 'values':
      case 'keys':
        if (args.length === 1 && args[0].tag === 'map') {
          return size(BigInt(args[0].value.size));
        }
        return 0n;
      case 'poseidon':
        // poseidon scales with the number of inputs.
        if (args.length === 1 && args[0].tag === 'array') {
          return satMul(c.poseidonPerInput, BigInt(args[0].value.length));
        }
        return satMul(c.poseidonPerInput, BigInt(args.length));
      case 'pmt_verify':
        // pmt_verify scales with path length (= number of siblings).
        if (args.length === 4 && args[3].tag === 'array') {
          return satMul(c.pmtPerSibling, BigInt(args[3].value.length));
        }
        return 0n;
      case 'bn254_pairing':
        // bn254_pairing scales with the number of (G1, G2) pairs. A lone
        // array is the pairs list only when every element is itself a pair.
        if (
          args.length === 1 &&
          args[0].tag === 'array' &&
          args[0].value.every((p) => p.tag === 'array')
        ) {
          return satMul(c.bn254PairingPerPair, BigInt(args[0].value.length));
        }
        return satMul(c.bn254PairingPerPair, BigInt(args.length));
      case 'bls_aggregate_verify':
        // bls_aggregate_verify scales with the number of public keys.
        if (args.length === 3 && args[0].tag === 'array') {
          return satMul(c.blsAggregatePerKey, BigInt(args[0].value.length));
        }
        return 0n;
      case 'smt_verify': {
        // smt_verify scales with the authentication-path depth.
        if (args.length === 2 && args[1].tag === 'map') {
          const siblings = mapGet(args[1].value, 'siblings');
          if (siblings !== undefined && siblings.tag === 'array') {
            return satMul(c.smtPerSibling, BigInt(siblings.value.length));
          }
        }
        return 0n;
      }
      case 'mpt_verify': {
        // mpt_verify scales with the number of nodes in the proof witness.
        if (args.length === 4 && args[3].tag === 'map') {
          const witness = mapGet(args[3].value, 'witness');
          if (witness !== undefined && witness.tag === 'array') {
            return satMul(c.mptPerNode, BigInt(witness.value.length));
          }
        }
        return 0n;
      }
      case 'mpt_prefix_verify':
        // mpt_prefix_verify scales with the number of entries proven complete.
        if (args.length === 4 && args[2].tag === 'map') {
          return satMul(c.mptPrefixPerEntry, BigInt(args[2].value.size));
        }
        return 0n;
      default:
        return 0n;
    }
  }

  /**
   * Residual size-scaled cost only observable on the PRODUCED value,
   * consumed AFTER the primitive. Mirrors `getOutputScaledCost`.
   */
  private outputScaledCost(op: string, result: JsonLogicValue): bigint {
    const c = this.config;
    switch (op) {
      case 'split':
        return result.tag === 'array' ? sizeCostOf(c, satMul(BigInt(result.value.length), 2n)) : 0n;
      case 'merge':
        if (result.tag === 'array') {
          return sizeCostOf(c, BigInt(result.value.length));
        }
        if (result.tag === 'map') {
          return sizeCostOf(c, BigInt(result.value.size));
        }
        return 0n;
      case 'flatten':
      case 'slice':
        return result.tag === 'array' ? sizeCostOf(c, BigInt(result.value.length)) : 0n;
      case 'substr':
        return result.tag === 'string' ? sizeCostOf(c, utf16Len(result.value)) : 0n;
      default:
        return 0n;
    }
  }
}

/**
 * Evaluate `expr` against `data` under `gasLimit` with the given gas schedule
 * (default schedule when omitted), returning the result value and the exact
 * gas consumed (the gas-counter delta). Out-of-gas surfaces as the DISTINCT
 * `GasExhaustedError`; ordinary evaluation failures as other JsonLogicErrors.
 */
export const evaluateWithGas = (
  expr: JsonLogicExpression,
  data: JsonLogicValue,
  gasLimit: bigint | number,
  config: GasSchedule = DEFAULT_GAS_SCHEDULE
): JsonLogicResult<GasMeteredResult> => {
  const limit = BigInt(gasLimit);
  try {
    const metered = new Metered(data, config, limit);
    const [value] = metered.evalGasAware(expr, undefined, 0);
    return ok({ value, gasUsed: limit - metered.remaining });
  } catch (e) {
    if (e instanceof JsonLogicError) {
      return err(e);
    }
    return err(new JsonLogicRuntimeError(String(e), e instanceof Error ? e : undefined));
  }
};
