/**
 * JSON Logic Evaluator
 *
 * The runtime that evaluates JSON Logic expressions. A faithful port of
 * rust/jlvm-core/src/eval.rs (which mirrors the Scala metakit
 * `JsonLogicRuntime.evaluate` + `JsonLogicSemantics`), so that the Scala,
 * Rust, and TypeScript evaluators are consensus-equivalent:
 *
 * - All arithmetic is exact: integers are unbounded bigints, floats are exact
 *   rationals (see ratio.ts / numeric.ts). Result typing matches Rust: a result
 *   is IntValue only when no operand was a float and the result is integral.
 * - Callback operators (map/filter/reduce/...) receive each element as the
 *   evaluation CONTEXT overlay; the outer data remains visible through
 *   `combineState`, matching the reference scoping exactly.
 * - Maps are insertion-ordered `Map`s (prototype-pollution safe).
 */

import type { JsonLogicExpression } from './expression';
import type { JsonLogicValue, MapValue } from './value';
import {
  nullValue,
  boolValue,
  intValue,
  floatValue,
  strValue,
  arrayValue,
  mapValue,
  functionValue,
  isTruthy,
  strictEquals,
  isPrimitive,
} from './value';
import { Ratio } from './ratio';
import {
  numericInt,
  numericIsFloat,
  numericToRatio,
  numericToValue,
  promoteToNumeric,
  combineNumeric,
  reduceNumeric,
  compareNumeric,
} from './numeric';
import { coerceToPrimitive, compareCoerced } from './coercion';
import {
  JsonLogicError,
  JsonLogicDivisionByZeroError,
  JsonLogicRuntimeError,
  type JsonLogicResult,
  ok,
  err,
} from './errors';

const MAX_SAFE_EXPONENT = 999n;
const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

/**
 * Evaluation context (kept for API compatibility)
 */
export interface EvaluationContext {
  /** The data object (input to the expression) */
  data: JsonLogicValue;
  /** Optional additional context (for nested evaluations) */
  context?: JsonLogicValue;
}

/**
 * Evaluate an expression with the given data
 */
export const evaluate = (
  expr: JsonLogicExpression,
  data: JsonLogicValue,
  context?: JsonLogicValue
): JsonLogicResult<JsonLogicValue> => {
  try {
    return ok(new Evaluator(data).eval(expr, context));
  } catch (e) {
    if (e instanceof JsonLogicError) {
      return err(e);
    }
    return err(new JsonLogicRuntimeError(String(e), e instanceof Error ? e : undefined));
  }
};

const fail = (message: string): never => {
  throw new JsonLogicRuntimeError(message);
};

/**
 * Whether the argument at `argIndex` of operator `op` is a lazily-wrapped
 * callback (a FunctionValue) rather than an eagerly-evaluated value.
 * Mirrors Rust `is_callback_arg`.
 */
const isCallbackArg = (op: string, argIndex: number): boolean =>
  argIndex === 1 &&
  (op === 'map' ||
    op === 'filter' ||
    op === 'all' ||
    op === 'some' ||
    op === 'none' ||
    op === 'find' ||
    op === 'count' ||
    op === 'reduce');

/** Compare two strings by their UTF-16 code units (RFC 8785 key ordering). */
const utf16Cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

const bigintToI64 = (v: bigint, what: string): bigint => {
  if (v < I64_MIN || v > I64_MAX) {
    fail(`${what} out of range`);
  }
  return v;
};

const bigintToU32 = (v: bigint): number => {
  if (v < 0n || v > 0xffffffffn) {
    fail('exponent out of range');
  }
  return Number(v);
};

/**
 * Merge two insertion-ordered maps: right overwrites left, preserving left
 * order then appending new right keys. Mirrors Rust `merge_maps`.
 */
const mergeMaps = (
  l: Map<string, JsonLogicValue>,
  r: Map<string, JsonLogicValue>
): Map<string, JsonLogicValue> => {
  const out = new Map(l);
  for (const [k, v] of r) {
    out.set(k, v);
  }
  return out;
};

/**
 * Get a child by path segment. Mirrors Rust `get_child`: arrays by numeric
 * index, maps by key, everything else -> Null.
 */
const getChild = (parent: JsonLogicValue, segment: string): JsonLogicValue => {
  if (parent.tag === 'array') {
    if (!/^-?[0-9]+$/.test(segment)) return nullValue();
    const idx = BigInt(segment);
    if (idx >= 0n && idx < BigInt(parent.value.length)) {
      return parent.value[Number(idx)];
    }
    return nullValue();
  }
  if (parent.tag === 'map') {
    return parent.value.get(segment) ?? nullValue();
  }
  return nullValue();
};

/** Stringification of primitives (used by `in`). Mirrors `stringify_primitive`. */
const stringifyPrimitive = (v: JsonLogicValue): string => {
  switch (v.tag) {
    case 'bool':
      return v.value.toString();
    case 'int':
      return v.value.toString();
    case 'float':
      return v.value.toPlainString();
    case 'string':
      return v.value;
    default:
      return '';
  }
};

/**
 * Stringification used by `join`. Mirrors Rust `array_to_string`: null,
 * collections and functions become empty strings.
 */
const arrayToString = (v: JsonLogicValue): string => {
  switch (v.tag) {
    case 'null':
      return '';
    case 'bool':
      return v.value.toString();
    case 'int':
      return v.value.toString();
    case 'float':
      return v.value.toPlainString();
    case 'string':
      return v.value;
    default:
      return '';
  }
};

/**
 * Replace unpaired UTF-16 surrogates with U+FFFD, matching Rust's
 * `String::from_utf16_lossy` at substr cut points.
 */
const replaceLoneSurrogates = (s: string): string => {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += s[i] + s[i + 1];
        i++;
      } else {
        out += '�';
      }
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      out += '�';
    } else {
      out += s[i];
    }
  }
  return out;
};

class Evaluator {
  constructor(private readonly vars: JsonLogicValue) {}

  eval(expr: JsonLogicExpression, ctx?: JsonLogicValue): JsonLogicValue {
    switch (expr.tag) {
      case 'const':
        return expr.value;
      case 'array':
        return arrayValue(expr.elements.map((e) => this.eval(e, ctx)));
      case 'map': {
        const out = new Map<string, JsonLogicValue>();
        for (const [k, e] of expr.entries) {
          out.set(k, this.eval(e, ctx));
        }
        return mapValue(out);
      }
      case 'var': {
        let keyStr: string;
        if (typeof expr.path === 'string') {
          keyStr = expr.path;
        } else {
          const evaluated = this.eval(expr.path, ctx);
          if (evaluated.tag === 'string') {
            keyStr = evaluated.value;
          } else if (evaluated.tag === 'array' && evaluated.value[0]?.tag === 'string') {
            keyStr = evaluated.value[0].value;
          } else {
            return fail(`Got non-string input for var key`);
          }
        }
        return this.lookupVar(keyStr, expr.defaultValue, ctx);
      }
      case 'apply':
        return this.evalApply(expr.op, expr.args, ctx);
    }
  }

  /**
   * Variable lookup with dot-path traversal and default handling.
   * Mirrors Rust `lookup_var` + `get_var`.
   */
  private lookupVar(
    key: string,
    defaultValue: JsonLogicValue | undefined,
    ctx?: JsonLogicValue
  ): JsonLogicValue {
    const raw = this.getVar(key, ctx);
    // Apply default only when key is non-empty and the lookup produced Null.
    if (key.length > 0 && raw.tag === 'null' && defaultValue !== undefined) {
      return defaultValue;
    }
    return raw;
  }

  private getVar(key: string, ctx?: JsonLogicValue): JsonLogicValue {
    if (key.length === 0) {
      return ctx ?? this.vars;
    }
    if (key.endsWith('.')) {
      return nullValue();
    }
    // Combine base (vars) with the context overlay. Mirrors `combineState`.
    let cur = this.combineState(ctx);
    for (const seg of key.split('.')) {
      cur = getChild(cur, seg);
    }
    return cur;
  }

  /**
   * Mirrors Rust `combine_state`: arrays/maps merge, primitives/null leave
   * base unchanged, other combinations replace base with ctx.
   */
  private combineState(ctx?: JsonLogicValue): JsonLogicValue {
    if (ctx === undefined || ctx.tag === 'null' || isPrimitive(ctx)) {
      return this.vars;
    }
    if (ctx.tag === 'array') {
      if (this.vars.tag === 'array') {
        return arrayValue([...this.vars.value, ...ctx.value]);
      }
      return ctx;
    }
    if (ctx.tag === 'map') {
      if (this.vars.tag === 'map') {
        return mapValue(mergeMaps(this.vars.value, ctx.value));
      }
      return ctx;
    }
    return ctx;
  }

  private evalApply(op: string, args: JsonLogicExpression[], ctx?: JsonLogicValue): JsonLogicValue {
    if (op === 'if') {
      return this.evalIf(args, ctx);
    }
    if (op === 'let') {
      return this.evalLet(args, ctx);
    }
    // Evaluate args, wrapping callback positions as FunctionValue.
    const values: JsonLogicValue[] = [];
    for (let idx = 0; idx < args.length; idx++) {
      const arg = args[idx];
      if (isCallbackArg(op, idx)) {
        if (arg.tag === 'const' && arg.value.tag === 'function') {
          values.push(arg.value);
        } else {
          values.push(functionValue(arg));
        }
      } else {
        values.push(this.eval(arg, ctx));
      }
    }
    return this.applyOp(op, values, ctx);
  }

  /** Lazy if/else chain. Mirrors Rust `eval_if`. */
  private evalIf(args: JsonLogicExpression[], ctx?: JsonLogicValue): JsonLogicValue {
    let rest = args;
    for (;;) {
      if (rest.length === 0) {
        return fail('If/else requires at least one argument');
      }
      if (rest.length === 1) {
        return fail('If/else malformed: condition without then-branch');
      }
      const [cond, then, ...tail] = rest;
      if (isTruthy(this.eval(cond, ctx))) {
        return this.eval(then, ctx);
      }
      if (tail.length === 0) {
        return nullValue();
      }
      if (tail.length === 1) {
        return this.eval(tail[0], ctx);
      }
      rest = tail;
    }
  }

  /**
   * `{"let": [[[name, expr], ...], result]}` (array form, insertion order) or
   * `{"let": [{name: expr, ...}, result]}` (object form, RFC-8785 sorted-key
   * order — UTF-16 code units, the SAME ordering the JSON canonicalizer uses,
   * so all impls are byte-identical). Bindings are evaluated SEQUENTIALLY,
   * each seeing prior bindings (and the outer scope) in context.
   * Mirrors Rust `eval_let`.
   */
  private evalLet(args: JsonLogicExpression[], ctx?: JsonLogicValue): JsonLogicValue {
    if (args.length !== 2) {
      return fail('let requires [[bindings...], resultExpr]');
    }
    const [bindingsExpr, resultExpr] = args;

    if (bindingsExpr.tag === 'map') {
      const sorted = [...bindingsExpr.entries].sort((a, b) => utf16Cmp(a[0], b[0]));
      const acc = new Map<string, JsonLogicValue>();
      for (const [name, valueExpr] of sorted) {
        const bindingCtx = this.letCtx(ctx, acc);
        acc.set(name, this.eval(valueExpr, bindingCtx));
      }
      const resultCtx = this.letCtx(ctx, acc) ?? mapValue(acc);
      return this.eval(resultExpr, resultCtx);
    }

    if (bindingsExpr.tag === 'array') {
      const acc = new Map<string, JsonLogicValue>();
      for (const binding of bindingsExpr.elements) {
        if (
          binding.tag === 'array' &&
          binding.elements.length === 2 &&
          binding.elements[0].tag === 'const' &&
          binding.elements[0].value.tag === 'string'
        ) {
          const name = binding.elements[0].value.value;
          const bindingCtx = this.letCtx(ctx, acc);
          acc.set(name, this.eval(binding.elements[1], bindingCtx));
        } else {
          return fail('let binding must be [name, expr]');
        }
      }
      const resultCtx = this.letCtx(ctx, acc) ?? mapValue(acc);
      return this.eval(resultExpr, resultCtx);
    }

    return fail('let requires [[bindings...], resultExpr]');
  }

  /**
   * Build the let context overlay from the current ctx and accumulated
   * bindings. Mirrors Rust `let_ctx`.
   */
  private letCtx(
    ctx: JsonLogicValue | undefined,
    acc: Map<string, JsonLogicValue>
  ): JsonLogicValue | undefined {
    if (ctx === undefined) {
      return acc.size === 0 ? undefined : mapValue(new Map(acc));
    }
    if (ctx.tag === 'map') {
      return mapValue(mergeMaps(ctx.value, acc));
    }
    const m = new Map(acc);
    m.set('', ctx);
    return mapValue(m);
  }

  // --- operator dispatch -----------------------------------------------

  private applyOp(op: string, values: JsonLogicValue[], ctx?: JsonLogicValue): JsonLogicValue {
    switch (op) {
      case '==':
        return this.opEq(values, false);
      case '!=':
        return this.opEq(values, true);
      case '===':
        return this.opEqStrict(values, false);
      case '!==':
        return this.opEqStrict(values, true);
      case '!':
        return this.opNot(values);
      case '!!':
        return this.opTruthy(values);
      case 'or':
        return this.opOr(values);
      case 'and':
        return this.opAnd(values);
      case '<':
        return this.opCmp(values, -1, false);
      case '<=':
        return this.opCmp(values, -1, true);
      case '>':
        return this.opCmpGt(values, false);
      case '>=':
        return this.opCmpGt(values, true);
      case '%':
        return this.opModulo(values);
      case 'max':
        return this.opMinMax(values, true);
      case 'min':
        return this.opMinMax(values, false);
      case '+':
        return this.opAdd(values);
      case '*':
        return this.opTimes(values);
      case '-':
        return this.opMinus(values);
      case '/':
        return this.opDiv(values);
      case 'merge':
        return this.opMerge(values);
      case 'in':
        return this.opIn(values);
      case 'intersect':
        return this.opIntersect(values);
      case 'cat':
        return this.opCat(values);
      case 'substr':
        return this.opSubstr(values);
      case 'map':
        return this.opMap(values);
      case 'filter':
        return this.opFilter(values);
      case 'reduce':
        return this.opReduce(values);
      case 'all':
        return this.opAll(values);
      case 'none':
        return this.opNone(values);
      case 'some':
        return this.opSome(values);
      case 'values':
        return this.opMapValues(values);
      case 'keys':
        return this.opMapKeys(values);
      case 'get':
        return this.opGet(values);
      case 'count':
        return this.opCount(values);
      case 'length':
        return this.opLength(values);
      case 'find':
        return this.opFind(values);
      case 'lower':
        return this.opLower(values);
      case 'upper':
        return this.opUpper(values);
      case 'join':
        return this.opJoin(values);
      case 'split':
        return this.opSplit(values);
      case 'default':
        return this.opDefault(values);
      case 'unique':
        return this.opUnique(values);
      case 'slice':
        return this.opSlice(values);
      case 'reverse':
        return this.opReverse(values);
      case 'flatten':
        return this.opFlatten(values);
      case 'trim':
        return this.opTrim(values);
      case 'startsWith':
        return this.opStartsWith(values);
      case 'endsWith':
        return this.opEndsWith(values);
      case 'abs':
        return this.opAbs(values);
      case 'round':
        return this.opRound(values);
      case 'floor':
        return this.opFloor(values);
      case 'ceil':
        return this.opCeil(values);
      case 'pow':
        return this.opPow(values);
      case 'has':
        return this.opHas(values);
      case 'entries':
        return this.opEntries(values);
      case 'typeof':
        return this.opTypeof(values);
      case 'exists':
        return this.opExists(values);
      case 'missing':
        return this.opMissing(values, ctx);
      case 'missing_some':
        return this.opMissingSome(values, ctx);
      default:
        return fail(`Unsupported operator: ${op}`);
    }
  }

  // --- equality ----------------------------------------------------------

  private opEq(values: JsonLogicValue[], negate: boolean): JsonLogicValue {
    if (values.length !== 2) {
      return fail(`Unexpected input for \`${negate ? '!=' : '=='}\``);
    }
    const result = compareCoerced(coerceToPrimitive(values[0]), coerceToPrimitive(values[1]));
    return boolValue(negate ? !result : result);
  }

  private opEqStrict(values: JsonLogicValue[], negate: boolean): JsonLogicValue {
    // `===` over two values; mismatched arity behaves like the reference
    // (non-2-arity pairs are simply "not strictly equal"). `!==` is the exact
    // negation of `===`, matching Rust (see the SPEC DIVERGENCE note there).
    const eq =
      values.length === 2 &&
      values[0].tag !== 'function' &&
      strictEquals(values[0], values[1]);
    return boolValue(negate ? !eq : eq);
  }

  // --- logical -------------------------------------------------------------

  private opNot(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 1) return fail('Unexpected input for `!`');
    return boolValue(!isTruthy(values[0]));
  }

  private opTruthy(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 1) return fail('Unexpected input for `!!`');
    return boolValue(isTruthy(values[0]));
  }

  private opOr(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 0) return boolValue(false);
    for (const v of values) {
      if (isTruthy(v)) return v;
    }
    return values[values.length - 1];
  }

  private opAnd(values: JsonLogicValue[]): JsonLogicValue {
    // Mirrors handleAndOp fold: returns first falsy, else the last element;
    // true if empty.
    let acc: JsonLogicValue = boolValue(true);
    for (const el of values) {
      if (!isTruthy(acc)) return acc;
      if (!isTruthy(el)) return el;
      acc = el;
    }
    return acc;
  }

  // --- comparison ----------------------------------------------------------

  private opCmp(values: JsonLogicValue[], want: number, orEqual: boolean): JsonLogicValue {
    const test = (a: JsonLogicValue, b: JsonLogicValue): boolean => {
      const ord = compareNumeric(promoteToNumeric(a), promoteToNumeric(b));
      return ord === want || (orEqual && ord === 0);
    };
    if (values.length === 2) {
      return boolValue(test(values[0], values[1]));
    }
    if (values.length === 3) {
      return boolValue(test(values[0], values[1]) && test(values[1], values[2]));
    }
    return fail('Unexpected input for comparison');
  }

  private opCmpGt(values: JsonLogicValue[], orEqual: boolean): JsonLogicValue {
    // `>` and `>=` are binary-only in the Scala semantics.
    if (values.length !== 2) return fail('Unexpected input for comparison');
    const ord = compareNumeric(promoteToNumeric(values[0]), promoteToNumeric(values[1]));
    return boolValue(ord === 1 || (orEqual && ord === 0));
  }

  // --- arithmetic ----------------------------------------------------------

  private opModulo(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 2) return fail('Unexpected input for `%`');
    const ln = promoteToNumeric(values[0]);
    const rn = promoteToNumeric(values[1]);
    if (numericToRatio(rn).isZero()) {
      throw new JsonLogicDivisionByZeroError();
    }
    return combineNumeric((a, b) => a.rem(b), ln, rn);
  }

  private opMinMax(values: JsonLogicValue[], isMax: boolean): JsonLogicValue {
    const list = values.length === 1 && values[0].tag === 'array' ? values[0].value : values;
    if (list.length === 0) {
      return fail('min/max: list cannot be empty');
    }
    const numerics = list.map(promoteToNumeric);
    const hasFloat = numerics.some(numericIsFloat);
    let acc = numericToRatio(numerics[0]);
    for (let i = 1; i < numerics.length; i++) {
      const r = numericToRatio(numerics[i]);
      acc = isMax ? acc.max(r) : acc.min(r);
    }
    if (!hasFloat && acc.isInteger()) {
      return intValue(acc.numerator);
    }
    return floatValue(acc);
  }

  private opAdd(values: JsonLogicValue[]): JsonLogicValue {
    const list = values.length === 1 && values[0].tag === 'array' ? values[0].value : values;
    if (list.length === 0) {
      return fail('`+`: list cannot be empty');
    }
    // Single string arg: coerce-to-number (unary plus). Mirrors handleAddOp.
    if (list.length === 1 && list[0].tag === 'string') {
      return numericToValue(promoteToNumeric(list[0]));
    }
    return reduceNumeric(list, (a, b) => a.add(b));
  }

  private opTimes(values: JsonLogicValue[]): JsonLogicValue {
    const list = values.length === 1 && values[0].tag === 'array' ? values[0].value : values;
    if (list.length === 0) {
      return fail('`*`: list cannot be empty');
    }
    return reduceNumeric(list, (a, b) => a.mul(b));
  }

  private opMinus(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1) {
      const n = promoteToNumeric(values[0]);
      return combineNumeric((a, _b) => Ratio.zero().sub(a), n, numericInt(0n));
    }
    if (values.length === 2) {
      return combineNumeric(
        (a, b) => a.sub(b),
        promoteToNumeric(values[0]),
        promoteToNumeric(values[1])
      );
    }
    return fail('Unexpected input for `-`');
  }

  private opDiv(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 2) return fail('Unexpected input for `/`');
    const ln = promoteToNumeric(values[0]);
    const rn = promoteToNumeric(values[1]);
    if (numericToRatio(rn).isZero()) {
      throw new JsonLogicDivisionByZeroError();
    }
    return combineNumeric((a, b) => a.div(b), ln, rn);
  }

  private opAbs(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 1) return fail('Unexpected input to abs');
    const n = promoteToNumeric(values[0]);
    return n.kind === 'int'
      ? intValue(n.value < 0n ? -n.value : n.value)
      : floatValue(n.value.abs());
  }

  private opRound(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 1) return fail('Unexpected input to round');
    const n = promoteToNumeric(values[0]);
    return n.kind === 'int' ? intValue(n.value) : intValue(n.value.roundHalfUp());
  }

  private opFloor(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 1) return fail('Unexpected input to floor');
    const n = promoteToNumeric(values[0]);
    return n.kind === 'int' ? intValue(n.value) : intValue(n.value.floor());
  }

  private opCeil(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 1) return fail('Unexpected input to ceil');
    const n = promoteToNumeric(values[0]);
    return n.kind === 'int' ? intValue(n.value) : intValue(n.value.ceil());
  }

  private opPow(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 2) return fail('Unexpected input to pow');
    const [base, exp] = values;

    // Int^Int fast path (non-negative exponent).
    if (base.tag === 'int' && exp.tag === 'int') {
      if (exp.value > MAX_SAFE_EXPONENT) {
        return fail(`Exponent ${exp.value} exceeds maximum safe value ${MAX_SAFE_EXPONENT}`);
      }
      if (exp.value >= 0n) {
        return intValue(base.value ** exp.value);
      }
      // Negative Int exponent falls through to the general path below.
    }

    const baseNum = promoteToNumeric(base);
    const expNum = promoteToNumeric(exp);
    const e = numericToRatio(expNum).toBigIntExact();
    if (e === null) {
      return fail('Exponent must be an integer for deterministic exponentiation');
    }
    const eAbs = e < 0n ? -e : e;
    if (eAbs > MAX_SAFE_EXPONENT) {
      return fail(`Exponent magnitude ${eAbs} exceeds maximum safe value ${MAX_SAFE_EXPONENT}`);
    }
    const br = numericToRatio(baseNum);
    if (e < 0n && br.numerator === 0n) {
      return fail('Zero cannot be raised to a negative power');
    }
    const powed = e >= 0n ? br.pow(bigintToU32(e)) : br.inverse().pow(bigintToU32(-e));
    if (!numericIsFloat(baseNum) && e >= 0n && powed.isInteger()) {
      return intValue(powed.numerator);
    }
    return floatValue(powed);
  }

  // --- collections / strings ----------------------------------------------

  private opMerge(values: JsonLogicValue[]): JsonLogicValue {
    // All maps -> merged map; else flatten one level.
    if (values.length > 0 && values.every((v) => v.tag === 'map')) {
      let acc = new Map<string, JsonLogicValue>();
      for (const v of values) {
        acc = mergeMaps(acc, (v as MapValue).value);
      }
      return mapValue(acc);
    }
    const list = values.length === 1 && values[0].tag === 'array' ? values[0].value : values;
    const flattened: JsonLogicValue[] = [];
    for (const el of list) {
      if (el.tag === 'array') {
        flattened.push(...el.value);
      } else {
        flattened.push(el);
      }
    }
    return arrayValue(flattened);
  }

  private opIn(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2) {
      const [toFind, haystack] = values;
      if (toFind.tag === 'null') {
        return boolValue(false);
      }
      if (haystack.tag === 'string' && isPrimitive(toFind)) {
        return boolValue(haystack.value.includes(stringifyPrimitive(toFind)));
      }
      if (haystack.tag === 'array') {
        return boolValue(haystack.value.some((x) => strictEquals(x, toFind)));
      }
    }
    return fail('Unexpected input to `in`');
  }

  private opIntersect(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2) {
      const [toFind, arr] = values;
      if (toFind.tag === 'null') {
        return boolValue(true);
      }
      if (toFind.tag === 'array' && arr.tag === 'null') {
        return boolValue(false);
      }
      if (toFind.tag === 'array' && arr.tag === 'array') {
        const all = toFind.value.every((x) => arr.value.some((y) => strictEquals(y, x)));
        return boolValue(all);
      }
    }
    return fail('Unexpected input to `intersect`: expected two arrays');
  }

  private opCat(values: JsonLogicValue[]): JsonLogicValue {
    let out = '';
    for (const v of values) {
      switch (v.tag) {
        case 'null':
          break;
        case 'bool':
          out += v.value.toString();
          break;
        case 'int':
          out += v.value.toString();
          break;
        case 'float':
          out += v.value.toPlainString();
          break;
        case 'string':
          out += v.value;
          break;
        default:
          return fail('Unexpected input for `cat`');
      }
    }
    return strValue(out);
  }

  private opSubstr(values: JsonLogicValue[]): JsonLogicValue {
    // Indices are over UTF-16 code units, matching Scala String semantics.
    let s: string;
    let start: bigint;
    let length: bigint;
    if (values.length === 2 && values[0].tag === 'string' && values[1].tag === 'int') {
      s = values[0].value;
      start = bigintToI64(values[1].value, 'substr start');
      length = BigInt(values[0].value.length);
    } else if (
      values.length === 3 &&
      values[0].tag === 'string' &&
      values[1].tag === 'int' &&
      values[2].tag === 'int'
    ) {
      s = values[0].value;
      start = bigintToI64(values[1].value, 'substr start');
      length = bigintToI64(values[2].value, 'substr length');
    } else {
      return fail('Unexpected input to `substr`');
    }

    const strLen = BigInt(s.length);
    const rawStart = start < 0n ? strLen + start : start;
    let startIdx = rawStart < 0n ? 0n : rawStart;
    if (startIdx > strLen) startIdx = strLen;
    let endIdx: bigint;
    if (length >= 0n) {
      endIdx = startIdx + length;
      if (endIdx > strLen) endIdx = strLen;
    } else {
      endIdx = strLen + length;
      if (endIdx < 0n) endIdx = 0n;
    }
    if (startIdx >= strLen || endIdx <= startIdx) {
      return strValue('');
    }
    return strValue(replaceLoneSurrogates(s.substring(Number(startIdx), Number(endIdx))));
  }

  // --- callbacks -------------------------------------------------------------

  private opMap(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      const expr = values[1].expr;
      return arrayValue(values[0].value.map((el) => this.eval(expr, el)));
    }
    return fail('Unexpected input to map');
  }

  private opFilter(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      const expr = values[1].expr;
      return arrayValue(values[0].value.filter((el) => isTruthy(this.eval(expr, el))));
    }
    return fail('Unexpected input to filter');
  }

  private opReduce(values: JsonLogicValue[]): JsonLogicValue {
    let arr: JsonLogicValue[];
    let expr: JsonLogicExpression;
    let init: JsonLogicValue | undefined;
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      arr = values[0].value;
      expr = values[1].expr;
      init = undefined;
    } else if (
      values.length === 3 &&
      values[0].tag === 'array' &&
      values[1].tag === 'function' &&
      isPrimitive(values[2])
    ) {
      arr = values[0].value;
      expr = values[1].expr;
      init = values[2];
    } else {
      return fail('Unexpected input to reduce');
    }

    let start: number;
    let acc: JsonLogicValue;
    if (init !== undefined) {
      start = 0;
      acc = init;
    } else {
      if (arr.length === 0) {
        return nullValue();
      }
      start = 1;
      acc = arr[0];
    }
    for (let i = start; i < arr.length; i++) {
      const ctx = mapValue(
        new Map<string, JsonLogicValue>([
          ['current', arr[i]],
          ['accumulator', acc],
        ])
      );
      acc = this.eval(expr, ctx);
    }
    return acc;
  }

  private opAll(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'null' && values[1].tag === 'function') {
      return boolValue(false);
    }
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      // The shared conformance vectors pin all-on-empty-array to `false`
      // (see the matching note in Rust `op_all`).
      if (values[0].value.length === 0) {
        return boolValue(false);
      }
      const expr = values[1].expr;
      for (const el of values[0].value) {
        if (!isTruthy(this.eval(expr, el))) {
          return boolValue(false);
        }
      }
      return boolValue(true);
    }
    return fail('Unexpected input to all');
  }

  private opNone(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      const expr = values[1].expr;
      for (const el of values[0].value) {
        if (isTruthy(this.eval(expr, el))) {
          return boolValue(false);
        }
      }
      return boolValue(true);
    }
    return fail('Unexpected input to none');
  }

  private opSome(values: JsonLogicValue[]): JsonLogicValue {
    let arr: JsonLogicValue[];
    let expr: JsonLogicExpression;
    let threshold: bigint;
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      arr = values[0].value;
      expr = values[1].expr;
      threshold = 1n;
    } else if (
      values.length === 3 &&
      values[0].tag === 'array' &&
      values[1].tag === 'function' &&
      values[2].tag === 'int'
    ) {
      arr = values[0].value;
      expr = values[1].expr;
      threshold = bigintToI64(values[2].value, 'some threshold');
    } else {
      return fail('Unexpected input to some');
    }
    let count = 0n;
    for (const el of arr) {
      if (isTruthy(this.eval(expr, el))) {
        count++;
      }
    }
    return boolValue(count >= threshold);
  }

  private opCount(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'array') {
      return intValue(BigInt(values[0].value.length));
    }
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      const expr = values[1].expr;
      let count = 0n;
      for (const el of values[0].value) {
        if (isTruthy(this.eval(expr, el))) {
          count++;
        }
      }
      return intValue(count);
    }
    return fail('Unexpected input to count');
  }

  private opFind(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'function') {
      const expr = values[1].expr;
      for (const el of values[0].value) {
        if (isTruthy(this.eval(expr, el))) {
          return el;
        }
      }
      return nullValue();
    }
    return fail('Unexpected input to find');
  }

  // --- maps / objects --------------------------------------------------------

  private opMapValues(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 0) return nullValue();
    if (values.length === 1 && values[0].tag === 'null') return nullValue();
    if (values.length === 1 && values[0].tag === 'map') {
      return arrayValue([...values[0].value.values()]);
    }
    return fail('Unexpected input for `values`');
  }

  private opMapKeys(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 0) return nullValue();
    if (values.length === 1 && values[0].tag === 'null') return nullValue();
    if (values.length === 1 && values[0].tag === 'map') {
      return arrayValue([...values[0].value.keys()].map((k) => strValue(k)));
    }
    return fail('Unexpected input for `keys`');
  }

  private opGet(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'map' && values[1].tag === 'string') {
      return values[0].value.get(values[1].value) ?? nullValue();
    }
    if (values.length === 3 && values[0].tag === 'map' && values[1].tag === 'string') {
      return values[0].value.get(values[1].value) ?? values[2];
    }
    return fail('Unexpected input to get');
  }

  private opHas(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'map' && values[1].tag === 'string') {
      return boolValue(values[0].value.has(values[1].value));
    }
    return fail('Unexpected input to has');
  }

  private opEntries(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 0) return nullValue();
    if (values.length === 1 && values[0].tag === 'map') {
      return arrayValue(
        [...values[0].value.entries()].map(([k, v]) => arrayValue([strValue(k), v]))
      );
    }
    return fail('Unexpected input to entries');
  }

  // --- strings / arrays --------------------------------------------------------

  private opLength(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'array') {
      return intValue(BigInt(values[0].value.length));
    }
    if (values.length === 1 && values[0].tag === 'string') {
      // UTF-16 code units, matching Scala String#length.
      return intValue(BigInt(values[0].value.length));
    }
    return fail('Unexpected input to length');
  }

  private opLower(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'string') {
      return strValue(values[0].value.toLowerCase());
    }
    return fail('Unexpected input to lower');
  }

  private opUpper(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'string') {
      return strValue(values[0].value.toUpperCase());
    }
    return fail('Unexpected input to upper');
  }

  private opJoin(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'string') {
      return strValue(values[0].value.map(arrayToString).join(values[1].value));
    }
    return fail('Unexpected input to join');
  }

  private opSplit(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'string' && values[1].tag === 'string') {
      const sep = values[1].value;
      if (sep.length === 0) {
        return fail('Split separator cannot be empty');
      }
      // Literal separator, keep trailing empties (Scala split(quote(sep), -1)).
      return arrayValue(values[0].value.split(sep).map((p) => strValue(p)));
    }
    return fail('Unexpected input to split');
  }

  private opDefault(values: JsonLogicValue[]): JsonLogicValue {
    for (const v of values) {
      if (v.tag !== 'null' && isTruthy(v)) {
        return v;
      }
    }
    return nullValue();
  }

  private opUnique(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'array') {
      const seen: JsonLogicValue[] = [];
      for (const el of values[0].value) {
        if (!seen.some((x) => strictEquals(x, el))) {
          seen.push(el);
        }
      }
      return arrayValue(seen);
    }
    return fail('Unexpected input to unique');
  }

  private opSlice(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2 && values[0].tag === 'array' && values[1].tag === 'int') {
      const arr = values[0].value;
      const len = BigInt(arr.length);
      const s = bigintToI64(values[1].value, 'slice start');
      let startIdx = s < 0n ? len + s : s;
      if (startIdx < 0n) startIdx = 0n;
      if (startIdx > len) startIdx = len;
      return arrayValue(arr.slice(Number(startIdx)));
    }
    if (
      values.length === 3 &&
      values[0].tag === 'array' &&
      values[1].tag === 'int' &&
      values[2].tag === 'int'
    ) {
      const arr = values[0].value;
      const len = BigInt(arr.length);
      const s = bigintToI64(values[1].value, 'slice start');
      const e = bigintToI64(values[2].value, 'slice end');
      let startIdx = s < 0n ? len + s : s;
      if (startIdx < 0n) startIdx = 0n;
      if (startIdx > len) startIdx = len;
      let endIdx = e < 0n ? len + e : e;
      if (endIdx < 0n) endIdx = 0n;
      if (endIdx > len) endIdx = len;
      if (endIdx <= startIdx) {
        return arrayValue([]);
      }
      return arrayValue(arr.slice(Number(startIdx), Number(endIdx)));
    }
    return fail('Unexpected input to slice');
  }

  private opReverse(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'array') {
      return arrayValue([...values[0].value].reverse());
    }
    return fail('Unexpected input to reverse');
  }

  private opFlatten(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'array') {
      const out: JsonLogicValue[] = [];
      for (const el of values[0].value) {
        if (el.tag === 'array') {
          out.push(...el.value);
        } else {
          out.push(el);
        }
      }
      return arrayValue(out);
    }
    return fail('Unexpected input to flatten');
  }

  private opTrim(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'string') {
      // Scala String.trim removes chars <= U+0020 from both ends.
      const s = values[0].value;
      let start = 0;
      let end = s.length;
      while (start < end && s.charCodeAt(start) <= 0x20) start++;
      while (end > start && s.charCodeAt(end - 1) <= 0x20) end--;
      return strValue(s.substring(start, end));
    }
    return fail('Unexpected input to trim');
  }

  private opStartsWith(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2) {
      const [a, b] = values;
      if (a.tag === 'string' && b.tag === 'string') {
        return boolValue(a.value.startsWith(b.value));
      }
      if (a.tag === 'string' && b.tag === 'null') return boolValue(false);
      if (a.tag === 'null') return boolValue(false);
    }
    return fail('Unexpected input to startsWith');
  }

  private opEndsWith(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 2) {
      const [a, b] = values;
      if (a.tag === 'string' && b.tag === 'string') {
        return boolValue(a.value.endsWith(b.value));
      }
      if (a.tag === 'string' && b.tag === 'null') return boolValue(false);
      if (a.tag === 'null') return boolValue(false);
    }
    return fail('Unexpected input to endsWith');
  }

  // --- utility -----------------------------------------------------------------

  private opTypeof(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length !== 1) return fail('Unexpected input to typeof');
    return strValue(values[0].tag);
  }

  private opExists(values: JsonLogicValue[]): JsonLogicValue {
    if (values.length === 1 && values[0].tag === 'array') {
      return boolValue(!values[0].value.some((v) => v.tag === 'null'));
    }
    return boolValue(!values.some((v) => v.tag === 'null'));
  }

  private opMissing(values: JsonLogicValue[], ctx?: JsonLogicValue): JsonLogicValue {
    const list = values.length === 1 && values[0].tag === 'array' ? values[0].value : values;
    const missing: JsonLogicValue[] = [];
    for (const field of list) {
      const m = this.fieldIfMissing(field, ctx);
      if (m !== null) {
        missing.push(m);
      }
    }
    return arrayValue(missing);
  }

  private opMissingSome(values: JsonLogicValue[], ctx?: JsonLogicValue): JsonLogicValue {
    let minRequired: bigint;
    let arr: JsonLogicValue[];
    if (values.length === 1 && values[0].tag === 'array') {
      minRequired = 1n;
      arr = values[0].value;
    } else if (
      values.length === 2 &&
      values[0].tag === 'int' &&
      values[0].value > 0n &&
      values[1].tag === 'array'
    ) {
      minRequired = bigintToI64(values[0].value, 'missing_some min');
      arr = values[1].value;
    } else {
      return fail("Unexpected input for `missing_some'");
    }
    const missing: JsonLogicValue[] = [];
    for (const field of arr) {
      const m = this.fieldIfMissing(field, ctx);
      if (m !== null) {
        missing.push(m);
      }
    }
    const present = BigInt(arr.length) - BigInt(missing.length);
    if (present >= minRequired) {
      return arrayValue([]);
    }
    return arrayValue(missing);
  }

  /**
   * Returns the field (a key name) if it is missing from the data, else null.
   * Mirrors Rust `field_if_missing` / Scala `isFieldMissing`.
   */
  private fieldIfMissing(field: JsonLogicValue, ctx?: JsonLogicValue): JsonLogicValue | null {
    let key: string;
    switch (field.tag) {
      case 'string':
        key = field.value;
        break;
      case 'int':
        key = field.value.toString();
        break;
      case 'float':
        key = field.value.toPlainString();
        break;
      default:
        return field;
    }
    const looked = this.getVar(key, ctx);
    return looked.tag === 'null' ? field : null;
  }
}
