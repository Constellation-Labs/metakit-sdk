/**
 * JSON Logic Evaluator
 *
 * The runtime that evaluates JSON Logic expressions.
 * Matches the Scala metakit implementation.
 */

import type { JsonLogicExpression } from './expression';
import type { JsonLogicOpTag } from './operators';
import type { JsonLogicValue } from './value';
import {
  nullValue,
  boolValue,
  intValue,
  floatValue,
  strValue,
  arrayValue,
  mapValue,
  isNull,
  isStr,
  isArray,
  isMap,
  isTruthy,
  toNumber,
  toString,
  strictEquals,
  looseEquals,
} from './value';
import {
  JsonLogicTypeError,
  JsonLogicDivisionByZeroError,
  JsonLogicRuntimeError,
  type JsonLogicResult,
  ok,
  err,
} from './errors';

/**
 * Evaluation context
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
  const ctx: EvaluationContext = { data, context };
  return evalExpr(expr, ctx);
};

/**
 * Core expression evaluator
 */
const evalExpr = (expr: JsonLogicExpression, ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  switch (expr.tag) {
    case 'const':
      return ok(expr.value);

    case 'var':
      return evalVar(expr.path, expr.defaultValue, ctx);

    case 'array': {
      const results: JsonLogicValue[] = [];
      for (const elem of expr.elements) {
        const result = evalExpr(elem, ctx);
        if (!result.ok) return result;
        results.push(result.value);
      }
      return ok(arrayValue(results));
    }

    case 'map': {
      const results: Record<string, JsonLogicValue> = {};
      for (const [key, elemExpr] of Object.entries(expr.entries)) {
        const result = evalExpr(elemExpr, ctx);
        if (!result.ok) return result;
        results[key] = result.value;
      }
      return ok(mapValue(results));
    }

    case 'apply':
      return evalApply(expr.op, expr.args, ctx);
  }
};

/**
 * Evaluate a variable reference
 */
const evalVar = (
  path: string | JsonLogicExpression,
  defaultValue: JsonLogicValue | undefined,
  ctx: EvaluationContext
): JsonLogicResult<JsonLogicValue> => {
  // If path is an expression, evaluate it first
  let pathStr: string;
  if (typeof path === 'string') {
    pathStr = path;
  } else {
    const pathResult = evalExpr(path, ctx);
    if (!pathResult.ok) return pathResult;
    pathStr = toString(pathResult.value);
  }

  // Empty path = return the whole data/context
  if (pathStr === '') {
    return ok(ctx.context ?? ctx.data);
  }

  // Trailing dot = null
  if (pathStr.endsWith('.')) {
    return ok(defaultValue ?? nullValue());
  }

  // Combine data and context
  const combined = combineState(ctx.data, ctx.context);

  // Navigate the path
  const segments = pathStr.split('.');
  let current = combined;

  for (const segment of segments) {
    const child = getChild(current, segment);
    if (isNull(child)) {
      return ok(defaultValue ?? nullValue());
    }
    current = child;
  }

  return ok(current);
};

/**
 * Combine base data with optional context
 */
const combineState = (base: JsonLogicValue, context: JsonLogicValue | undefined): JsonLogicValue => {
  if (!context || isNull(context)) return base;

  // Merge arrays
  if (isArray(base) && isArray(context)) {
    return arrayValue([...base.value, ...context.value]);
  }

  // Merge maps
  if (isMap(base) && isMap(context)) {
    return mapValue({ ...base.value, ...context.value });
  }

  // Context overrides for non-collections
  return context;
};

/**
 * Get a child value from a parent by key
 */
const getChild = (parent: JsonLogicValue, key: string): JsonLogicValue => {
  if (isArray(parent)) {
    const idx = parseInt(key, 10);
    if (!isNaN(idx) && idx >= 0 && idx < parent.value.length) {
      return parent.value[idx];
    }
    return nullValue();
  }

  if (isMap(parent)) {
    return parent.value[key] ?? nullValue();
  }

  return nullValue();
};

/**
 * Evaluate an operator application
 */
const evalApply = (
  op: JsonLogicOpTag,
  argExprs: JsonLogicExpression[],
  ctx: EvaluationContext
): JsonLogicResult<JsonLogicValue> => {
  // Some operators have special evaluation (short-circuit, lazy, etc.)
  switch (op) {
    case 'if':
      return evalIf(argExprs, ctx);
    case 'and':
      return evalAnd(argExprs, ctx);
    case 'or':
      return evalOr(argExprs, ctx);
    case 'let':
      return evalLet(argExprs, ctx);
    case 'map':
      return evalMapOp(argExprs, ctx);
    case 'filter':
      return evalFilter(argExprs, ctx);
    case 'reduce':
      return evalReduce(argExprs, ctx);
    case 'all':
      return evalAll(argExprs, ctx);
    case 'some':
      return evalSome(argExprs, ctx);
    case 'none':
      return evalNone(argExprs, ctx);
    case 'find':
      return evalFind(argExprs, ctx);
    case 'count':
      return evalCount(argExprs, ctx);
    default: {
      // Evaluate all arguments first
      const args: JsonLogicValue[] = [];
      for (const argExpr of argExprs) {
        const result = evalExpr(argExpr, ctx);
        if (!result.ok) return result;
        args.push(result.value);
      }
      return applyOp(op, args);
    }
  }
};

/**
 * Apply an operator to evaluated arguments
 */
const applyOp = (op: JsonLogicOpTag, args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  switch (op) {
    // Logical
    case '!':
      return ok(boolValue(!isTruthy(args[0] ?? nullValue())));
    case '!!':
      return ok(boolValue(isTruthy(args[0] ?? nullValue())));

    // Comparison
    case '==':
      return ok(boolValue(looseEquals(args[0] ?? nullValue(), args[1] ?? nullValue())));
    case '===':
      return ok(boolValue(strictEquals(args[0] ?? nullValue(), args[1] ?? nullValue())));
    case '!=':
      return ok(boolValue(!looseEquals(args[0] ?? nullValue(), args[1] ?? nullValue())));
    case '!==':
      return ok(boolValue(!strictEquals(args[0] ?? nullValue(), args[1] ?? nullValue())));

    case '<':
      return evalComparison(args, (a, b) => a < b);
    case '<=':
      return evalComparison(args, (a, b) => a <= b);
    case '>':
      return evalComparison(args, (a, b) => a > b);
    case '>=':
      return evalComparison(args, (a, b) => a >= b);

    // Arithmetic
    case '+':
      return evalAdd(args);
    case '-':
      return evalSubtract(args);
    case '*':
      return evalMultiply(args);
    case '/':
      return evalDivide(args);
    case '%':
      return evalModulo(args);
    case 'max':
      return evalMinMax(args, 'max');
    case 'min':
      return evalMinMax(args, 'min');
    case 'abs':
      return evalAbs(args);
    case 'round':
      return evalRound(args);
    case 'floor':
      return evalFloor(args);
    case 'ceil':
      return evalCeil(args);
    case 'pow':
      return evalPow(args);

    // String
    case 'cat':
      return ok(strValue(args.map((a) => toString(a)).join('')));
    case 'substr':
      return evalSubstr(args);
    case 'lower':
      return ok(strValue(toString(args[0] ?? nullValue()).toLowerCase()));
    case 'upper':
      return ok(strValue(toString(args[0] ?? nullValue()).toUpperCase()));
    case 'trim':
      return ok(strValue(toString(args[0] ?? nullValue()).trim()));
    case 'join':
      return evalJoin(args);
    case 'split':
      return evalSplit(args);
    case 'startsWith':
      return evalStartsWith(args);
    case 'endsWith':
      return evalEndsWith(args);

    // Array
    case 'merge':
      return evalMerge(args);
    case 'in':
      return evalIn(args);
    case 'intersect':
      return evalIntersect(args);
    case 'unique':
      return evalUnique(args);
    case 'slice':
      return evalSlice(args);
    case 'reverse':
      return evalReverse(args);
    case 'flatten':
      return evalFlatten(args);

    // Object
    case 'keys':
      return evalKeys(args);
    case 'values':
      return evalValues(args);
    case 'get':
      return evalGet(args);
    case 'has':
      return evalHas(args);
    case 'entries':
      return evalEntries(args);

    // Utility
    case 'length':
      return evalLength(args);
    case 'typeof':
      return ok(strValue((args[0] ?? nullValue()).tag));
    case 'default':
      return ok(args.find((a) => isTruthy(a)) ?? nullValue());
    case 'exists':
      return ok(boolValue(!isNull(args[0] ?? nullValue())));
    case 'missing':
      return evalMissing(args);
    case 'missing_some':
      return evalMissingSome(args);

    case 'noop':
      return err(new JsonLogicRuntimeError('Unexpected noop operator'));

    default:
      return err(new JsonLogicRuntimeError(`Unknown operator: ${op}`));
  }
};

// ============= Operator Implementations =============

// Comparison with chaining: [1, 2, 3] means 1 < 2 < 3
const evalComparison = (
  args: JsonLogicValue[],
  cmp: (a: number, b: number) => boolean
): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) {
    return ok(boolValue(true));
  }

  for (let i = 0; i < args.length - 1; i++) {
    const a = toNumber(args[i]);
    const b = toNumber(args[i + 1]);
    if (a === null || b === null) {
      return ok(boolValue(false));
    }
    if (!cmp(a, b)) {
      return ok(boolValue(false));
    }
  }

  return ok(boolValue(true));
};

// Add: unary +, binary +, or variadic sum
const evalAdd = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length === 0) return ok(intValue(0n));

  // Unary: coerce to number
  if (args.length === 1) {
    const n = toNumber(args[0]);
    if (n === null) return ok(intValue(0n));
    if (Number.isInteger(n)) return ok(intValue(BigInt(n)));
    return ok(floatValue(n));
  }

  // Variadic sum
  let sum = 0;
  let isIntResult = true;
  for (const arg of args) {
    const n = toNumber(arg);
    if (n === null) continue;
    sum += n;
    if (!Number.isInteger(n)) isIntResult = false;
  }

  if (isIntResult && Number.isSafeInteger(sum)) {
    return ok(intValue(BigInt(sum)));
  }
  return ok(floatValue(sum));
};

// Subtract: unary negation or binary subtraction
const evalSubtract = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length === 0) return ok(intValue(0n));

  if (args.length === 1) {
    const n = toNumber(args[0]);
    if (n === null) return ok(intValue(0n));
    if (Number.isInteger(n)) return ok(intValue(BigInt(-n)));
    return ok(floatValue(-n));
  }

  const a = toNumber(args[0]);
  const b = toNumber(args[1]);
  if (a === null || b === null) return ok(nullValue());

  const result = a - b;
  if (Number.isInteger(result) && Number.isSafeInteger(result)) {
    return ok(intValue(BigInt(result)));
  }
  return ok(floatValue(result));
};

// Multiply: variadic product
const evalMultiply = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length === 0) return ok(intValue(1n));

  let product = 1;
  let isIntResult = true;
  for (const arg of args) {
    const n = toNumber(arg);
    if (n === null) return ok(nullValue());
    product *= n;
    if (!Number.isInteger(n)) isIntResult = false;
  }

  if (isIntResult && Number.isSafeInteger(product)) {
    return ok(intValue(BigInt(product)));
  }
  return ok(floatValue(product));
};

// Divide
const evalDivide = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(nullValue());

  const a = toNumber(args[0]);
  const b = toNumber(args[1]);
  if (a === null || b === null) return ok(nullValue());
  if (b === 0) return err(new JsonLogicDivisionByZeroError());

  return ok(floatValue(a / b));
};

// Modulo
const evalModulo = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(nullValue());

  const a = toNumber(args[0]);
  const b = toNumber(args[1]);
  if (a === null || b === null) return ok(nullValue());
  if (b === 0) return err(new JsonLogicDivisionByZeroError());

  const result = a % b;
  if (Number.isInteger(result) && Number.isSafeInteger(result)) {
    return ok(intValue(BigInt(result)));
  }
  return ok(floatValue(result));
};

// Min/Max
const evalMinMax = (args: JsonLogicValue[], mode: 'min' | 'max'): JsonLogicResult<JsonLogicValue> => {
  if (args.length === 0) return ok(nullValue());

  // Flatten arrays
  const values: number[] = [];
  const collectValues = (arr: JsonLogicValue[]) => {
    for (const v of arr) {
      if (isArray(v)) {
        collectValues(v.value);
      } else {
        const n = toNumber(v);
        if (n !== null) values.push(n);
      }
    }
  };
  collectValues(args);

  if (values.length === 0) return ok(nullValue());

  const result = mode === 'min' ? Math.min(...values) : Math.max(...values);
  if (Number.isInteger(result) && Number.isSafeInteger(result)) {
    return ok(intValue(BigInt(result)));
  }
  return ok(floatValue(result));
};

// Abs
const evalAbs = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const n = toNumber(args[0] ?? nullValue());
  if (n === null) return ok(nullValue());

  const result = Math.abs(n);
  if (Number.isInteger(result) && Number.isSafeInteger(result)) {
    return ok(intValue(BigInt(result)));
  }
  return ok(floatValue(result));
};

// Round
const evalRound = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const n = toNumber(args[0] ?? nullValue());
  if (n === null) return ok(nullValue());
  return ok(intValue(BigInt(Math.round(n))));
};

// Floor
const evalFloor = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const n = toNumber(args[0] ?? nullValue());
  if (n === null) return ok(nullValue());
  return ok(intValue(BigInt(Math.floor(n))));
};

// Ceil
const evalCeil = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const n = toNumber(args[0] ?? nullValue());
  if (n === null) return ok(nullValue());
  return ok(intValue(BigInt(Math.ceil(n))));
};

// Pow
const evalPow = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(nullValue());

  const base = toNumber(args[0]);
  const exp = toNumber(args[1]);
  if (base === null || exp === null) return ok(nullValue());

  const result = Math.pow(base, exp);
  if (Number.isInteger(result) && Number.isSafeInteger(result)) {
    return ok(intValue(BigInt(result)));
  }
  return ok(floatValue(result));
};

// Substr
const evalSubstr = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(strValue(''));

  const str = toString(args[0]);
  const start = toNumber(args[1]) ?? 0;
  const len = args.length > 2 ? toNumber(args[2]) : undefined;

  // Handle negative start
  const startIdx = start < 0 ? Math.max(0, str.length + start) : start;

  if (len === undefined || len === null) {
    return ok(strValue(str.substring(startIdx)));
  }

  // Handle negative length (means "from end")
  if (len < 0) {
    return ok(strValue(str.substring(startIdx, str.length + len)));
  }

  return ok(strValue(str.substring(startIdx, startIdx + len)));
};

// Join
const evalJoin = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length === 0) return ok(strValue(''));

  const arr = args[0];
  const sep = args.length > 1 ? toString(args[1]) : '';

  if (!isArray(arr)) {
    return ok(strValue(toString(arr)));
  }

  return ok(strValue(arr.value.map((v) => toString(v)).join(sep)));
};

// Split
const evalSplit = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length === 0) return ok(arrayValue([]));

  const str = toString(args[0]);
  const sep = args.length > 1 ? toString(args[1]) : '';

  return ok(arrayValue(str.split(sep).map((s) => strValue(s))));
};

// StartsWith
const evalStartsWith = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(boolValue(false));
  const str = toString(args[0]);
  const prefix = toString(args[1]);
  return ok(boolValue(str.startsWith(prefix)));
};

// EndsWith
const evalEndsWith = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(boolValue(false));
  const str = toString(args[0]);
  const suffix = toString(args[1]);
  return ok(boolValue(str.endsWith(suffix)));
};

// Merge arrays
const evalMerge = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const result: JsonLogicValue[] = [];
  for (const arg of args) {
    if (isArray(arg)) {
      result.push(...arg.value);
    } else {
      result.push(arg);
    }
  }
  return ok(arrayValue(result));
};

// In (element in array or substring in string)
const evalIn = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(boolValue(false));

  const needle = args[0];
  const haystack = args[1];

  if (isStr(haystack) && isStr(needle)) {
    return ok(boolValue(haystack.value.includes(needle.value)));
  }

  if (isArray(haystack)) {
    for (const item of haystack.value) {
      if (looseEquals(needle, item)) {
        return ok(boolValue(true));
      }
    }
    return ok(boolValue(false));
  }

  return ok(boolValue(false));
};

// Intersect arrays
const evalIntersect = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length === 0) return ok(arrayValue([]));
  if (args.length === 1) {
    return isArray(args[0]) ? ok(args[0]) : ok(arrayValue([args[0]]));
  }

  const first = args[0];
  const second = args[1];

  if (!isArray(first) || !isArray(second)) {
    return ok(arrayValue([]));
  }

  const result = first.value.filter((a) => second.value.some((b) => looseEquals(a, b)));
  return ok(arrayValue(result));
};

// Unique
const evalUnique = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const arr = args[0];
  if (!isArray(arr)) return ok(arrayValue([]));

  const seen: JsonLogicValue[] = [];
  const result: JsonLogicValue[] = [];

  for (const item of arr.value) {
    if (!seen.some((s) => strictEquals(s, item))) {
      seen.push(item);
      result.push(item);
    }
  }

  return ok(arrayValue(result));
};

// Slice
const evalSlice = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const arr = args[0];
  if (!isArray(arr)) return ok(arrayValue([]));

  const start = args.length > 1 ? (toNumber(args[1]) ?? 0) : 0;
  const end = args.length > 2 ? (toNumber(args[2]) ?? undefined) : undefined;

  return ok(arrayValue(arr.value.slice(start, end)));
};

// Reverse
const evalReverse = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const arr = args[0];
  if (!isArray(arr)) {
    if (isStr(arr)) {
      return ok(strValue(arr.value.split('').reverse().join('')));
    }
    return ok(arrayValue([]));
  }
  return ok(arrayValue([...arr.value].reverse()));
};

// Flatten
const evalFlatten = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const arr = args[0];
  if (!isArray(arr)) return ok(arrayValue([arr]));

  const depth = args.length > 1 ? (toNumber(args[1]) ?? 1) : 1;

  const flatten = (arr: JsonLogicValue[], d: number): JsonLogicValue[] => {
    if (d <= 0) return arr;
    const result: JsonLogicValue[] = [];
    for (const item of arr) {
      if (isArray(item)) {
        result.push(...flatten(item.value, d - 1));
      } else {
        result.push(item);
      }
    }
    return result;
  };

  return ok(arrayValue(flatten(arr.value, depth)));
};

// Keys
const evalKeys = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const obj = args[0];
  if (!isMap(obj)) return ok(arrayValue([]));
  return ok(arrayValue(Object.keys(obj.value).map((k) => strValue(k))));
};

// Values
const evalValues = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const obj = args[0];
  if (!isMap(obj)) return ok(arrayValue([]));
  return ok(arrayValue(Object.values(obj.value)));
};

// Get (nested property access)
const evalGet = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(nullValue());

  const obj = args[0];
  const key = toString(args[1]);
  const defaultVal = args.length > 2 ? args[2] : nullValue();

  const result = getChild(obj, key);
  return ok(isNull(result) ? defaultVal : result);
};

// Has (check if key exists)
const evalHas = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(boolValue(false));

  const obj = args[0];
  const key = toString(args[1]);

  if (isMap(obj)) {
    return ok(boolValue(key in obj.value));
  }

  if (isArray(obj)) {
    const idx = parseInt(key, 10);
    return ok(boolValue(!isNaN(idx) && idx >= 0 && idx < obj.value.length));
  }

  return ok(boolValue(false));
};

// Entries (key-value pairs)
const evalEntries = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const obj = args[0];
  if (!isMap(obj)) return ok(arrayValue([]));

  const entries = Object.entries(obj.value).map(([k, v]) => arrayValue([strValue(k), v]));
  return ok(arrayValue(entries));
};

// Length
const evalLength = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  const val = args[0] ?? nullValue();

  if (isStr(val)) return ok(intValue(BigInt(val.value.length)));
  if (isArray(val)) return ok(intValue(BigInt(val.value.length)));
  if (isMap(val)) return ok(intValue(BigInt(Object.keys(val.value).length)));

  return ok(intValue(0n));
};

// Missing
const evalMissing = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  // Flatten args and check each key
  const keys: string[] = [];
  const collectKeys = (arr: JsonLogicValue[]) => {
    for (const v of arr) {
      if (isArray(v)) collectKeys(v.value);
      else if (isStr(v)) keys.push(v.value);
    }
  };
  collectKeys(args);

  // Missing keys are returned
  const missing: JsonLogicValue[] = [];
  for (const key of keys) {
    // Check if key exists in data
    // This is simplified - full implementation would use var lookup
    missing.push(strValue(key));
  }

  return ok(arrayValue(missing));
};

// Missing some (simplified implementation)
const evalMissingSome = (args: JsonLogicValue[]): JsonLogicResult<JsonLogicValue> => {
  if (args.length < 2) return ok(arrayValue([]));

  // args[0] = minimum required, args[1] = keys to check
  // Full implementation would check how many keys exist and compare to minimum
  const keys = args[1];
  if (!isArray(keys)) return ok(arrayValue([]));

  return ok(arrayValue([]));
};

// ============= Control Flow with Lazy Evaluation =============

// If-else
const evalIf = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  // if(cond, then, else) or if(c1, t1, c2, t2, ..., else)
  for (let i = 0; i < argExprs.length - 1; i += 2) {
    const condResult = evalExpr(argExprs[i], ctx);
    if (!condResult.ok) return condResult;

    if (isTruthy(condResult.value)) {
      return evalExpr(argExprs[i + 1], ctx);
    }
  }

  // Else clause (odd number of args)
  if (argExprs.length % 2 === 1) {
    return evalExpr(argExprs[argExprs.length - 1], ctx);
  }

  return ok(nullValue());
};

// And (short-circuit)
const evalAnd = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  let last: JsonLogicValue = boolValue(true);

  for (const expr of argExprs) {
    const result = evalExpr(expr, ctx);
    if (!result.ok) return result;

    last = result.value;
    if (!isTruthy(last)) {
      return ok(last);
    }
  }

  return ok(last);
};

// Or (short-circuit)
const evalOr = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  let last: JsonLogicValue = boolValue(false);

  for (const expr of argExprs) {
    const result = evalExpr(expr, ctx);
    if (!result.ok) return result;

    last = result.value;
    if (isTruthy(last)) {
      return ok(last);
    }
  }

  return ok(last);
};

// Let (variable binding)
const evalLet = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 2) return ok(nullValue());

  // let([{name: expr, ...}, body])
  const bindingsExpr = argExprs[0];
  const bodyExpr = argExprs[1];

  // Evaluate bindings expression to get the bindings object
  const bindingsResult = evalExpr(bindingsExpr, ctx);
  if (!bindingsResult.ok) return bindingsResult;

  const bindings = bindingsResult.value;
  if (!isMap(bindings)) {
    return err(new JsonLogicTypeError('let', 'map', bindings.tag));
  }

  // Create new context with bindings merged in
  const newContext: JsonLogicValue = isMap(ctx.data)
    ? mapValue({ ...ctx.data.value, ...bindings.value })
    : bindings;

  return evalExpr(bodyExpr, { data: newContext, context: ctx.context });
};

// Map (iterate over array)
const evalMapOp = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 2) return ok(arrayValue([]));

  const arrResult = evalExpr(argExprs[0], ctx);
  if (!arrResult.ok) return arrResult;

  const arr = arrResult.value;
  if (!isArray(arr)) return ok(arrayValue([]));

  const mapperExpr = argExprs[1];
  const results: JsonLogicValue[] = [];

  for (const item of arr.value) {
    // The current item becomes the new data for the mapper expression
    // { var: '' } will return the item
    const itemResult = evalExpr(mapperExpr, { data: item });
    if (!itemResult.ok) return itemResult;
    results.push(itemResult.value);
  }

  return ok(arrayValue(results));
};

// Filter
const evalFilter = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 2) return ok(arrayValue([]));

  const arrResult = evalExpr(argExprs[0], ctx);
  if (!arrResult.ok) return arrResult;

  const arr = arrResult.value;
  if (!isArray(arr)) return ok(arrayValue([]));

  const predicateExpr = argExprs[1];
  const results: JsonLogicValue[] = [];

  for (const item of arr.value) {
    const predResult = evalExpr(predicateExpr, { data: item });
    if (!predResult.ok) return predResult;

    if (isTruthy(predResult.value)) {
      results.push(item);
    }
  }

  return ok(arrayValue(results));
};

// Reduce
const evalReduce = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 3) return ok(nullValue());

  const arrResult = evalExpr(argExprs[0], ctx);
  if (!arrResult.ok) return arrResult;

  const arr = arrResult.value;
  if (!isArray(arr)) return ok(nullValue());

  const reducerExpr = argExprs[1];
  const initialResult = evalExpr(argExprs[2], ctx);
  if (!initialResult.ok) return initialResult;

  let accumulator = initialResult.value;

  for (const item of arr.value) {
    // Reducer gets {current: item, accumulator: acc}
    const reducerData = mapValue({
      current: item,
      accumulator,
    });

    const result = evalExpr(reducerExpr, { data: reducerData, context: ctx.data });
    if (!result.ok) return result;

    accumulator = result.value;
  }

  return ok(accumulator);
};

// All
const evalAll = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 2) return ok(boolValue(true));

  const arrResult = evalExpr(argExprs[0], ctx);
  if (!arrResult.ok) return arrResult;

  const arr = arrResult.value;
  if (!isArray(arr)) return ok(boolValue(false));
  if (arr.value.length === 0) return ok(boolValue(false));

  const predicateExpr = argExprs[1];

  for (const item of arr.value) {
    const predResult = evalExpr(predicateExpr, { data: item });
    if (!predResult.ok) return predResult;

    if (!isTruthy(predResult.value)) {
      return ok(boolValue(false));
    }
  }

  return ok(boolValue(true));
};

// Some
const evalSome = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 2) return ok(boolValue(false));

  const arrResult = evalExpr(argExprs[0], ctx);
  if (!arrResult.ok) return arrResult;

  const arr = arrResult.value;
  if (!isArray(arr)) return ok(boolValue(false));

  const predicateExpr = argExprs[1];

  for (const item of arr.value) {
    const predResult = evalExpr(predicateExpr, { data: item });
    if (!predResult.ok) return predResult;

    if (isTruthy(predResult.value)) {
      return ok(boolValue(true));
    }
  }

  return ok(boolValue(false));
};

// None
const evalNone = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  const someResult = evalSome(argExprs, ctx);
  if (!someResult.ok) return someResult;

  return ok(boolValue(!isTruthy(someResult.value)));
};

// Find
const evalFind = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 2) return ok(nullValue());

  const arrResult = evalExpr(argExprs[0], ctx);
  if (!arrResult.ok) return arrResult;

  const arr = arrResult.value;
  if (!isArray(arr)) return ok(nullValue());

  const predicateExpr = argExprs[1];

  for (const item of arr.value) {
    const predResult = evalExpr(predicateExpr, { data: item });
    if (!predResult.ok) return predResult;

    if (isTruthy(predResult.value)) {
      return ok(item);
    }
  }

  return ok(nullValue());
};

// Count (count matching items)
const evalCount = (argExprs: JsonLogicExpression[], ctx: EvaluationContext): JsonLogicResult<JsonLogicValue> => {
  if (argExprs.length < 2) return ok(intValue(0n));

  const arrResult = evalExpr(argExprs[0], ctx);
  if (!arrResult.ok) return arrResult;

  const arr = arrResult.value;
  if (!isArray(arr)) return ok(intValue(0n));

  const predicateExpr = argExprs[1];
  let count = 0n;

  for (const item of arr.value) {
    const predResult = evalExpr(predicateExpr, { data: item });
    if (!predResult.ok) return predResult;

    if (isTruthy(predResult.value)) {
      count++;
    }
  }

  return ok(intValue(count));
};
