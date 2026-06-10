/**
 * JSON Logic Codec
 *
 * Parse JSON to expressions and encode expressions to JSON.
 * Mirrors rust/jlvm-core/src/expression.rs (`decodeJsonLogicExpr`) and the
 * Scala metakit serialization format.
 *
 * Security note: parsed objects are stored as `Map`s (never plain JS objects
 * keyed by attacker-controlled strings), so keys like "__proto__" or
 * "constructor" cannot pollute prototypes.
 */

import { isKnownOperator } from './operators';
import type { JsonLogicExpression } from './expression';
import { applyExpr, arrayExpr, constExpr, mapExpr, varExpr } from './expression';
import type { JsonLogicValue } from './value';
import {
  arrayValue,
  boolValue,
  floatValue,
  intValue,
  mapValue,
  nullValue,
  strValue,
} from './value';
import { Ratio } from './ratio';

/**
 * Error thrown when parsing fails
 */
export class JsonLogicParseError extends Error {
  constructor(
    message: string,
    public readonly path?: string
  ) {
    super(path ? `${message} at ${path}` : message);
    this.name = 'JsonLogicParseError';
  }
}

/**
 * Number -> Value following circe / Rust `number_to_value`: integral numbers
 * become IntValue (exact, unbounded), everything else FloatValue (exact decimal
 * from the shortest-round-trip string form). `bigint` inputs are accepted for
 * beyond-2^53 integers.
 */
const parseNumber = (n: number | bigint): JsonLogicValue => {
  if (typeof n === 'bigint') {
    return intValue(n);
  }
  if (!Number.isFinite(n)) {
    throw new JsonLogicParseError(`Cannot parse non-finite number: ${n}`);
  }
  const r = Ratio.parseDecimal(String(n));
  if (r === null) {
    throw new JsonLogicParseError(`Cannot parse number: ${n}`);
  }
  if (r.isInteger()) {
    return intValue(r.numerator);
  }
  return floatValue(r);
};

/**
 * Parse a JSON value to a JsonLogicValue (runtime value, not expression)
 */
export const parseValue = (json: unknown): JsonLogicValue => {
  if (json === null || json === undefined) {
    return nullValue();
  }

  if (typeof json === 'boolean') {
    return boolValue(json);
  }

  if (typeof json === 'number' || typeof json === 'bigint') {
    return parseNumber(json);
  }

  if (typeof json === 'string') {
    return strValue(json);
  }

  if (Array.isArray(json)) {
    return arrayValue(json.map(parseValue));
  }

  if (typeof json === 'object') {
    const result = new Map<string, JsonLogicValue>();
    for (const [key, val] of Object.entries(json)) {
      result.set(key, parseValue(val));
    }
    return mapValue(result);
  }

  throw new JsonLogicParseError(`Cannot parse value: ${typeof json}`);
};

/**
 * Parse a JSON value to a JsonLogicExpression
 *
 * JSON Logic expressions can be:
 * - Primitives (null, bool, number, string) -> ConstExpression
 * - Arrays -> either ArrayExpression or array-syntax operator
 * - Objects with single operator key -> ApplyExpression
 * - Objects with "var" key -> VarExpression
 * - Other objects -> MapExpression
 */
export const parseExpression = (json: unknown): JsonLogicExpression => {
  // Null
  if (json === null || json === undefined) {
    return constExpr(nullValue());
  }

  // Boolean
  if (typeof json === 'boolean') {
    return constExpr(boolValue(json));
  }

  // Number (bigint accepted for beyond-2^53 integers)
  if (typeof json === 'number' || typeof json === 'bigint') {
    return constExpr(parseNumber(json));
  }

  // String
  if (typeof json === 'string') {
    return constExpr(strValue(json));
  }

  // Array
  if (Array.isArray(json)) {
    return parseArrayExpression(json);
  }

  // Object
  if (typeof json === 'object') {
    return parseObjectExpression(json as Record<string, unknown>);
  }

  throw new JsonLogicParseError(`Cannot parse expression: ${typeof json}`);
};

/**
 * Parse an array JSON value
 *
 * Arrays can be:
 * - Array-syntax operators: ["var", "path"] or ["+", 1, 2]
 * - Regular arrays of expressions
 */
const parseArrayExpression = (arr: unknown[]): JsonLogicExpression => {
  if (arr.length === 0) {
    return arrayExpr([]);
  }

  const [first, ...rest] = arr;

  // Check for array-syntax operators like ["var", "path"]
  if (typeof first === 'string') {
    // Special case: var
    if (first === 'var') {
      return parseVarFromArray(rest);
    }

    // Check for known operators
    if (isKnownOperator(first)) {
      return applyExpr(
        first,
        rest.map((arg) => parseExpression(arg))
      );
    }
  }

  // Regular array of expressions
  return arrayExpr(arr.map((elem) => parseExpression(elem)));
};

/**
 * Parse a var expression from array syntax: ["var", "path"] or ["var", "path", default]
 */
const parseVarFromArray = (args: unknown[]): JsonLogicExpression => {
  if (args.length === 0) {
    throw new JsonLogicParseError('var operator requires at least one argument');
  }

  const [pathArg, defaultArg] = args;

  // Path can be string, number (for array index), or nested expression
  let path: string | JsonLogicExpression;
  if (typeof pathArg === 'string') {
    path = pathArg;
  } else if (typeof pathArg === 'number') {
    path = pathArg.toString();
  } else {
    path = parseExpression(pathArg);
  }

  // Optional default value
  const defaultValue = defaultArg !== undefined ? parseValue(defaultArg) : undefined;

  return varExpr(path, defaultValue);
};

/**
 * Parse an object JSON value
 *
 * Objects can be:
 * - {"var": ...} -> VarExpression
 * - {"op": args} -> ApplyExpression (single known operator key)
 * - {"": ...} -> VarExpression (empty string = root var)
 * - Other -> MapExpression (insertion-ordered entries; mirrors Rust, which
 *   keeps the MapExpression form even when all values are constants — this is
 *   required for object-form `let` bindings)
 */
const parseObjectExpression = (obj: Record<string, unknown>): JsonLogicExpression => {
  const keys = Object.keys(obj);

  // Empty object -> ConstExpression(MapValue)
  if (keys.length === 0) {
    return constExpr(mapValue(new Map()));
  }

  // Single key
  if (keys.length === 1) {
    const key = keys[0];
    const value = obj[key];

    // Empty string key or var operator -> VarExpression
    if (key === '' || key === 'var') {
      return parseVarExpression(value);
    }

    // Known operator
    if (isKnownOperator(key)) {
      const args = parseOperatorArgs(value);
      return applyExpr(key, args);
    }
  }

  // Not an operator - parse as MapExpression (element-wise evaluation).
  const entries: Array<[string, JsonLogicExpression]> = [];
  for (const [k, v] of Object.entries(obj)) {
    entries.push([k, parseExpression(v)]);
  }
  return mapExpr(entries);
};

/**
 * Parse operator arguments
 *
 * In metakit's JSON Logic:
 * - {"op": [arg1, arg2, ...]} -> multiple arguments
 * - {"op": arg} -> single argument
 *
 * The tricky part: arrays can be either:
 * 1. A list of arguments to the operator
 * 2. A single array value as the argument
 *
 * We follow the convention that arrays are argument lists.
 * To pass an array as a single argument, use nested arrays: {"length": [[1,2,3]]}
 */
const parseOperatorArgs = (value: unknown): JsonLogicExpression[] => {
  if (Array.isArray(value)) {
    return value.map((v) => parseExpression(v));
  }
  return [parseExpression(value)];
};

/**
 * Parse a var expression from object syntax: {"var": ...}
 */
const parseVarExpression = (value: unknown): JsonLogicExpression => {
  // Simple string path: {"var": "path"}
  if (typeof value === 'string') {
    return varExpr(value);
  }

  // Numeric path (for array index): {"var": 0}
  if (typeof value === 'number') {
    return varExpr(value.toString());
  }

  // Array with path and optional default: {"var": ["path", default]}
  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new JsonLogicParseError('var array cannot be empty');
    }

    const [pathArg, defaultArg] = value;

    let path: string | JsonLogicExpression;
    if (typeof pathArg === 'string') {
      path = pathArg;
    } else if (typeof pathArg === 'number') {
      path = pathArg.toString();
    } else {
      path = parseExpression(pathArg);
    }

    const defaultValue = defaultArg !== undefined ? parseValue(defaultArg) : undefined;
    return varExpr(path, defaultValue);
  }

  // Nested expression for dynamic path: {"var": {"op": ...}}
  return varExpr(parseExpression(value));
};

/**
 * Encode a JsonLogicValue to JSON
 *
 * IntValue encodes as a JS number while it is exactly representable
 * (|v| <= Number.MAX_SAFE_INTEGER) and as a `bigint` beyond that, preserving
 * full precision (consensus-critical for token amounts). FloatValue encodes
 * to the nearest double — the same f64 boundary the Rust/Scala encoders use.
 */
export const encodeValue = (value: JsonLogicValue): unknown => {
  switch (value.tag) {
    case 'null':
      return null;
    case 'bool':
      return value.value;
    case 'int':
      if (
        value.value >= BigInt(Number.MIN_SAFE_INTEGER) &&
        value.value <= BigInt(Number.MAX_SAFE_INTEGER)
      ) {
        return Number(value.value);
      }
      // Preserve exactness for big integers rather than silently rounding.
      return value.value;
    case 'float':
      return value.value.toNumber();
    case 'string':
      return value.value;
    case 'array':
      return value.value.map(encodeValue);
    case 'map':
      // Object.fromEntries uses CreateDataProperty semantics, so keys like
      // "__proto__" become plain own properties (no prototype pollution).
      return Object.fromEntries([...value.value.entries()].map(([k, v]) => [k, encodeValue(v)]));
    case 'function':
      return null; // Functions can't be serialized
  }
};

/**
 * Encode a JsonLogicExpression to JSON
 */
export const encodeExpression = (expr: JsonLogicExpression): unknown => {
  switch (expr.tag) {
    case 'const':
      return encodeValue(expr.value);

    case 'var': {
      const pathJson = typeof expr.path === 'string' ? expr.path : encodeExpression(expr.path);

      if (expr.defaultValue !== undefined) {
        return { var: [pathJson, encodeValue(expr.defaultValue)] };
      }
      return { var: pathJson };
    }

    case 'array':
      return expr.elements.map(encodeExpression);

    case 'map':
      return Object.fromEntries(expr.entries.map(([k, v]) => [k, encodeExpression(v)]));

    case 'apply':
      if (expr.args.length === 1) {
        return { [expr.op]: encodeExpression(expr.args[0]) };
      }
      return { [expr.op]: expr.args.map(encodeExpression) };
  }
};
