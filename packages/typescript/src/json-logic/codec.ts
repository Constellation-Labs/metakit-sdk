/**
 * JSON Logic Codec
 *
 * Parse JSON to expressions and encode expressions to JSON.
 * Matches the Scala metakit serialization format.
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

/**
 * Error thrown when parsing fails
 */
export class JsonLogicParseError extends Error {
  constructor(message: string, public readonly path?: string) {
    super(path ? `${message} at ${path}` : message);
    this.name = 'JsonLogicParseError';
  }
}

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

  if (typeof json === 'number') {
    // Check if it's an integer
    if (Number.isInteger(json) && Number.isSafeInteger(json)) {
      return intValue(BigInt(json));
    }
    return floatValue(json);
  }

  if (typeof json === 'string') {
    return strValue(json);
  }

  if (Array.isArray(json)) {
    return arrayValue(json.map(parseValue));
  }

  if (typeof json === 'object') {
    const result: Record<string, JsonLogicValue> = {};
    for (const [key, val] of Object.entries(json)) {
      result[key] = parseValue(val);
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
 * - Other objects -> MapExpression or ConstExpression(MapValue)
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

  // Number
  if (typeof json === 'number') {
    if (Number.isInteger(json) && Number.isSafeInteger(json)) {
      return constExpr(intValue(BigInt(json)));
    }
    return constExpr(floatValue(json));
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
 * - Other -> MapExpression
 */
const parseObjectExpression = (obj: Record<string, unknown>): JsonLogicExpression => {
  const keys = Object.keys(obj);

  // Empty object -> ConstExpression(MapValue)
  if (keys.length === 0) {
    return constExpr(mapValue({}));
  }

  // Single key
  if (keys.length === 1) {
    const key = keys[0];
    const value = obj[key];

    // Empty string key -> var to root
    if (key === '') {
      return parseVarExpression(value);
    }

    // var operator
    if (key === 'var') {
      return parseVarExpression(value);
    }

    // Known operator
    if (isKnownOperator(key)) {
      const args = parseOperatorArgs(value);
      return applyExpr(key, args);
    }
  }

  // Not an operator - parse as MapExpression or ConstExpression(MapValue)
  // If all values are simple values (no expressions), use ConstExpression
  // Otherwise use MapExpression
  const entries: Record<string, JsonLogicExpression> = {};
  let hasExpressions = false;

  for (const [k, v] of Object.entries(obj)) {
    const expr = parseExpression(v);
    entries[k] = expr;

    // Check if this is more than a simple const
    if (expr.tag !== 'const') {
      hasExpressions = true;
    }
  }

  if (hasExpressions) {
    return mapExpr(entries);
  }

  // All values are consts - collapse to ConstExpression(MapValue)
  const constEntries: Record<string, JsonLogicValue> = {};
  for (const [k, expr] of Object.entries(entries)) {
    if (expr.tag === 'const') {
      constEntries[k] = expr.value;
    }
  }
  return constExpr(mapValue(constEntries));
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
 */
export const encodeValue = (value: JsonLogicValue): unknown => {
  switch (value.tag) {
    case 'null':
      return null;
    case 'bool':
      return value.value;
    case 'int':
      // BigInt can't be directly serialized to JSON
      // If it fits in a safe integer, use number; otherwise use string
      if (value.value >= BigInt(Number.MIN_SAFE_INTEGER) && value.value <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return Number(value.value);
      }
      // For very large integers, we lose precision but match JSON semantics
      return Number(value.value);
    case 'float':
      return value.value;
    case 'string':
      return value.value;
    case 'array':
      return value.value.map(encodeValue);
    case 'map': {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value.value)) {
        result[k] = encodeValue(v);
      }
      return result;
    }
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

    case 'map': {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(expr.entries)) {
        result[k] = encodeExpression(v);
      }
      return result;
    }

    case 'apply':
      if (expr.args.length === 1) {
        return { [expr.op]: encodeExpression(expr.args[0]) };
      }
      return { [expr.op]: expr.args.map(encodeExpression) };
  }
};
