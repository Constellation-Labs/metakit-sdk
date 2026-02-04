/**
 * JSON Logic VM for Metakit
 *
 * A TypeScript implementation of the JSON Logic virtual machine
 * compatible with the Scala metakit implementation.
 *
 * @example
 * ```typescript
 * import { jsonLogic } from '@constellation-network/metagraph-sdk/json-logic';
 *
 * // Parse and evaluate a JSON Logic expression
 * const result = jsonLogic.apply(
 *   { "+": [1, { "var": "x" }] },
 *   { x: 2 }
 * );
 * // result = 3
 * ```
 */

// Re-export types
export type {
  JsonLogicValue,
  JsonLogicValueTag,
  NullValue,
  BoolValue,
  IntValue,
  FloatValue,
  StrValue,
  ArrayValue,
  MapValue,
  FunctionValue,
} from './value';

export type {
  JsonLogicExpression,
  JsonLogicExpressionTag,
  ApplyExpression,
  ConstExpression,
  ArrayExpression,
  MapExpression,
  VarExpression,
} from './expression';

export type { JsonLogicOpTag } from './operators';

// Re-export constructors and utilities
export {
  // Value constructors
  nullValue,
  boolValue,
  intValue,
  floatValue,
  strValue,
  arrayValue,
  mapValue,
  functionValue,
  emptyArray,
  emptyMap,
  // Value type guards
  isNull,
  isBool,
  isInt,
  isFloat,
  isStr,
  isArray,
  isMap,
  isFunction,
  isNumeric,
  isPrimitive,
  isCollection,
  // Value utilities
  isTruthy,
  getDefault,
  strictEquals,
  looseEquals,
  toNumber,
  toString,
} from './value';

export {
  // Expression constructors
  applyExpr,
  constExpr,
  arrayExpr,
  mapExpr,
  varExpr,
  // Expression type guards
  isApply,
  isConst,
  isArrayExpr,
  isMapExpr,
  isVar,
} from './expression';

export { KNOWN_OPERATORS, isKnownOperator, OPERATOR_CATEGORIES } from './operators';

export {
  // Codec
  parseExpression,
  parseValue,
  encodeExpression,
  encodeValue,
  JsonLogicParseError,
} from './codec';

export {
  // Errors
  JsonLogicError,
  JsonLogicTypeError,
  JsonLogicArityError,
  JsonLogicDivisionByZeroError,
  JsonLogicUnknownOperatorError,
  JsonLogicVariableNotFoundError,
  JsonLogicOutOfGasError,
  JsonLogicRuntimeError,
  // Result type
  type JsonLogicResult,
  ok,
  err,
  tryCatch,
  andThen,
  map,
} from './errors';

export { evaluate, type EvaluationContext } from './evaluator';

// Gas metering
export {
  type GasCost,
  type GasLimit,
  type GasUsed,
  type GasConfig,
  type EvaluationResult,
  gasCost,
  gasLimit,
  gasUsed,
  addCost,
  multiplyCost,
  canAfford,
  consumeGas,
  getOperatorCost,
  depthPenalty,
  sizeCost,
  evaluationResult,
  DEFAULT_GAS_CONFIG,
  DEV_GAS_CONFIG,
  MAINNET_GAS_CONFIG,
  DEFAULT_GAS_LIMIT,
  UNLIMITED_GAS,
  ZERO_GAS_USED,
} from './gas';

// ============= High-level API =============

import { parseExpression, parseValue, encodeValue } from './codec';
import { evaluate } from './evaluator';
import type { JsonLogicValue } from './value';

/**
 * High-level JSON Logic interface (similar to json-logic-js)
 */
export const jsonLogic = {
  /**
   * Apply a JSON Logic expression to data
   *
   * @param logic - The JSON Logic expression (as JSON)
   * @param data - The data object (as JSON)
   * @returns The result (as JSON)
   * @throws JsonLogicError on evaluation errors
   *
   * @example
   * ```typescript
   * jsonLogic.apply({ "+": [1, 2] }, {}); // 3
   * jsonLogic.apply({ "var": "x" }, { x: 42 }); // 42
   * jsonLogic.apply({ "if": [true, "yes", "no"] }, {}); // "yes"
   * ```
   */
  apply(logic: unknown, data: unknown = {}): unknown {
    const expr = parseExpression(logic);
    const dataValue = parseValue(data);
    const result = evaluate(expr, dataValue);

    if (!result.ok) {
      throw result.error;
    }

    return encodeValue(result.value);
  },

  /**
   * Apply and return a typed result
   */
  applyTyped(logic: unknown, data: unknown = {}): JsonLogicValue {
    const expr = parseExpression(logic);
    const dataValue = parseValue(data);
    const result = evaluate(expr, dataValue);

    if (!result.ok) {
      throw result.error;
    }

    return result.value;
  },

  /**
   * Check if a value is truthy (according to JSON Logic rules)
   */
  truthy(value: unknown): boolean {
    const v = parseValue(value);
    return v.tag === 'null'
      ? false
      : v.tag === 'bool'
        ? v.value
        : v.tag === 'int'
          ? v.value !== 0n
          : v.tag === 'float'
            ? v.value !== 0
            : v.tag === 'string'
              ? v.value.length > 0
              : v.tag === 'array'
                ? v.value.length > 0
                : v.tag === 'map'
                  ? Object.keys(v.value).length > 0
                  : false;
  },
};

// Default export
export default jsonLogic;
