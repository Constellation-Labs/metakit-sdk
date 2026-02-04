/**
 * JSON Logic Expression Types
 *
 * The AST (Abstract Syntax Tree) for JSON Logic expressions.
 * Mirrors the Scala implementation in metakit.
 */

import type { JsonLogicOpTag } from './operators';
import type { JsonLogicValue } from './value';

// Expression type tags
export type JsonLogicExpressionTag = 'apply' | 'const' | 'array' | 'map' | 'var';

// Base interface
export interface JsonLogicExpressionBase {
  readonly tag: JsonLogicExpressionTag;
}

/**
 * Apply an operator to arguments
 * e.g., { "+": [1, 2] } -> ApplyExpression("+", [ConstExpression(1), ConstExpression(2)])
 */
export interface ApplyExpression extends JsonLogicExpressionBase {
  readonly tag: 'apply';
  readonly op: JsonLogicOpTag;
  readonly args: JsonLogicExpression[];
}

/**
 * A constant/literal value
 * e.g., 42 -> ConstExpression(IntValue(42))
 */
export interface ConstExpression extends JsonLogicExpressionBase {
  readonly tag: 'const';
  readonly value: JsonLogicValue;
}

/**
 * An array of expressions (not a literal array)
 * e.g., [{"var": "x"}, 1] when the array contains expressions
 */
export interface ArrayExpression extends JsonLogicExpressionBase {
  readonly tag: 'array';
  readonly elements: JsonLogicExpression[];
}

/**
 * A map/object of expressions (not a literal map)
 * e.g., {"a": {"var": "x"}, "b": 1} when the map contains expressions
 */
export interface MapExpression extends JsonLogicExpressionBase {
  readonly tag: 'map';
  readonly entries: Record<string, JsonLogicExpression>;
}

/**
 * Variable reference
 * e.g., {"var": "user.name"} -> VarExpression("user.name")
 * e.g., {"var": ["user.name", "default"]} -> VarExpression("user.name", defaultValue)
 */
export interface VarExpression extends JsonLogicExpressionBase {
  readonly tag: 'var';
  /** Path can be a string or a nested expression */
  readonly path: string | JsonLogicExpression;
  /** Optional default value if path doesn't exist */
  readonly defaultValue?: JsonLogicValue;
}

// Union of all expression types
export type JsonLogicExpression =
  | ApplyExpression
  | ConstExpression
  | ArrayExpression
  | MapExpression
  | VarExpression;

// Type guards
export const isApply = (e: JsonLogicExpression): e is ApplyExpression => e.tag === 'apply';
export const isConst = (e: JsonLogicExpression): e is ConstExpression => e.tag === 'const';
export const isArrayExpr = (e: JsonLogicExpression): e is ArrayExpression => e.tag === 'array';
export const isMapExpr = (e: JsonLogicExpression): e is MapExpression => e.tag === 'map';
export const isVar = (e: JsonLogicExpression): e is VarExpression => e.tag === 'var';

// Constructors
export const applyExpr = (op: JsonLogicOpTag, args: JsonLogicExpression[]): ApplyExpression => ({
  tag: 'apply',
  op,
  args,
});

export const constExpr = (value: JsonLogicValue): ConstExpression => ({
  tag: 'const',
  value,
});

export const arrayExpr = (elements: JsonLogicExpression[]): ArrayExpression => ({
  tag: 'array',
  elements,
});

export const mapExpr = (entries: Record<string, JsonLogicExpression>): MapExpression => ({
  tag: 'map',
  entries,
});

export const varExpr = (
  path: string | JsonLogicExpression,
  defaultValue?: JsonLogicValue
): VarExpression => ({
  tag: 'var',
  path,
  defaultValue,
});
