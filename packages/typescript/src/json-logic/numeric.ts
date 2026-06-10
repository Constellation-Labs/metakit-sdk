/**
 * Unified numeric handling. Mirrors rust/jlvm-core/src/numeric.rs
 * (`json_logic.ops.NumericOps` in Scala).
 *
 * All arithmetic is exact (rational). A result is IntValue only when neither
 * operand was a float and the result is integral; otherwise FloatValue.
 */

import { Ratio } from './ratio';
import type { JsonLogicValue } from './value';
import { floatValue, intValue } from './value';

export type Numeric =
  | { readonly kind: 'int'; readonly value: bigint }
  | { readonly kind: 'float'; readonly value: Ratio };

export const numericInt = (value: bigint): Numeric => ({ kind: 'int', value });
export const numericFloat = (value: Ratio): Numeric => ({ kind: 'float', value });

export const numericToRatio = (n: Numeric): Ratio =>
  n.kind === 'int' ? Ratio.fromBigInt(n.value) : n.value;

export const numericIsFloat = (n: Numeric): boolean => n.kind === 'float';

export const numericToValue = (n: Numeric): JsonLogicValue =>
  n.kind === 'int' ? intValue(n.value) : floatValue(n.value);

/**
 * `BigInt(s)` parse: strict integer, allowing a leading sign. Mirrors Scala's
 * `BigInt(s)` / Rust `parse_bigint`.
 */
export const parseBigInt = (s: string): bigint | null => {
  const t = s.trim();
  if (t.length === 0) return null;
  let body = t;
  let sign = 1n;
  if (body.startsWith('+')) {
    body = body.slice(1);
  } else if (body.startsWith('-')) {
    sign = -1n;
    body = body.slice(1);
  }
  if (body.length === 0 || !/^[0-9]+$/.test(body)) return null;
  return sign * BigInt(body);
};

/**
 * Promote a value to a numeric type with JS-style coercion.
 * Mirrors `promoteToNumeric`. Throws on inconvertible values.
 */
export const promoteToNumeric = (value: JsonLogicValue): Numeric => {
  switch (value.tag) {
    case 'int':
      return numericInt(value.value);
    case 'float':
      return numericFloat(value.value);
    case 'bool':
      return numericInt(value.value ? 1n : 0n);
    case 'null':
      return numericInt(0n);
    case 'string': {
      const s = value.value;
      if (s.length === 0) {
        return numericInt(0n);
      }
      const i = parseBigInt(s);
      if (i !== null) {
        return numericInt(i);
      }
      const r = Ratio.parseDecimal(s);
      if (r !== null) {
        return numericFloat(r);
      }
      throw new Error(`Cannot convert string '${s}' to number`);
    }
    case 'array': {
      const list = value.value;
      if (list.length === 0) return numericInt(0n);
      if (list.length === 1) return promoteToNumeric(list[0]);
      throw new Error('Cannot convert multi-element array to number');
    }
    case 'map': {
      const entries = [...value.value.values()];
      if (entries.length === 0) return numericInt(0n);
      if (entries.length === 1) return promoteToNumeric(entries[0]);
      throw new Error('Cannot convert multi-key object to number');
    }
    case 'function':
      throw new Error('Cannot convert function to number');
  }
};

/**
 * Combine two numerics with an exact-rational op, typing the result.
 * Mirrors `combineNumeric`.
 */
export const combineNumeric = (
  op: (a: Ratio, b: Ratio) => Ratio,
  left: Numeric,
  right: Numeric
): JsonLogicValue => {
  const result = op(numericToRatio(left), numericToRatio(right));
  if (!numericIsFloat(left) && !numericIsFloat(right) && result.isInteger()) {
    return intValue(result.numerator);
  }
  return floatValue(result);
};

/**
 * Reduce a list of values with an exact-rational op. Mirrors `reduceNumeric`.
 */
export const reduceNumeric = (
  values: JsonLogicValue[],
  op: (a: Ratio, b: Ratio) => Ratio
): JsonLogicValue => {
  if (values.length === 0) {
    throw new Error('Cannot reduce empty list');
  }
  const numerics = values.map(promoteToNumeric);
  const hasFloat = numerics.some(numericIsFloat);
  let acc = numericToRatio(numerics[0]);
  for (let i = 1; i < numerics.length; i++) {
    acc = op(acc, numericToRatio(numerics[i]));
  }
  if (!hasFloat && acc.isInteger()) {
    return intValue(acc.numerator);
  }
  return floatValue(acc);
};

/** Exact comparison of two numerics: -1, 0, or 1. Mirrors `compareNumeric`. */
export const compareNumeric = (left: Numeric, right: Numeric): number =>
  numericToRatio(left).compare(numericToRatio(right));
