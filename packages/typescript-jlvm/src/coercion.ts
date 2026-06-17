/**
 * Loose-equality coercion. Mirrors rust/jlvm-core/src/coercion.rs
 * (`json_logic.ops.CoercionOps` in Scala).
 */

import { Ratio } from './ratio';
import { parseBigInt, promoteToNumeric, numericToRatio } from './numeric';
import type { JsonLogicValue } from './value';

const MAX_NUMERIC_STRING_LENGTH = 1000;

export type Coerced =
  | { readonly kind: 'null' }
  | { readonly kind: 'bool'; readonly value: boolean }
  | { readonly kind: 'int'; readonly value: bigint }
  | { readonly kind: 'float'; readonly value: Ratio }
  | { readonly kind: 'string'; readonly value: string };

const safeParseBigInt = (s: string): bigint | null =>
  s.length > MAX_NUMERIC_STRING_LENGTH ? null : parseBigInt(s);

const safeParseDecimal = (s: string): Ratio | null =>
  s.length > MAX_NUMERIC_STRING_LENGTH ? null : Ratio.parseDecimal(s);

/** Mirrors Scala's `String.toBooleanOption`: only exact lowercase true/false. */
const parseBool = (s: string): boolean | null =>
  s === 'true' ? true : s === 'false' ? false : null;

/**
 * Coerce a value to a primitive. Mirrors `coerceToPrimitive`. Note the
 * JS-flavored rules: empty string -> Int(0); numeric strings -> Int when they
 * parse as BigInt. Throws on inconvertible values.
 */
export const coerceToPrimitive = (value: JsonLogicValue): Coerced => {
  switch (value.tag) {
    case 'null':
      return { kind: 'null' };
    case 'bool':
      return { kind: 'bool', value: value.value };
    case 'int':
      return { kind: 'int', value: value.value };
    case 'float':
      return { kind: 'float', value: value.value };
    case 'string': {
      const s = value.value;
      if (s.length === 0) {
        return { kind: 'int', value: 0n };
      }
      const i = safeParseBigInt(s);
      if (i !== null) {
        return { kind: 'int', value: i };
      }
      return { kind: 'string', value: s };
    }
    case 'function':
      throw new Error('Cannot coerce FunctionValue to a primitive');
    case 'array': {
      const list = value.value;
      if (list.length === 0) return { kind: 'int', value: 0n };
      if (list.length === 1) return coerceToPrimitive(list[0]);
      throw new Error('Cannot coerce multi-element array to a single primitive');
    }
    case 'map': {
      const entries = [...value.value.values()];
      if (entries.length === 0) return { kind: 'int', value: 0n };
      if (entries.length === 1) return coerceToPrimitive(entries[0]);
      throw new Error('Cannot coerce multi-key object to a single primitive');
    }
  }
};

/**
 * Compare two coerced values for loose equality. Mirrors `compareCoercedValues`.
 */
export const compareCoerced = (l: Coerced, r: Coerced): boolean => {
  if (l.kind === 'null' || r.kind === 'null') {
    return l.kind === 'null' && r.kind === 'null';
  }

  if (l.kind === 'bool') {
    switch (r.kind) {
      case 'bool':
        return l.value === r.value;
      case 'int':
        return r.value === (l.value ? 1n : 0n);
      case 'float':
        return r.value.equals(Ratio.fromBigInt(l.value ? 1n : 0n));
      case 'string':
        return parseBool(r.value) === l.value;
    }
  }

  if (l.kind === 'int') {
    switch (r.kind) {
      case 'bool':
        return l.value === (r.value ? 1n : 0n);
      case 'int':
        return l.value === r.value;
      case 'float':
        return Ratio.fromBigInt(l.value).equals(r.value);
      case 'string': {
        const parsed = safeParseBigInt(r.value);
        return parsed !== null && parsed === l.value;
      }
    }
  }

  if (l.kind === 'float') {
    switch (r.kind) {
      case 'bool':
        return l.value.equals(Ratio.fromBigInt(r.value ? 1n : 0n));
      case 'int':
        return l.value.equals(Ratio.fromBigInt(r.value));
      case 'float':
        return l.value.equals(r.value);
      case 'string': {
        const parsed = safeParseDecimal(r.value);
        return parsed !== null && parsed.equals(l.value);
      }
    }
  }

  // l.kind === 'string'
  switch (r.kind) {
    case 'bool':
      return parseBool(l.value) === r.value;
    case 'int': {
      const parsed = safeParseBigInt(l.value);
      return parsed !== null && parsed === r.value;
    }
    case 'float': {
      const parsed = safeParseDecimal(l.value);
      return parsed !== null && parsed.equals(r.value);
    }
    case 'string':
      return l.value === r.value;
  }
};

/**
 * Loose equality with type coercion (`==`). Returns false when either side
 * cannot be coerced to a primitive. Kept for API compatibility.
 */
export const looseEquals = (a: JsonLogicValue, b: JsonLogicValue): boolean => {
  try {
    return compareCoerced(coerceToPrimitive(a), coerceToPrimitive(b));
  } catch {
    return false;
  }
};

/**
 * Convert a value to a JS number (f64 boundary), or null when inconvertible.
 * Kept for API compatibility; internal arithmetic never uses this.
 */
export const toNumber = (v: JsonLogicValue): number | null => {
  try {
    return numericToRatio(promoteToNumeric(v)).toNumber();
  } catch {
    return null;
  }
};
