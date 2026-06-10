/**
 * JSON Logic Value Types
 *
 * Represents runtime values in the JSON Logic VM.
 * Mirrors the Scala implementation in metakit and rust/jlvm-core/src/value.rs:
 * NullValue, BoolValue, IntValue (unbounded bigint), FloatValue (exact Ratio),
 * StrValue, ArrayValue, MapValue (insertion-ordered, prototype-safe `Map`),
 * and FunctionValue.
 */

import type { JsonLogicExpression } from './expression';
import { Ratio } from './ratio';

// Discriminated union tag
export type JsonLogicValueTag =
  | 'null'
  | 'bool'
  | 'int'
  | 'float'
  | 'string'
  | 'array'
  | 'map'
  | 'function';

// Base interface
export interface JsonLogicValueBase {
  readonly tag: JsonLogicValueTag;
}

// Null value
export interface NullValue extends JsonLogicValueBase {
  readonly tag: 'null';
}

// Boolean value
export interface BoolValue extends JsonLogicValueBase {
  readonly tag: 'bool';
  readonly value: boolean;
}

// Integer value (arbitrary precision)
export interface IntValue extends JsonLogicValueBase {
  readonly tag: 'int';
  readonly value: bigint;
}

// Float value (exact rational - see ratio.ts)
export interface FloatValue extends JsonLogicValueBase {
  readonly tag: 'float';
  readonly value: Ratio;
}

// String value
export interface StrValue extends JsonLogicValueBase {
  readonly tag: 'string';
  readonly value: string;
}

// Array value
export interface ArrayValue extends JsonLogicValueBase {
  readonly tag: 'array';
  readonly value: JsonLogicValue[];
}

// Map/Object value. Backed by a `Map` (insertion-ordered, immune to prototype
// pollution via attacker-controlled keys like "__proto__"/"constructor").
export interface MapValue extends JsonLogicValueBase {
  readonly tag: 'map';
  readonly value: Map<string, JsonLogicValue>;
}

// Function value (unevaluated expression)
export interface FunctionValue extends JsonLogicValueBase {
  readonly tag: 'function';
  readonly expr: JsonLogicExpression;
}

// Union of all value types
export type JsonLogicValue =
  | NullValue
  | BoolValue
  | IntValue
  | FloatValue
  | StrValue
  | ArrayValue
  | MapValue
  | FunctionValue;

// Type guards
export const isNull = (v: JsonLogicValue): v is NullValue => v.tag === 'null';
export const isBool = (v: JsonLogicValue): v is BoolValue => v.tag === 'bool';
export const isInt = (v: JsonLogicValue): v is IntValue => v.tag === 'int';
export const isFloat = (v: JsonLogicValue): v is FloatValue => v.tag === 'float';
export const isStr = (v: JsonLogicValue): v is StrValue => v.tag === 'string';
export const isArray = (v: JsonLogicValue): v is ArrayValue => v.tag === 'array';
export const isMap = (v: JsonLogicValue): v is MapValue => v.tag === 'map';
export const isFunction = (v: JsonLogicValue): v is FunctionValue => v.tag === 'function';

// Numeric check (int or float)
export const isNumeric = (v: JsonLogicValue): v is IntValue | FloatValue =>
  v.tag === 'int' || v.tag === 'float';

// Primitive check
export const isPrimitive = (v: JsonLogicValue): v is BoolValue | IntValue | FloatValue | StrValue =>
  v.tag === 'bool' || v.tag === 'int' || v.tag === 'float' || v.tag === 'string';

// Collection check
export const isCollection = (v: JsonLogicValue): v is ArrayValue | MapValue =>
  v.tag === 'array' || v.tag === 'map';

// Constructors
export const nullValue = (): NullValue => ({ tag: 'null' });
export const boolValue = (value: boolean): BoolValue => ({ tag: 'bool', value });
export const intValue = (value: bigint | number): IntValue => ({
  tag: 'int',
  value: typeof value === 'number' ? BigInt(Math.trunc(value)) : value,
});
export const floatValue = (value: Ratio | number): FloatValue => ({
  tag: 'float',
  value: value instanceof Ratio ? value : ratioFromNumber(value),
});
export const strValue = (value: string): StrValue => ({ tag: 'string', value });
export const arrayValue = (value: JsonLogicValue[]): ArrayValue => ({ tag: 'array', value });
export const mapValue = (
  value: Map<string, JsonLogicValue> | Record<string, JsonLogicValue>
): MapValue => ({
  tag: 'map',
  value: value instanceof Map ? value : new Map(Object.entries(value)),
});
export const functionValue = (expr: JsonLogicExpression): FunctionValue => ({
  tag: 'function',
  expr,
});

/**
 * Exact Ratio from a finite JS number, via its ECMAScript shortest-round-trip
 * decimal form (the same value Rust gets from serde_json's f64 Display).
 */
export const ratioFromNumber = (n: number): Ratio => {
  if (!Number.isFinite(n)) {
    throw new Error(`Cannot represent non-finite number ${n} as an exact ratio`);
  }
  const r = Ratio.parseDecimal(String(n));
  if (r === null) {
    throw new Error(`Cannot parse number ${n} as an exact ratio`);
  }
  return r;
};

// Empty values
export const emptyArray = (): ArrayValue => arrayValue([]);
export const emptyMap = (): MapValue => mapValue(new Map());

// Truthiness (matches Scala/Rust `isTruthy`)
export const isTruthy = (v: JsonLogicValue): boolean => {
  switch (v.tag) {
    case 'null':
      return false;
    case 'bool':
      return v.value;
    case 'int':
      return v.value !== 0n;
    case 'float':
      return !v.value.isZero();
    case 'string':
      return v.value.length > 0;
    case 'array':
      return v.value.length > 0;
    case 'map':
      return v.value.size > 0;
    case 'function':
      return false;
  }
};

// Get default value for a type
export const getDefault = (v: JsonLogicValue): JsonLogicValue => {
  switch (v.tag) {
    case 'null':
      return nullValue();
    case 'bool':
      return boolValue(false);
    case 'int':
      return intValue(0n);
    case 'float':
      return floatValue(Ratio.zero());
    case 'string':
      return strValue('');
    case 'array':
      return emptyArray();
    case 'map':
      return emptyMap();
    case 'function':
      return nullValue();
  }
};

/**
 * Structural (deep) equality. Used by `===`/`!==` for collections and by `in`,
 * `unique`, `intersect`. Mirrors Rust `Value::deep_eq` / Scala `eqJsonLogicValue`.
 * Strict: types must match (1 !== 1.0); functions are never equal.
 */
export const strictEquals = (a: JsonLogicValue, b: JsonLogicValue): boolean => {
  if (a.tag !== b.tag) return false;

  switch (a.tag) {
    case 'null':
      return true;
    case 'bool':
      return a.value === (b as BoolValue).value;
    case 'int':
      return a.value === (b as IntValue).value;
    case 'float':
      return a.value.equals((b as FloatValue).value);
    case 'string':
      return a.value === (b as StrValue).value;
    case 'array': {
      const bArr = (b as ArrayValue).value;
      if (a.value.length !== bArr.length) return false;
      return a.value.every((v, i) => strictEquals(v, bArr[i]));
    }
    case 'map': {
      const bMap = (b as MapValue).value;
      if (a.value.size !== bMap.size) return false;
      for (const [k, v] of a.value) {
        const bv = bMap.get(k);
        if (bv === undefined || !strictEquals(v, bv)) return false;
      }
      return true;
    }
    case 'function':
      return false; // Functions are never equal
  }
};

// Convert to string (debug/display rendering)
export const toString = (v: JsonLogicValue): string => {
  switch (v.tag) {
    case 'null':
      return 'null';
    case 'bool':
      return v.value.toString();
    case 'int':
      return v.value.toString();
    case 'float':
      return v.value.toPlainString();
    case 'string':
      return v.value;
    case 'array':
      return `[${v.value.map(toString).join(', ')}]`;
    case 'map':
      return `{${[...v.value.entries()]
        .map(([k, val]) => `"${k}": ${toString(val)}`)
        .join(', ')}}`;
    case 'function':
      return '<function>';
  }
};
