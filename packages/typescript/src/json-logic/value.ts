/**
 * JSON Logic Value Types
 *
 * Represents runtime values in the JSON Logic VM.
 * Mirrors the Scala implementation in metakit.
 */

import type { JsonLogicExpression } from './expression';

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

// Float value (decimal)
export interface FloatValue extends JsonLogicValueBase {
  readonly tag: 'float';
  readonly value: number;
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

// Map/Object value
export interface MapValue extends JsonLogicValueBase {
  readonly tag: 'map';
  readonly value: Record<string, JsonLogicValue>;
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
export const floatValue = (value: number): FloatValue => ({ tag: 'float', value });
export const strValue = (value: string): StrValue => ({ tag: 'string', value });
export const arrayValue = (value: JsonLogicValue[]): ArrayValue => ({ tag: 'array', value });
export const mapValue = (value: Record<string, JsonLogicValue>): MapValue => ({ tag: 'map', value });
export const functionValue = (expr: JsonLogicExpression): FunctionValue => ({ tag: 'function', expr });

// Empty values
export const emptyArray = (): ArrayValue => arrayValue([]);
export const emptyMap = (): MapValue => mapValue({});

// Truthiness (matches Scala implementation)
export const isTruthy = (v: JsonLogicValue): boolean => {
  switch (v.tag) {
    case 'null':
      return false;
    case 'bool':
      return v.value;
    case 'int':
      return v.value !== 0n;
    case 'float':
      return v.value !== 0;
    case 'string':
      return v.value.length > 0;
    case 'array':
      return v.value.length > 0;
    case 'map':
      return Object.keys(v.value).length > 0;
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
      return floatValue(0);
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

// Equality (strict - types must match, 1 !== 1.0)
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
      return a.value === (b as FloatValue).value;
    case 'string':
      return a.value === (b as StrValue).value;
    case 'array': {
      const bArr = (b as ArrayValue).value;
      if (a.value.length !== bArr.length) return false;
      return a.value.every((v, i) => strictEquals(v, bArr[i]));
    }
    case 'map': {
      const aKeys = Object.keys(a.value);
      const bMap = (b as MapValue).value;
      const bKeys = Object.keys(bMap);
      if (aKeys.length !== bKeys.length) return false;
      return aKeys.every((k) => k in bMap && strictEquals(a.value[k], bMap[k]));
    }
    case 'function':
      return false; // Functions are never equal
  }
};

// Loose equality (with type coercion)
export const looseEquals = (a: JsonLogicValue, b: JsonLogicValue): boolean => {
  // Same type - use strict
  if (a.tag === b.tag) return strictEquals(a, b);

  // Null equals null only
  if (a.tag === 'null' || b.tag === 'null') return false;

  // Numeric comparison (int vs float)
  if (isNumeric(a) && isNumeric(b)) {
    const aNum = a.tag === 'int' ? Number(a.value) : a.value;
    const bNum = b.tag === 'int' ? Number(b.value) : b.value;
    return aNum === bNum;
  }

  // String to number coercion
  if (isNumeric(a) && isStr(b)) {
    const bNum = parseFloat(b.value);
    if (isNaN(bNum)) return false;
    const aNum = a.tag === 'int' ? Number(a.value) : a.value;
    return aNum === bNum;
  }
  if (isStr(a) && isNumeric(b)) {
    return looseEquals(b, a);
  }

  return false;
};

// Convert to number (for arithmetic)
export const toNumber = (v: JsonLogicValue): number | null => {
  switch (v.tag) {
    case 'int':
      return Number(v.value);
    case 'float':
      return v.value;
    case 'string': {
      const n = parseFloat(v.value);
      return isNaN(n) ? null : n;
    }
    case 'bool':
      return v.value ? 1 : 0;
    default:
      return null;
  }
};

// Convert to string
export const toString = (v: JsonLogicValue): string => {
  switch (v.tag) {
    case 'null':
      return 'null';
    case 'bool':
      return v.value.toString();
    case 'int':
      return v.value.toString();
    case 'float':
      return v.value.toString();
    case 'string':
      return v.value;
    case 'array':
      return `[${v.value.map(toString).join(', ')}]`;
    case 'map':
      return `{${Object.entries(v.value)
        .map(([k, val]) => `"${k}": ${toString(val)}`)
        .join(', ')}}`;
    case 'function':
      return '<function>';
  }
};
