/**
 * JSON Logic Operators
 *
 * All supported operators in the JSON Logic VM.
 * Matches the Scala metakit implementation.
 */

// Operator tags (string literals for JSON serialization)
export type JsonLogicOpTag =
  // Control Flow
  | 'noop'
  | 'if'
  | 'default'
  | 'let'
  // Logical
  | '!'
  | '!!'
  | 'or'
  | 'and'
  // Comparison
  | '=='
  | '==='
  | '!='
  | '!=='
  | '<'
  | '<='
  | '>'
  | '>='
  // Arithmetic
  | '+'
  | '-'
  | '*'
  | '/'
  | '%'
  | 'max'
  | 'min'
  | 'abs'
  | 'round'
  | 'floor'
  | 'ceil'
  | 'pow'
  // Array
  | 'map'
  | 'filter'
  | 'reduce'
  | 'merge'
  | 'all'
  | 'some'
  | 'none'
  | 'find'
  | 'count'
  | 'in'
  | 'intersect'
  | 'unique'
  | 'slice'
  | 'reverse'
  | 'flatten'
  // String
  | 'cat'
  | 'substr'
  | 'lower'
  | 'upper'
  | 'join'
  | 'split'
  | 'trim'
  | 'startsWith'
  | 'endsWith'
  // Object/Map
  | 'values'
  | 'keys'
  | 'get'
  | 'has'
  | 'entries'
  // Utility
  | 'length'
  | 'exists'
  | 'missing'
  | 'missing_some'
  | 'typeof';

// All known operator tags
export const KNOWN_OPERATORS: ReadonlySet<JsonLogicOpTag> = new Set([
  // Control Flow
  'noop',
  'if',
  'default',
  'let',
  // Logical
  '!',
  '!!',
  'or',
  'and',
  // Comparison
  '==',
  '===',
  '!=',
  '!==',
  '<',
  '<=',
  '>',
  '>=',
  // Arithmetic
  '+',
  '-',
  '*',
  '/',
  '%',
  'max',
  'min',
  'abs',
  'round',
  'floor',
  'ceil',
  'pow',
  // Array
  'map',
  'filter',
  'reduce',
  'merge',
  'all',
  'some',
  'none',
  'find',
  'count',
  'in',
  'intersect',
  'unique',
  'slice',
  'reverse',
  'flatten',
  // String
  'cat',
  'substr',
  'lower',
  'upper',
  'join',
  'split',
  'trim',
  'startsWith',
  'endsWith',
  // Object/Map
  'values',
  'keys',
  'get',
  'has',
  'entries',
  // Utility
  'length',
  'exists',
  'missing',
  'missing_some',
  'typeof',
]);

// Check if a string is a known operator
export const isKnownOperator = (tag: string): tag is JsonLogicOpTag =>
  KNOWN_OPERATORS.has(tag as JsonLogicOpTag);

// Operator categories for documentation/grouping
export const OPERATOR_CATEGORIES = {
  controlFlow: ['noop', 'if', 'default', 'let'] as const,
  logical: ['!', '!!', 'or', 'and'] as const,
  comparison: ['==', '===', '!=', '!==', '<', '<=', '>', '>='] as const,
  arithmetic: ['+', '-', '*', '/', '%', 'max', 'min', 'abs', 'round', 'floor', 'ceil', 'pow'] as const,
  array: [
    'map',
    'filter',
    'reduce',
    'merge',
    'all',
    'some',
    'none',
    'find',
    'count',
    'in',
    'intersect',
    'unique',
    'slice',
    'reverse',
    'flatten',
  ] as const,
  string: ['cat', 'substr', 'lower', 'upper', 'join', 'split', 'trim', 'startsWith', 'endsWith'] as const,
  object: ['values', 'keys', 'get', 'has', 'entries'] as const,
  utility: ['length', 'exists', 'missing', 'missing_some', 'typeof'] as const,
} as const;
