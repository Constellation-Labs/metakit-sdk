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
  | 'typeof'
  // ZK / crypto opcodes (Tiers 1-3), mirroring Scala `JsonLogicOp` / Rust `ops.rs`.
  // All are decodable; the evaluator implements poseidon / pmt_verify /
  // schnorr_verify / bls_verify / bls_aggregate_verify and rejects the rest at
  // runtime ("Unsupported operator: ...") until they are ported.
  | 'poseidon'
  | 'pmt_verify'
  | 'schnorr_verify'
  | 'smt_verify'
  | 'mpt_verify'
  | 'mpt_prefix_verify'
  | 'bn254_add'
  | 'bn254_mul'
  | 'bn254_pairing'
  | 'ecvrf_verify'
  | 'groth16_verify'
  | 'bls_verify'
  | 'bls_aggregate_verify';

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
  // ZK / crypto
  'poseidon',
  'pmt_verify',
  'schnorr_verify',
  'smt_verify',
  'mpt_verify',
  'mpt_prefix_verify',
  'bn254_add',
  'bn254_mul',
  'bn254_pairing',
  'ecvrf_verify',
  'groth16_verify',
  'bls_verify',
  'bls_aggregate_verify',
]);

// Check if a string is a known operator
export const isKnownOperator = (tag: string): tag is JsonLogicOpTag =>
  KNOWN_OPERATORS.has(tag as JsonLogicOpTag);

// Operator categories for documentation/grouping
export const OPERATOR_CATEGORIES = {
  controlFlow: ['noop', 'if', 'default', 'let'] as const,
  logical: ['!', '!!', 'or', 'and'] as const,
  comparison: ['==', '===', '!=', '!==', '<', '<=', '>', '>='] as const,
  arithmetic: [
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
  ] as const,
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
  string: [
    'cat',
    'substr',
    'lower',
    'upper',
    'join',
    'split',
    'trim',
    'startsWith',
    'endsWith',
  ] as const,
  object: ['values', 'keys', 'get', 'has', 'entries'] as const,
  utility: ['length', 'exists', 'missing', 'missing_some', 'typeof'] as const,
  zk: [
    'poseidon',
    'pmt_verify',
    'schnorr_verify',
    'smt_verify',
    'mpt_verify',
    'mpt_prefix_verify',
    'bn254_add',
    'bn254_mul',
    'bn254_pairing',
    'ecvrf_verify',
    'groth16_verify',
    'bls_verify',
    'bls_aggregate_verify',
  ] as const,
} as const;
