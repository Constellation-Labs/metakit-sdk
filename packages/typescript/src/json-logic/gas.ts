/**
 * Gas Metering for JSON Logic VM
 *
 * Tracks execution cost to prevent unbounded computation.
 * Matches the Scala metakit implementation.
 */

import type { JsonLogicOpTag } from './operators';

/**
 * Gas cost for an operation
 */
export interface GasCost {
  readonly amount: number;
}

export const gasCost = (amount: number): GasCost => ({ amount });

export const addCost = (a: GasCost, b: GasCost): GasCost => gasCost(a.amount + b.amount);

export const multiplyCost = (cost: GasCost, multiplier: number): GasCost =>
  gasCost(cost.amount * multiplier);

/**
 * Gas limit for evaluation
 */
export interface GasLimit {
  readonly amount: number;
}

export const gasLimit = (amount: number): GasLimit => ({ amount });

export const UNLIMITED_GAS: GasLimit = gasLimit(Number.MAX_SAFE_INTEGER);
export const DEFAULT_GAS_LIMIT: GasLimit = gasLimit(1_000_000);

export const canAfford = (limit: GasLimit, cost: GasCost): boolean => limit.amount >= cost.amount;

export const consumeGas = (
  limit: GasLimit,
  cost: GasCost
): { ok: true; remaining: GasLimit } | { ok: false; required: GasCost; available: GasLimit } => {
  if (canAfford(limit, cost)) {
    return { ok: true, remaining: gasLimit(limit.amount - cost.amount) };
  }
  return { ok: false, required: cost, available: limit };
};

/**
 * Gas used during evaluation
 */
export interface GasUsed {
  readonly amount: number;
}

export const gasUsed = (amount: number): GasUsed => ({ amount });
export const ZERO_GAS_USED: GasUsed = gasUsed(0);

/**
 * Gas configuration - costs for each operation
 *
 * Matches Scala GasConfig defaults
 */
export interface GasConfig {
  // Control flow
  readonly ifElse: GasCost;
  readonly default: GasCost;
  readonly let: GasCost;

  // Logic
  readonly not: GasCost;
  readonly doubleNot: GasCost;
  readonly or: GasCost;
  readonly and: GasCost;

  // Comparison
  readonly eq: GasCost;
  readonly eqStrict: GasCost;
  readonly neq: GasCost;
  readonly neqStrict: GasCost;
  readonly lt: GasCost;
  readonly leq: GasCost;
  readonly gt: GasCost;
  readonly geq: GasCost;

  // Arithmetic
  readonly add: GasCost;
  readonly minus: GasCost;
  readonly times: GasCost;
  readonly div: GasCost;
  readonly modulo: GasCost;
  readonly max: GasCost;
  readonly min: GasCost;
  readonly abs: GasCost;
  readonly round: GasCost;
  readonly floor: GasCost;
  readonly ceil: GasCost;
  readonly pow: GasCost;

  // Array
  readonly map: GasCost;
  readonly filter: GasCost;
  readonly reduce: GasCost;
  readonly merge: GasCost;
  readonly all: GasCost;
  readonly some: GasCost;
  readonly none: GasCost;
  readonly find: GasCost;
  readonly count: GasCost;
  readonly inOp: GasCost;
  readonly intersect: GasCost;
  readonly unique: GasCost;
  readonly slice: GasCost;
  readonly reverse: GasCost;
  readonly flatten: GasCost;

  // String
  readonly cat: GasCost;
  readonly substr: GasCost;
  readonly lower: GasCost;
  readonly upper: GasCost;
  readonly join: GasCost;
  readonly split: GasCost;
  readonly trim: GasCost;
  readonly startsWith: GasCost;
  readonly endsWith: GasCost;

  // Object
  readonly mapValues: GasCost;
  readonly mapKeys: GasCost;
  readonly get: GasCost;
  readonly has: GasCost;
  readonly entries: GasCost;

  // Utility
  readonly length: GasCost;
  readonly exists: GasCost;
  readonly missing: GasCost;
  readonly missingSome: GasCost;
  readonly typeOf: GasCost;

  // Base costs
  readonly const: GasCost;
  readonly varAccess: GasCost;

  // Multipliers
  readonly depthPenaltyMultiplier: number;
  readonly collectionSizeMultiplier: number;
}

/**
 * Default gas configuration (matches Scala)
 */
export const DEFAULT_GAS_CONFIG: GasConfig = {
  // Control flow
  ifElse: gasCost(10),
  default: gasCost(5),
  let: gasCost(10),

  // Logic
  not: gasCost(1),
  doubleNot: gasCost(1),
  or: gasCost(2),
  and: gasCost(2),

  // Comparison
  eq: gasCost(3),
  eqStrict: gasCost(2),
  neq: gasCost(3),
  neqStrict: gasCost(2),
  lt: gasCost(3),
  leq: gasCost(3),
  gt: gasCost(3),
  geq: gasCost(3),

  // Arithmetic
  add: gasCost(5),
  minus: gasCost(5),
  times: gasCost(8),
  div: gasCost(10),
  modulo: gasCost(10),
  max: gasCost(5),
  min: gasCost(5),
  abs: gasCost(2),
  round: gasCost(3),
  floor: gasCost(3),
  ceil: gasCost(3),
  pow: gasCost(20),

  // Array
  map: gasCost(10),
  filter: gasCost(10),
  reduce: gasCost(15),
  merge: gasCost(5),
  all: gasCost(10),
  some: gasCost(10),
  none: gasCost(10),
  find: gasCost(10),
  count: gasCost(5),
  inOp: gasCost(8),
  intersect: gasCost(15),
  unique: gasCost(20),
  slice: gasCost(5),
  reverse: gasCost(5),
  flatten: gasCost(10),

  // String
  cat: gasCost(5),
  substr: gasCost(8),
  lower: gasCost(3),
  upper: gasCost(3),
  join: gasCost(10),
  split: gasCost(15),
  trim: gasCost(5),
  startsWith: gasCost(5),
  endsWith: gasCost(5),

  // Object
  mapValues: gasCost(5),
  mapKeys: gasCost(5),
  get: gasCost(3),
  has: gasCost(3),
  entries: gasCost(10),

  // Utility
  length: gasCost(1),
  exists: gasCost(5),
  missing: gasCost(10),
  missingSome: gasCost(15),
  typeOf: gasCost(1),

  // Base costs
  const: gasCost(0),
  varAccess: gasCost(2),

  // Multipliers
  depthPenaltyMultiplier: 5,
  collectionSizeMultiplier: 1,
};

/**
 * Development gas config (lower costs for testing)
 */
export const DEV_GAS_CONFIG: GasConfig = {
  ...DEFAULT_GAS_CONFIG,
  map: gasCost(5),
  filter: gasCost(5),
  reduce: gasCost(8),
};

/**
 * Mainnet gas config (higher costs for production)
 */
export const MAINNET_GAS_CONFIG: GasConfig = {
  ...DEFAULT_GAS_CONFIG,
  pow: gasCost(50),
  unique: gasCost(30),
  split: gasCost(25),
  reduce: gasCost(20),
  depthPenaltyMultiplier: 10,
};

/**
 * Get gas cost for an operator
 */
export const getOperatorCost = (op: JsonLogicOpTag, config: GasConfig): GasCost => {
  switch (op) {
    case 'if':
      return config.ifElse;
    case 'default':
      return config.default;
    case 'let':
      return config.let;
    case '!':
      return config.not;
    case '!!':
      return config.doubleNot;
    case 'or':
      return config.or;
    case 'and':
      return config.and;
    case '==':
      return config.eq;
    case '===':
      return config.eqStrict;
    case '!=':
      return config.neq;
    case '!==':
      return config.neqStrict;
    case '<':
      return config.lt;
    case '<=':
      return config.leq;
    case '>':
      return config.gt;
    case '>=':
      return config.geq;
    case '+':
      return config.add;
    case '-':
      return config.minus;
    case '*':
      return config.times;
    case '/':
      return config.div;
    case '%':
      return config.modulo;
    case 'max':
      return config.max;
    case 'min':
      return config.min;
    case 'abs':
      return config.abs;
    case 'round':
      return config.round;
    case 'floor':
      return config.floor;
    case 'ceil':
      return config.ceil;
    case 'pow':
      return config.pow;
    case 'map':
      return config.map;
    case 'filter':
      return config.filter;
    case 'reduce':
      return config.reduce;
    case 'merge':
      return config.merge;
    case 'all':
      return config.all;
    case 'some':
      return config.some;
    case 'none':
      return config.none;
    case 'find':
      return config.find;
    case 'count':
      return config.count;
    case 'in':
      return config.inOp;
    case 'intersect':
      return config.intersect;
    case 'unique':
      return config.unique;
    case 'slice':
      return config.slice;
    case 'reverse':
      return config.reverse;
    case 'flatten':
      return config.flatten;
    case 'cat':
      return config.cat;
    case 'substr':
      return config.substr;
    case 'lower':
      return config.lower;
    case 'upper':
      return config.upper;
    case 'join':
      return config.join;
    case 'split':
      return config.split;
    case 'trim':
      return config.trim;
    case 'startsWith':
      return config.startsWith;
    case 'endsWith':
      return config.endsWith;
    case 'values':
      return config.mapValues;
    case 'keys':
      return config.mapKeys;
    case 'get':
      return config.get;
    case 'has':
      return config.has;
    case 'entries':
      return config.entries;
    case 'length':
      return config.length;
    case 'exists':
      return config.exists;
    case 'missing':
      return config.missing;
    case 'missing_some':
      return config.missingSome;
    case 'typeof':
      return config.typeOf;
    case 'noop':
      return gasCost(0);
  }
};

/**
 * Calculate depth penalty
 */
export const depthPenalty = (depth: number, config: GasConfig): GasCost =>
  gasCost(depth * config.depthPenaltyMultiplier);

/**
 * Calculate collection size cost
 */
export const sizeCost = (size: number, config: GasConfig): GasCost =>
  gasCost(size * config.collectionSizeMultiplier);

/**
 * Result of gas-metered evaluation
 */
export interface EvaluationResult<T> {
  readonly value: T;
  readonly gasUsed: GasUsed;
  readonly maxDepth: number;
  readonly operationCount: number;
}

export const evaluationResult = <T>(
  value: T,
  gasUsed: GasUsed = ZERO_GAS_USED,
  maxDepth: number = 0,
  operationCount: number = 0
): EvaluationResult<T> => ({
  value,
  gasUsed,
  maxDepth,
  operationCount,
});
