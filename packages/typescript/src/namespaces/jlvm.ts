/**
 * JLVM namespace — JSON Logic Virtual Machine
 *
 * Re-exports everything from the json-logic module under a
 * convenient `jlvm` namespace.
 */

export {
  // High-level API
  jsonLogic,

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

  // Operators
  KNOWN_OPERATORS,
  isKnownOperator,
  OPERATOR_CATEGORIES,

  // Codec
  parseExpression,
  parseValue,
  encodeExpression,
  encodeValue,
  JsonLogicParseError,

  // Errors
  JsonLogicError,
  JsonLogicTypeError,
  JsonLogicArityError,
  JsonLogicDivisionByZeroError,
  JsonLogicUnknownOperatorError,
  JsonLogicVariableNotFoundError,
  JsonLogicOutOfGasError,
  JsonLogicRuntimeError,
  ok,
  err,
  tryCatch,
  andThen,
  map,

  // Evaluator
  evaluate,

  // Gas
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
} from '../json-logic';

export type {
  // Value types
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

  // Expression types
  JsonLogicExpression,
  JsonLogicExpressionTag,
  ApplyExpression,
  ConstExpression,
  ArrayExpression,
  MapExpression,
  VarExpression,

  // Operator types
  JsonLogicOpTag,

  // Error types
  JsonLogicResult,

  // Evaluator types
  EvaluationContext,

  // Gas types
  GasCost,
  GasLimit,
  GasUsed,
  GasConfig,
  EvaluationResult,
} from '../json-logic';
