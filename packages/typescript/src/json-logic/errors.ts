/**
 * JSON Logic Errors
 *
 * Exception types for the JSON Logic VM.
 * Matches the Scala metakit exceptions.
 */

// Base error class
export class JsonLogicError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JsonLogicError';
  }
}

// Type errors (wrong argument types)
export class JsonLogicTypeError extends JsonLogicError {
  constructor(
    public readonly operator: string,
    public readonly expected: string,
    public readonly actual: string,
    public readonly argIndex?: number
  ) {
    const msg =
      argIndex !== undefined
        ? `${operator}: argument ${argIndex} expected ${expected}, got ${actual}`
        : `${operator}: expected ${expected}, got ${actual}`;
    super(msg);
    this.name = 'JsonLogicTypeError';
  }
}

// Arity errors (wrong number of arguments)
export class JsonLogicArityError extends JsonLogicError {
  constructor(
    public readonly operator: string,
    public readonly expected: number | string,
    public readonly actual: number
  ) {
    super(`${operator}: expected ${expected} arguments, got ${actual}`);
    this.name = 'JsonLogicArityError';
  }
}

// Division by zero
export class JsonLogicDivisionByZeroError extends JsonLogicError {
  constructor() {
    super('Division by zero');
    this.name = 'JsonLogicDivisionByZeroError';
  }
}

// Unknown operator
export class JsonLogicUnknownOperatorError extends JsonLogicError {
  constructor(public readonly operator: string) {
    super(`Unknown operator: ${operator}`);
    this.name = 'JsonLogicUnknownOperatorError';
  }
}

// Variable not found
export class JsonLogicVariableNotFoundError extends JsonLogicError {
  constructor(public readonly path: string) {
    super(`Variable not found: ${path}`);
    this.name = 'JsonLogicVariableNotFoundError';
  }
}

// Out of gas
export class JsonLogicOutOfGasError extends JsonLogicError {
  constructor(
    public readonly used: number,
    public readonly limit: number
  ) {
    super(`Gas limit exceeded: used ${used}, limit ${limit}`);
    this.name = 'JsonLogicOutOfGasError';
  }
}

// Generic runtime error
export class JsonLogicRuntimeError extends JsonLogicError {
  constructor(
    message: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'JsonLogicRuntimeError';
  }
}

// Result type for evaluation
export type JsonLogicResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: JsonLogicError };

export const ok = <T>(value: T): JsonLogicResult<T> => ({ ok: true, value });
export const err = <T>(error: JsonLogicError): JsonLogicResult<T> => ({ ok: false, error });

// Helper to wrap a throwing function
export const tryCatch = <T>(fn: () => T): JsonLogicResult<T> => {
  try {
    return ok(fn());
  } catch (e) {
    if (e instanceof JsonLogicError) {
      return err(e);
    }
    return err(new JsonLogicRuntimeError(String(e), e instanceof Error ? e : undefined));
  }
};

// Helper to chain results
export const andThen = <T, U>(
  result: JsonLogicResult<T>,
  fn: (value: T) => JsonLogicResult<U>
): JsonLogicResult<U> => {
  if (!result.ok) {
    return result;
  }
  return fn(result.value);
};

// Helper to map results
export const map = <T, U>(result: JsonLogicResult<T>, fn: (value: T) => U): JsonLogicResult<U> => {
  if (!result.ok) {
    return result;
  }
  return ok(fn(result.value));
};
