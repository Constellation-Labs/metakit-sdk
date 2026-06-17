/**
 * Wave-2 cross-language parity pins, matching the Rust reference
 * (rust/jlvm-core) and the Scala `ParityWave2Suite`:
 *
 *   1. SCALE BOUND — string -> number coercion rejects any decimal whose
 *      effective scale magnitude exceeds `Ratio.MAX_DECIMAL_SCALE` = 10_000
 *      (Rust `Ratio::MAX_DECIMAL_SCALE`); coerced `==` treats an out-of-bound
 *      string as unparseable (false, not an error).
 *   2. SUBSTR / SLICE i64 EXTREMES — full-i64 saturating index semantics;
 *      beyond-i64 indices error.
 *   3. DEPTH CAP — MAX_EVAL_DEPTH = 256, one unit per evaluated node
 *      (operator args, if/let children, callback runs), in both the plain and
 *      the gas-metered evaluators.
 *   4. SCHEDULE DRIFT — the legacy `DEFAULT_GAS_CONFIG` (gas.ts) must agree
 *      field-for-field with the metered evaluator's `DEFAULT_GAS_SCHEDULE`.
 */

import { jsonLogic, Ratio, MAX_EVAL_DEPTH } from '../src';
import { parseExpression, parseValue } from '../src/codec';
import {
  DEFAULT_GAS_SCHEDULE,
  evaluateWithGas,
  GasExhaustedError,
  javaSplitDotSegments,
} from '../src/gas-eval';
import { DEFAULT_GAS_CONFIG } from '../src/gas';

describe('decimal scale bound (Ratio.MAX_DECIMAL_SCALE)', () => {
  it('accepts |scale| == 10000 (both bound edges)', () => {
    expect(Ratio.parseDecimal('1e-10000')).not.toBeNull();
    expect(Ratio.parseDecimal('1e10000')).not.toBeNull();
    expect(jsonLogic.apply({ '+': ['1e10000'] }, {})).toBeDefined();
  });

  it('rejects |scale| == 10001 (one past the bound)', () => {
    expect(Ratio.parseDecimal('1e-10001')).toBeNull();
    expect(Ratio.parseDecimal('1e10001')).toBeNull();
    expect(() => jsonLogic.apply({ '+': ['1e-10001'] }, {})).toThrow();
    expect(() => jsonLogic.apply({ '+': ['1e10001'] }, {})).toThrow();
  });

  it('rejects the 1e-2000000000 memory bomb (fast, no 10^|scale| allocation)', () => {
    const start = Date.now();
    expect(Ratio.parseDecimal('1e-2000000000')).toBeNull();
    expect(() => jsonLogic.apply({ '+': ['1e-2000000000'] }, {})).toThrow();
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('bounds the EFFECTIVE scale (fractional digits minus exponent)', () => {
    // 1 frac digit + e-9999 -> scale 10000: accepted.
    expect(Ratio.parseDecimal('0.1e-9999')).not.toBeNull();
    // 1 frac digit + e-10000 -> scale 10001: rejected.
    expect(Ratio.parseDecimal('0.1e-10000')).toBeNull();
  });

  it('coerced == treats an out-of-bound decimal string as unparseable: false, not an error', () => {
    expect(jsonLogic.apply({ '==': [1.5, '1e-2000000000'] }, {})).toBe(false);
  });
});

describe('substr/slice at i64 extremes (Rust saturating semantics)', () => {
  // i64 extremes are NOT exactly representable as JS numbers, so the exprs are
  // built with bigint literals (the codec accepts bigint for beyond-2^53 ints).
  const I64_MAX = 9223372036854775807n;
  const I64_MIN = -9223372036854775808n;

  it('substr saturates at i64 extremes exactly like Rust op_substr', () => {
    expect(jsonLogic.apply({ substr: ['hello', I64_MIN] }, {})).toBe('hello');
    expect(jsonLogic.apply({ substr: ['hello', 1, I64_MAX] }, {})).toBe('ello');
    expect(jsonLogic.apply({ substr: ['hello', I64_MAX] }, {})).toBe('');
    expect(jsonLogic.apply({ substr: ['hello', 0, I64_MIN] }, {})).toBe('');
  });

  it('slice saturates at i64 extremes exactly like Rust op_slice', () => {
    expect(jsonLogic.apply({ slice: [[1, 2, 3], I64_MIN] }, {})).toEqual([1, 2, 3]);
    expect(jsonLogic.apply({ slice: [[1, 2, 3], 0, I64_MAX] }, {})).toEqual([1, 2, 3]);
    expect(jsonLogic.apply({ slice: [[1, 2, 3], I64_MAX] }, {})).toEqual([]);
  });

  it('indices beyond the i64 range are an error (Rust bigint_to_i64 parity)', () => {
    expect(() => jsonLogic.apply({ substr: ['hello', I64_MAX + 1n] }, {})).toThrow(
      'substr start out of range'
    );
    expect(() => jsonLogic.apply({ slice: [[1, 2, 3], I64_MIN - 1n] }, {})).toThrow(
      'slice start out of range'
    );
  });
});

describe(`depth cap (MAX_EVAL_DEPTH = ${MAX_EVAL_DEPTH})`, () => {
  /** A chain of n nested {"!": [...]} over true: max node depth is n + 1. */
  const nestedNot = (n: number): unknown => {
    let acc: unknown = true;
    for (let i = 0; i < n; i++) {
      acc = { '!': [acc] };
    }
    return acc;
  };

  it('255 nested operators evaluate (max node depth 256 == MAX_EVAL_DEPTH)', () => {
    expect(jsonLogic.apply(nestedNot(MAX_EVAL_DEPTH - 1), {})).toBe(false);
  });

  it('256 nested operators exceed the cap (node depth 257)', () => {
    expect(() => jsonLogic.apply(nestedNot(MAX_EVAL_DEPTH), {})).toThrow(
      `Recursion depth limit exceeded (${MAX_EVAL_DEPTH})`
    );
  });

  it('callback runs count toward the cap (map body resumes from the map node depth)', () => {
    // map node at depth 1, callback body root at depth 2: a body of k nested
    // `!` over {"var":""} has ops at depths 2..k+1 and the var at k+2.
    // k = 254 -> max 256 (ok); k = 255 -> 257 (error). Matches Rust/Scala.
    const mapWithBody = (k: number): unknown => {
      let body: unknown = { var: '' };
      for (let i = 0; i < k; i++) {
        body = { '!': [body] };
      }
      return { map: [[1], body] };
    };
    expect(jsonLogic.apply(mapWithBody(254), {})).toBeDefined();
    expect(() => jsonLogic.apply(mapWithBody(255), {})).toThrow('Recursion depth limit exceeded');
  });

  it('untaken if branches never count toward the cap (lazy)', () => {
    expect(jsonLogic.apply({ if: [true, 1, nestedNot(400)] }, {})).toBe(1);
  });

  it('the gas-metered evaluator enforces the same cap with a non-gas error', () => {
    const expr = parseExpression(nestedNot(MAX_EVAL_DEPTH));
    const outcome = evaluateWithGas(expr, parseValue({}), 10_000_000n);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error).not.toBeInstanceOf(GasExhaustedError);
      expect(outcome.error.message).toBe(`Recursion depth limit exceeded (${MAX_EVAL_DEPTH})`);
    }
  });
});

describe('gas schedule drift guard', () => {
  it('legacy DEFAULT_GAS_CONFIG agrees with the metered DEFAULT_GAS_SCHEDULE', () => {
    const legacy = DEFAULT_GAS_CONFIG as unknown as Record<
      string,
      { amount: number } | number | undefined
    >;
    // Field names shared between the two (the legacy config calls `inOp`/`in`
    // and `const` differently in a few places; map them explicitly).
    const fieldMap: Record<string, string> = {
      typeOf: 'typeOf',
      missingSome: 'missingSome',
      inOp: 'inOp',
      constCost: 'const',
      default: 'default',
    };
    for (const [name, value] of Object.entries(DEFAULT_GAS_SCHEDULE)) {
      const legacyName = fieldMap[name] ?? name;
      const legacyValue = legacy[legacyName];
      if (legacyValue === undefined) {
        throw new Error(`legacy DEFAULT_GAS_CONFIG is missing field ${legacyName}`);
      }
      const amount =
        typeof legacyValue === 'number' ? legacyValue : (legacyValue as { amount: number }).amount;
      expect(`${name}=${BigInt(amount)}`).toBe(`${name}=${value}`);
    }
  });

  it('java-split path segment counting matches the Scala meter', () => {
    expect(javaSplitDotSegments('')).toBe(1n);
    expect(javaSplitDotSegments('a')).toBe(1n);
    expect(javaSplitDotSegments('a.b')).toBe(2n);
    expect(javaSplitDotSegments('a.b.c')).toBe(3n);
    expect(javaSplitDotSegments('a.')).toBe(1n);
    expect(javaSplitDotSegments('.')).toBe(0n);
    expect(javaSplitDotSegments('.a')).toBe(2n);
    expect(javaSplitDotSegments('a..b')).toBe(3n);
  });
});
