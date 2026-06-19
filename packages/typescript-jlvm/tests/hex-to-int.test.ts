/**
 * `hex_to_int` opcode unit tests.
 *
 * Parses a 0x-prefixed lowercase big-endian hex string (via the shared crypto
 * hex codec) and interprets the bytes as an UNSIGNED big-endian integer. The
 * canonical conformance vectors here MUST match rust/jlvm-core/src/hex.rs, the
 * Scala implementation, and shared/json_logic_test_vectors.json byte-for-byte.
 *
 * `applyTyped(...).value` is used so arbitrary-precision results (2^64-1, 2^64,
 * 2^512-1 — all beyond Number.MAX_SAFE_INTEGER) are compared as exact bigints.
 * Expected big values are EXPRESSED (e.g. 2n ** 512n - 1n), not transcribed.
 */

import { jsonLogic } from '../src';

/** Evaluate `{ hex_to_int: [hex] }` and return the exact bigint result. */
const hexToInt = (hex: string): bigint => {
  const v = jsonLogic.applyTyped({ hex_to_int: [hex] }, {});
  if (v.tag !== 'int') {
    throw new Error(`hex_to_int returned a non-int value: ${v.tag}`);
  }
  return v.value;
};

describe('hex_to_int', () => {
  describe('canonical conformance vectors', () => {
    it('decodes the small / boundary vectors', () => {
      expect(hexToInt('0x')).toBe(0n); // empty body -> 0
      expect(hexToInt('0x00')).toBe(0n);
      expect(hexToInt('0xff')).toBe(255n);
      expect(hexToInt('0x0100')).toBe(256n); // big-endian
      expect(hexToInt('0x00ff')).toBe(255n); // leading zero byte ignored
      expect(hexToInt('0xdeadbeef')).toBe(3735928559n);
    });

    it('decodes values beyond i64 / f64 exact range', () => {
      // 2^64 - 1 — proves arbitrary precision past i64::MAX / f64 exactness.
      expect(hexToInt('0xffffffffffffffff')).toBe(2n ** 64n - 1n);
      // 2^64.
      expect(hexToInt('0x010000000000000000')).toBe(2n ** 64n);
      // 64-byte all-ones -> 2^512 - 1.
      expect(hexToInt('0x' + 'f'.repeat(128))).toBe(2n ** 512n - 1n);
    });
  });

  describe('properties', () => {
    it('always returns a non-negative integer (high bit set is not a sign)', () => {
      expect(hexToInt('0x80')).toBe(128n);
      expect(hexToInt('0xffffffffffffffff') >= 0n).toBe(true);
    });
  });

  describe('error vectors', () => {
    it('rejects odd-length hex bodies', () => {
      expect(() => jsonLogic.apply({ hex_to_int: ['0xfff'] }, {})).toThrow();
    });

    it('rejects non-hex characters', () => {
      expect(() => jsonLogic.apply({ hex_to_int: ['0xzz'] }, {})).toThrow();
    });

    it('rejects uppercase / missing-prefix (inherited from the shared codec)', () => {
      expect(() => jsonLogic.apply({ hex_to_int: ['0xAB'] }, {})).toThrow();
      expect(() => jsonLogic.apply({ hex_to_int: ['ab'] }, {})).toThrow();
    });

    it('rejects a non-string argument', () => {
      expect(() => jsonLogic.apply({ hex_to_int: [5] }, {})).toThrow();
    });

    it('rejects wrong arity', () => {
      expect(() => jsonLogic.apply({ hex_to_int: [] }, {})).toThrow();
      expect(() => jsonLogic.apply({ hex_to_int: ['0x00', '0x01'] }, {})).toThrow();
    });
  });
});
