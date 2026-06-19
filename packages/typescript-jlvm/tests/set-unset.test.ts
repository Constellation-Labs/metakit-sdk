/**
 * `set` / `unset` map opcode unit tests.
 *
 * `set [map, key, value]` returns a NEW map with `key`->`value`: an existing key
 * is replaced in place (last-wins, position-preserving), a new key is appended.
 * `unset [map, key]` returns a NEW map without `key`; an absent key is a no-op
 * (unchanged, NOT an error). Both are immutable (input cloned, never mutated).
 *
 * The canonical conformance vectors here MUST match rust/jlvm-core/src/eval.rs
 * (`op_set` / `op_unset`), the Scala implementation, and
 * shared/json_logic_test_vectors.json byte-for-byte. Maps canonicalize by sorted
 * keys (RFC 8785) for hashing, so `toEqual` (key-order-independent) is the right
 * comparison.
 */

import { jsonLogic } from '../src';

describe('set', () => {
  describe('canonical conformance vectors', () => {
    it('adds a key to an empty map', () => {
      expect(jsonLogic.apply({ set: [{}, 'a', 1] }, {})).toEqual({ a: 1 });
    });

    it('appends a new key', () => {
      expect(jsonLogic.apply({ set: [{ a: 1 }, 'b', 2] }, {})).toEqual({ a: 1, b: 2 });
    });

    it('replaces an existing key (last-wins)', () => {
      expect(jsonLogic.apply({ set: [{ a: 1, b: 2 }, 'a', 9] }, {})).toEqual({ a: 9, b: 2 });
    });

    it('supports computed key and value from data', () => {
      expect(jsonLogic.apply({ set: [{}, { var: 'k' }, { var: 'v' }] }, { k: 'x', v: 5 })).toEqual({
        x: 5,
      });
    });

    it('supports array and object values', () => {
      expect(jsonLogic.apply({ set: [{ a: 1 }, 'b', [1, 2]] }, {})).toEqual({ a: 1, b: [1, 2] });
      expect(jsonLogic.apply({ set: [{ a: 1 }, 'b', { c: 3 }] }, {})).toEqual({
        a: 1,
        b: { c: 3 },
      });
    });

    it('integration: registers an agent as a voter', () => {
      expect(
        jsonLogic.apply(
          { set: [{ var: 'voters' }, { var: 'agent' }, true] },
          { voters: { '0xaaa': true }, agent: '0xbbb' }
        )
      ).toEqual({ '0xaaa': true, '0xbbb': true });
    });
  });

  describe('immutability', () => {
    it('does not mutate the input map (reference safety)', () => {
      // `var` resolves to a live map; `set` must clone it, so a second read of
      // the same var still has only its original key.
      const result = jsonLogic.apply(
        {
          cat: [
            { join: [{ keys: [{ set: [{ var: 'm' }, 'b', 2] }] }, ','] },
            '|',
            { join: [{ keys: [{ var: 'm' }] }, ','] },
          ],
        },
        { m: { a: 1 } }
      );
      expect(result).toBe('a,b|a');
    });
  });

  describe('error vectors', () => {
    it('rejects a non-map first argument', () => {
      expect(() => jsonLogic.apply({ set: [5, 'a', 1] }, {})).toThrow();
    });

    it('rejects a non-string key', () => {
      expect(() => jsonLogic.apply({ set: [{}, 5, 1] }, {})).toThrow();
    });

    it('rejects wrong arity', () => {
      expect(() => jsonLogic.apply({ set: [{}, 'a'] }, {})).toThrow();
      expect(() => jsonLogic.apply({ set: [{}] }, {})).toThrow();
    });
  });
});

describe('unset', () => {
  describe('canonical conformance vectors', () => {
    it('removes a present key', () => {
      expect(jsonLogic.apply({ unset: [{ a: 1, b: 2 }, 'a'] }, {})).toEqual({ b: 2 });
    });

    it('is a no-op for an absent key (NOT an error)', () => {
      expect(jsonLogic.apply({ unset: [{ a: 1 }, 'z'] }, {})).toEqual({ a: 1 });
    });

    it('can empty the map', () => {
      expect(jsonLogic.apply({ unset: [{ a: 1 }, 'a'] }, {})).toEqual({});
    });

    it('supports a computed key from data', () => {
      expect(jsonLogic.apply({ unset: [{ a: 1, b: 2 }, { var: 'k' }] }, { k: 'a' })).toEqual({
        b: 2,
      });
    });
  });

  describe('immutability', () => {
    it('does not mutate the input map (reference safety)', () => {
      const result = jsonLogic.apply(
        {
          cat: [
            { join: [{ keys: [{ unset: [{ var: 'm' }, 'a'] }] }, ','] },
            '|',
            { join: [{ keys: [{ var: 'm' }] }, ','] },
          ],
        },
        { m: { a: 1, b: 2 } }
      );
      // unset result keys -> "b"; original m keys -> "a,b"
      expect(result).toBe('b|a,b');
    });
  });

  describe('error vectors', () => {
    it('rejects a non-map first argument', () => {
      expect(() => jsonLogic.apply({ unset: [5, 'a'] }, {})).toThrow();
    });

    it('rejects a non-string key', () => {
      expect(() => jsonLogic.apply({ unset: [{}, 5] }, {})).toThrow();
    });

    it('rejects wrong arity', () => {
      expect(() => jsonLogic.apply({ unset: [{}] }, {})).toThrow();
    });
  });
});
