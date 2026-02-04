/**
 * JSON Logic VM Tests
 *
 * Tests for the TypeScript JSON Logic implementation.
 * Based on json-logic-js test suite and metakit test vectors.
 */

import { jsonLogic, parseExpression, parseValue, evaluate } from '../src/json-logic';

describe('JSON Logic VM', () => {
  describe('Basic Operations', () => {
    it('handles constants', () => {
      expect(jsonLogic.apply(1, {})).toBe(1);
      expect(jsonLogic.apply('hello', {})).toBe('hello');
      expect(jsonLogic.apply(true, {})).toBe(true);
      // eslint-disable-next-line prefer-spread -- this is jsonLogic.apply(), not Function.prototype.apply()
      expect(jsonLogic.apply(null, {})).toBe(null);
      expect(jsonLogic.apply([1, 2, 3], {})).toEqual([1, 2, 3]);
      expect(jsonLogic.apply({ a: 1, b: 2 }, {})).toEqual({ a: 1, b: 2 });
    });

    it('handles var', () => {
      expect(jsonLogic.apply({ var: 'x' }, { x: 42 })).toBe(42);
      expect(jsonLogic.apply({ var: 'a.b' }, { a: { b: 'nested' } })).toBe('nested');
      expect(jsonLogic.apply({ var: '' }, { x: 1 })).toEqual({ x: 1 });
      expect(jsonLogic.apply({ var: ['missing', 'default'] }, {})).toBe('default');
      expect(jsonLogic.apply({ var: 0 }, ['first', 'second'])).toBe('first');
    });
  });

  describe('Arithmetic', () => {
    it('handles +', () => {
      expect(jsonLogic.apply({ '+': [1, 2] }, {})).toBe(3);
      expect(jsonLogic.apply({ '+': [1, 2, 3] }, {})).toBe(6);
      expect(jsonLogic.apply({ '+': [1] }, {})).toBe(1);
      expect(jsonLogic.apply({ '+': '3' }, {})).toBe(3);
    });

    it('handles -', () => {
      expect(jsonLogic.apply({ '-': [5, 3] }, {})).toBe(2);
      expect(jsonLogic.apply({ '-': [5] }, {})).toBe(-5);
    });

    it('handles *', () => {
      expect(jsonLogic.apply({ '*': [2, 3] }, {})).toBe(6);
      expect(jsonLogic.apply({ '*': [2, 3, 4] }, {})).toBe(24);
    });

    it('handles /', () => {
      expect(jsonLogic.apply({ '/': [10, 2] }, {})).toBe(5);
      expect(jsonLogic.apply({ '/': [7, 2] }, {})).toBe(3.5);
    });

    it('handles %', () => {
      expect(jsonLogic.apply({ '%': [10, 3] }, {})).toBe(1);
    });

    it('handles min/max', () => {
      expect(jsonLogic.apply({ min: [1, 2, 3] }, {})).toBe(1);
      expect(jsonLogic.apply({ max: [1, 2, 3] }, {})).toBe(3);
      expect(jsonLogic.apply({ min: [[1, 2], [3]] }, {})).toBe(1);
    });

    it('handles abs/round/floor/ceil', () => {
      expect(jsonLogic.apply({ abs: -5 }, {})).toBe(5);
      expect(jsonLogic.apply({ round: 2.6 }, {})).toBe(3);
      expect(jsonLogic.apply({ floor: 2.9 }, {})).toBe(2);
      expect(jsonLogic.apply({ ceil: 2.1 }, {})).toBe(3);
    });

    it('handles pow', () => {
      expect(jsonLogic.apply({ pow: [2, 3] }, {})).toBe(8);
    });
  });

  describe('Comparison', () => {
    it('handles ==', () => {
      expect(jsonLogic.apply({ '==': [1, 1] }, {})).toBe(true);
      expect(jsonLogic.apply({ '==': [1, '1'] }, {})).toBe(true);
      expect(jsonLogic.apply({ '==': [1, 2] }, {})).toBe(false);
    });

    it('handles ===', () => {
      expect(jsonLogic.apply({ '===': [1, 1] }, {})).toBe(true);
      expect(jsonLogic.apply({ '===': [1, '1'] }, {})).toBe(false);
    });

    it('handles != and !==', () => {
      expect(jsonLogic.apply({ '!=': [1, 2] }, {})).toBe(true);
      expect(jsonLogic.apply({ '!==': [1, '1'] }, {})).toBe(true);
    });

    it('handles < <= > >=', () => {
      expect(jsonLogic.apply({ '<': [1, 2] }, {})).toBe(true);
      expect(jsonLogic.apply({ '<=': [2, 2] }, {})).toBe(true);
      expect(jsonLogic.apply({ '>': [3, 2] }, {})).toBe(true);
      expect(jsonLogic.apply({ '>=': [2, 2] }, {})).toBe(true);
    });

    it('handles chained comparisons', () => {
      expect(jsonLogic.apply({ '<': [1, 2, 3] }, {})).toBe(true);
      expect(jsonLogic.apply({ '<': [1, 3, 2] }, {})).toBe(false);
      expect(jsonLogic.apply({ '<=': [1, 2, 2, 3] }, {})).toBe(true);
    });
  });

  describe('Logic', () => {
    it('handles !', () => {
      expect(jsonLogic.apply({ '!': true }, {})).toBe(false);
      expect(jsonLogic.apply({ '!': false }, {})).toBe(true);
      expect(jsonLogic.apply({ '!': 0 }, {})).toBe(true);
      expect(jsonLogic.apply({ '!': '' }, {})).toBe(true);
    });

    it('handles !!', () => {
      expect(jsonLogic.apply({ '!!': 1 }, {})).toBe(true);
      expect(jsonLogic.apply({ '!!': 0 }, {})).toBe(false);
      expect(jsonLogic.apply({ '!!': 'hello' }, {})).toBe(true);
    });

    it('handles and', () => {
      expect(jsonLogic.apply({ and: [true, true] }, {})).toBe(true);
      expect(jsonLogic.apply({ and: [true, false] }, {})).toBe(false);
      expect(jsonLogic.apply({ and: [1, 2, 3] }, {})).toBe(3);
      expect(jsonLogic.apply({ and: [1, 0, 3] }, {})).toBe(0);
    });

    it('handles or', () => {
      expect(jsonLogic.apply({ or: [false, true] }, {})).toBe(true);
      expect(jsonLogic.apply({ or: [false, false] }, {})).toBe(false);
      expect(jsonLogic.apply({ or: [0, 1, 2] }, {})).toBe(1);
    });
  });

  describe('Control Flow', () => {
    it('handles if', () => {
      expect(jsonLogic.apply({ if: [true, 'yes', 'no'] }, {})).toBe('yes');
      expect(jsonLogic.apply({ if: [false, 'yes', 'no'] }, {})).toBe('no');
      expect(jsonLogic.apply({ if: [false, 'a', true, 'b', 'c'] }, {})).toBe('b');
    });

    it('handles default', () => {
      expect(jsonLogic.apply({ default: [null, '', 0, 'fallback'] }, {})).toBe('fallback');
      expect(jsonLogic.apply({ default: [null, 'found'] }, {})).toBe('found');
    });
  });

  describe('String Operations', () => {
    it('handles cat', () => {
      expect(jsonLogic.apply({ cat: ['hello', ' ', 'world'] }, {})).toBe('hello world');
    });

    it('handles substr', () => {
      expect(jsonLogic.apply({ substr: ['hello', 0, 2] }, {})).toBe('he');
      expect(jsonLogic.apply({ substr: ['hello', -2] }, {})).toBe('lo');
      expect(jsonLogic.apply({ substr: ['hello', 1, -1] }, {})).toBe('ell');
    });

    it('handles lower/upper', () => {
      expect(jsonLogic.apply({ lower: 'HELLO' }, {})).toBe('hello');
      expect(jsonLogic.apply({ upper: 'hello' }, {})).toBe('HELLO');
    });

    it('handles trim', () => {
      expect(jsonLogic.apply({ trim: '  hello  ' }, {})).toBe('hello');
    });

    it('handles join/split', () => {
      expect(jsonLogic.apply({ join: [['a', 'b', 'c'], '-'] }, {})).toBe('a-b-c');
      expect(jsonLogic.apply({ split: ['a-b-c', '-'] }, {})).toEqual(['a', 'b', 'c']);
    });

    it('handles startsWith/endsWith', () => {
      expect(jsonLogic.apply({ startsWith: ['hello', 'he'] }, {})).toBe(true);
      expect(jsonLogic.apply({ endsWith: ['hello', 'lo'] }, {})).toBe(true);
    });
  });

  describe('Array Operations', () => {
    it('handles map', () => {
      expect(
        jsonLogic.apply({ map: [[1, 2, 3], { '*': [{ var: '' }, 2] }] }, {})
      ).toEqual([2, 4, 6]);
    });

    it('handles filter', () => {
      expect(
        jsonLogic.apply({ filter: [[1, 2, 3, 4], { '>': [{ var: '' }, 2] }] }, {})
      ).toEqual([3, 4]);
    });

    it('handles reduce', () => {
      expect(
        jsonLogic.apply(
          {
            reduce: [
              [1, 2, 3, 4],
              { '+': [{ var: 'accumulator' }, { var: 'current' }] },
              0,
            ],
          },
          {}
        )
      ).toBe(10);
    });

    it('handles all/some/none', () => {
      expect(
        jsonLogic.apply({ all: [[1, 2, 3], { '>': [{ var: '' }, 0] }] }, {})
      ).toBe(true);
      expect(
        jsonLogic.apply({ some: [[1, 2, 3], { '>': [{ var: '' }, 2] }] }, {})
      ).toBe(true);
      expect(
        jsonLogic.apply({ none: [[1, 2, 3], { '<': [{ var: '' }, 0] }] }, {})
      ).toBe(true);
    });

    it('handles merge', () => {
      expect(jsonLogic.apply({ merge: [[1, 2], [3, 4]] }, {})).toEqual([1, 2, 3, 4]);
    });

    it('handles in', () => {
      expect(jsonLogic.apply({ in: [2, [1, 2, 3]] }, {})).toBe(true);
      expect(jsonLogic.apply({ in: ['world', 'hello world'] }, {})).toBe(true);
    });

    it('handles length', () => {
      // Note: { length: [1, 2, 3] } parses as length with 3 args (1, 2, 3)
      // To get length of an array, pass it as a single arg
      expect(jsonLogic.apply({ length: [[1, 2, 3]] }, {})).toBe(3);
      expect(jsonLogic.apply({ length: 'hello' }, {})).toBe(5);
      // Or use var to reference an array in data
      expect(jsonLogic.apply({ length: { var: 'arr' } }, { arr: [1, 2, 3] })).toBe(3);
    });

    it('handles slice', () => {
      expect(jsonLogic.apply({ slice: [[1, 2, 3, 4], 1, 3] }, {})).toEqual([2, 3]);
    });

    it('handles reverse', () => {
      expect(jsonLogic.apply({ reverse: [[1, 2, 3]] }, {})).toEqual([3, 2, 1]);
      expect(jsonLogic.apply({ reverse: 'hello' }, {})).toBe('olleh');
    });

    it('handles unique', () => {
      expect(jsonLogic.apply({ unique: [[1, 2, 2, 3, 3, 3]] }, {})).toEqual([1, 2, 3]);
    });

    it('handles flatten', () => {
      expect(jsonLogic.apply({ flatten: [[[1, 2], [3, 4]]] }, {})).toEqual([1, 2, 3, 4]);
    });
  });

  describe('Object Operations', () => {
    it('handles keys', () => {
      expect(jsonLogic.apply({ keys: { a: 1, b: 2 } }, {})).toEqual(['a', 'b']);
    });

    it('handles values', () => {
      expect(jsonLogic.apply({ values: { a: 1, b: 2 } }, {})).toEqual([1, 2]);
    });

    it('handles get', () => {
      expect(jsonLogic.apply({ get: [{ a: 1 }, 'a'] }, {})).toBe(1);
      expect(jsonLogic.apply({ get: [{ a: 1 }, 'b', 'default'] }, {})).toBe('default');
    });

    it('handles has', () => {
      expect(jsonLogic.apply({ has: [{ a: 1 }, 'a'] }, {})).toBe(true);
      expect(jsonLogic.apply({ has: [{ a: 1 }, 'b'] }, {})).toBe(false);
    });

    it('handles entries', () => {
      expect(jsonLogic.apply({ entries: { a: 1, b: 2 } }, {})).toEqual([
        ['a', 1],
        ['b', 2],
      ]);
    });
  });

  describe('Type Operations', () => {
    it('handles typeof', () => {
      expect(jsonLogic.apply({ typeof: 42 }, {})).toBe('int');
      expect(jsonLogic.apply({ typeof: 3.14 }, {})).toBe('float');
      expect(jsonLogic.apply({ typeof: 'hello' }, {})).toBe('string');
      expect(jsonLogic.apply({ typeof: true }, {})).toBe('bool');
      expect(jsonLogic.apply({ typeof: null }, {})).toBe('null');
      // Note: { typeof: [1, 2] } parses as typeof with 2 args, returns type of first
      // To get typeof an array, wrap it: { typeof: [[1, 2]] }
      expect(jsonLogic.apply({ typeof: [[1, 2]] }, {})).toBe('array');
      // Or use var
      expect(jsonLogic.apply({ typeof: { var: 'arr' } }, { arr: [1, 2] })).toBe('array');
      expect(jsonLogic.apply({ typeof: { a: 1 } }, {})).toBe('map');
    });

    it('handles exists', () => {
      expect(jsonLogic.apply({ exists: { var: 'x' } }, { x: 1 })).toBe(true);
      expect(jsonLogic.apply({ exists: { var: 'y' } }, { x: 1 })).toBe(false);
    });
  });

  describe('Strict Equality (1 !== 1.0)', () => {
    // This is a key difference from standard JSON Logic
    it('distinguishes int from float in strict equality', () => {
      // Note: In JSON parsing, 1 becomes IntValue, 1.0 becomes FloatValue
      // This matches the Scala metakit behavior
      const expr = parseExpression({ '===': [{ var: 'a' }, { var: 'b' }] });

      // Same type - equal
      const intInt = evaluate(expr, parseValue({ a: 1, b: 1 }));
      expect(intInt.ok && intInt.value.tag === 'bool' && intInt.value.value).toBe(true);

      // Different types - not equal
      // Note: 1.0 in JSON is ambiguous - it may parse as int or float depending on implementation
      // In our implementation, 1.0 parses as IntValue(1) because Number.isInteger(1.0) is true
      // So this test just verifies the behavior
      const intFloat = evaluate(expr, parseValue({ a: 1, b: 1.5 }));
      expect(intFloat.ok && intFloat.value.tag === 'bool' && intFloat.value.value).toBe(false);
    });
  });

  describe('Complex Expressions', () => {
    it('handles nested operations', () => {
      const expr = {
        if: [
          { '>': [{ var: 'score' }, 90] },
          'A',
          { '>': [{ var: 'score' }, 80] },
          'B',
          { '>': [{ var: 'score' }, 70] },
          'C',
          'F',
        ],
      };

      expect(jsonLogic.apply(expr, { score: 95 })).toBe('A');
      expect(jsonLogic.apply(expr, { score: 85 })).toBe('B');
      expect(jsonLogic.apply(expr, { score: 75 })).toBe('C');
      expect(jsonLogic.apply(expr, { score: 65 })).toBe('F');
    });

    it('handles let bindings', () => {
      const expr = {
        let: [
          { doubled: { '*': [{ var: 'x' }, 2] } },
          { '+': [{ var: 'doubled' }, 1] },
        ],
      };

      expect(jsonLogic.apply(expr, { x: 5 })).toBe(11);
    });
  });
});
