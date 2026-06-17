/**
 * Consensus-grade conformance tests for the TypeScript JLVM.
 *
 * Pins the behaviors fixed in the 2026-06 cross-implementation review against
 * the Rust reference (rust/jlvm-core): exact bigint/rational numerics,
 * missing/missing_some, callback scoping, 2-arg reduce, prototype-pollution
 * safety, and substr/slice index bounds.
 */

import { jsonLogic, parseValue, parseExpression, evaluate, Ratio } from '../src';

const applyTyped = (logic: unknown, data: unknown = {}) => jsonLogic.applyTyped(logic, data);

describe('Numeric model (bigint integers + exact rationals)', () => {
  it('compares token amounts beyond 2^53 exactly', () => {
    // 10^18 + 1 vs 10^18: f64 cannot distinguish these.
    const big = 10n ** 18n;
    const data = { a: big + 1n, b: big };
    expect(jsonLogic.apply({ '>': [{ var: 'a' }, { var: 'b' }] }, data)).toBe(true);
    expect(jsonLogic.apply({ '==': [{ var: 'a' }, { var: 'b' }] }, data)).toBe(false);
    expect(jsonLogic.apply({ '===': [{ var: 'a' }, { var: 'b' }] }, data)).toBe(false);
    expect(jsonLogic.apply({ '==': [{ var: 'a' }, { var: 'a' }] }, data)).toBe(true);
  });

  it('multiplies into >2^53 territory without losing precision', () => {
    // 3037000499^2 = 9223372030926249001 > 2^53 (and > 2^63 / 2 - ish): exact.
    const result = applyTyped({ '*': [3037000499, 3037000499] });
    expect(result.tag).toBe('int');
    expect(result.tag === 'int' && result.value).toBe(9223372030926249001n);
  });

  it('adds 1 to 10^18 exactly (encodes as bigint beyond safe range)', () => {
    const result = jsonLogic.apply({ '+': [{ var: 'amount' }, 1] }, { amount: 10n ** 18n });
    expect(result).toBe(10n ** 18n + 1n);
  });

  it('compares numeric strings beyond 2^53 exactly (coercion path)', () => {
    expect(
      jsonLogic.apply({ '==': ['1000000000000000000001', '1000000000000000000002'] }, {})
    ).toBe(false);
    expect(
      jsonLogic.apply({ '==': [{ var: 'a' }, '1000000000000000000001'] }, { a: 10n ** 21n + 1n })
    ).toBe(true);
  });

  it('keeps division exact (1/3 * 3 == 1)', () => {
    const third = applyTyped({ '/': [1, 3] });
    expect(third.tag).toBe('float');
    expect(third.tag === 'float' && third.value.equals(Ratio.of(1n, 3n))).toBe(true);
    // (1/3)*3 is integral and no float operand among Int inputs? The division
    // produced a Float, so the result stays Float — but exactly 1.
    const back = applyTyped({ '*': [{ '/': [1, 3] }, 3] });
    expect(back.tag).toBe('float');
    expect(back.tag === 'float' && back.value.equals(Ratio.fromBigInt(1n))).toBe(true);
    expect(jsonLogic.apply({ '==': [{ '*': [{ '/': [1, 3] }, 3] }, 1] }, {})).toBe(true);
  });

  it('types results like Rust: integral int-only ops stay Int, division may yield Float', () => {
    expect(applyTyped({ '/': [10, 2] }).tag).toBe('int'); // integral, no float operand
    expect(applyTyped({ '/': [7, 2] }).tag).toBe('float'); // 3.5
    expect(applyTyped({ '+': [1.5, 2.5] }).tag).toBe('float'); // float operand -> Float(4)
    expect(jsonLogic.apply({ '+': [1.5, 2.5] }, {})).toBe(4);
    expect(applyTyped({ '+': [1, 2] }).tag).toBe('int');
  });

  it('handles 0.1 + 0.2 == 0.3 exactly (no IEEE-754 drift)', () => {
    expect(jsonLogic.apply({ '==': [{ '+': [0.1, 0.2] }, 0.3] }, {})).toBe(true);
    expect(jsonLogic.apply({ '+': [0.1, 0.2] }, {})).toBe(0.3);
  });

  it('pow: bigint base with int exponent is exact; exponent cap enforced', () => {
    expect(jsonLogic.apply({ pow: [10, 30] }, {})).toBe(10n ** 30n);
    expect(() => jsonLogic.apply({ pow: [2, 1000] }, {})).toThrow();
    expect(() => jsonLogic.apply({ pow: [2, 0.5] }, {})).toThrow();
    expect(() => jsonLogic.apply({ pow: [0, -1] }, {})).toThrow();
  });

  it('cat renders floats as plain decimal strings', () => {
    expect(jsonLogic.apply({ cat: ['x=', { '/': [7, 2] }] }, {})).toBe('x=3.5');
    expect(jsonLogic.apply({ cat: ['n=', { '+': [{ var: 'a' }, 0] }] }, { a: 10n ** 20n })).toBe(
      'n=100000000000000000000'
    );
  });
});

describe('missing / missing_some (Rust eval.rs semantics)', () => {
  it('missing returns only the keys absent from data', () => {
    expect(jsonLogic.apply({ missing: ['a', 'b'] }, { a: 1 })).toEqual(['b']);
    expect(jsonLogic.apply({ missing: ['a', 'b'] }, { a: 1, b: 2 })).toEqual([]);
    expect(jsonLogic.apply({ missing: ['a', 'b'] }, {})).toEqual(['a', 'b']);
  });

  it('missing supports a single array argument and dot paths', () => {
    expect(jsonLogic.apply({ missing: [['x.y', 'x.z']] }, { x: { y: 1 } })).toEqual(['x.z']);
  });

  it('missing sees callback context overlays', () => {
    // Inside `let`, bound names are present.
    expect(jsonLogic.apply({ let: [{ bound: 1 }, { missing: ['bound', 'unbound'] }] }, {})).toEqual(
      ['unbound']
    );
  });

  it('missing_some returns [] when the minimum is met', () => {
    expect(jsonLogic.apply({ missing_some: [1, ['a', 'b', 'c']] }, { a: 1 })).toEqual([]);
  });

  it('missing_some returns all missing keys when below the minimum', () => {
    expect(jsonLogic.apply({ missing_some: [2, ['a', 'b', 'c']] }, { a: 1 })).toEqual(['b', 'c']);
  });

  it('missing_some single-array form behaves like min=1', () => {
    expect(jsonLogic.apply({ missing_some: [['a', 'b']] }, { a: 1 })).toEqual([]);
    expect(jsonLogic.apply({ missing_some: [['a', 'b']] }, {})).toEqual(['a', 'b']);
  });
});

describe('Callback scoping (outer data visible inside callbacks)', () => {
  it('map callbacks can reference outer variables', () => {
    expect(
      jsonLogic.apply(
        { map: [{ var: 'items' }, { '*': [{ var: '' }, { var: 'factor' }] }] },
        { items: [1, 2, 3], factor: 10 }
      )
    ).toEqual([10, 20, 30]);
  });

  it('filter callbacks can reference outer variables', () => {
    expect(
      jsonLogic.apply(
        { filter: [{ var: 'items' }, { '>': [{ var: '' }, { var: 'threshold' }] }] },
        { items: [1, 5, 10], threshold: 4 }
      )
    ).toEqual([5, 10]);
  });

  it('element fields shadow outer fields when both are maps', () => {
    expect(
      jsonLogic.apply(
        { map: [{ var: 'items' }, { cat: [{ var: 'name' }, '-', { var: 'suffix' }] }] },
        { items: [{ name: 'a' }, { name: 'b' }], suffix: 's', name: 'outer' }
      )
    ).toEqual(['a-s', 'b-s']);
  });

  it('all/some/none/find/count callbacks see outer scope', () => {
    const data = { items: [1, 2, 3], limit: 2 };
    expect(jsonLogic.apply({ all: [{ var: 'items' }, { '<=': [{ var: '' }, 3] }] }, data)).toBe(
      true
    );
    expect(
      jsonLogic.apply({ some: [{ var: 'items' }, { '>': [{ var: '' }, { var: 'limit' }] }] }, data)
    ).toBe(true);
    expect(jsonLogic.apply({ none: [{ var: 'items' }, { '>': [{ var: '' }, 99] }] }, data)).toBe(
      true
    );
    expect(
      jsonLogic.apply({ find: [{ var: 'items' }, { '>': [{ var: '' }, { var: 'limit' }] }] }, data)
    ).toBe(3);
    expect(
      jsonLogic.apply({ count: [{ var: 'items' }, { '<': [{ var: '' }, { var: 'limit' }] }] }, data)
    ).toBe(1);
  });

  it('reduce callbacks see outer scope alongside current/accumulator', () => {
    expect(
      jsonLogic.apply(
        {
          reduce: [
            { var: 'items' },
            { '+': [{ var: 'accumulator' }, { '*': [{ var: 'current' }, { var: 'factor' }] }] },
            0,
          ],
        },
        { items: [1, 2, 3], factor: 10 }
      )
    ).toBe(60);
  });
});

describe('reduce without initializer (2-arg form)', () => {
  it('reduces from the first element', () => {
    expect(
      jsonLogic.apply(
        { reduce: [{ var: 'items' }, { '+': [{ var: 'accumulator' }, { var: 'current' }] }] },
        { items: [1, 2, 3, 4] }
      )
    ).toBe(10);
  });

  it('returns null for an empty array without initializer', () => {
    expect(
      jsonLogic.apply(
        { reduce: [{ var: 'items' }, { '+': [{ var: 'accumulator' }, { var: 'current' }] }] },
        { items: [] }
      )
    ).toBe(null);
  });

  it('errors when a 3-arg initializer is not a primitive', () => {
    expect(() =>
      jsonLogic.apply(
        { reduce: [[1, 2], { '+': [{ var: 'accumulator' }, { var: 'current' }] }, [0]] },
        {}
      )
    ).toThrow();
  });
});

describe('Prototype pollution resistance', () => {
  it('does not pollute Object.prototype via __proto__ data keys', () => {
    const evil = JSON.parse('{"__proto__": {"polluted": true}, "x": 1}');
    expect(jsonLogic.apply({ var: 'x' }, evil)).toBe(1);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('treats __proto__ and constructor as ordinary map keys', () => {
    const data = JSON.parse('{"__proto__": 7, "constructor": 8}');
    expect(jsonLogic.apply({ var: '__proto__' }, data)).toBe(7);
    expect(jsonLogic.apply({ var: 'constructor' }, data)).toBe(8);
    expect(jsonLogic.apply({ has: [{ var: '' }, '__proto__'] }, data)).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('does not fabricate inherited properties (toString/hasOwnProperty)', () => {
    expect(jsonLogic.apply({ var: 'toString' }, { x: 1 })).toBe(null);
    expect(jsonLogic.apply({ has: [{ var: '' }, 'hasOwnProperty'] }, { x: 1 })).toBe(false);
    expect(jsonLogic.apply({ get: [{ var: '' }, 'toString', 'absent'] }, { x: 1 })).toBe('absent');
    expect(jsonLogic.apply({ missing: ['toString'] }, { x: 1 })).toEqual(['toString']);
  });

  it('encoding a map with __proto__ key yields a safe plain object', () => {
    const result = jsonLogic.apply(
      { merge: [{ var: 'a' }, { var: 'b' }] },
      JSON.parse('{"a": {"__proto__": {"polluted": true}}, "b": {"y": 2}}')
    ) as Record<string, unknown>;
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(result.y).toBe(2);
  });

  it('object-form let with __proto__ binding is inert', () => {
    const expr = JSON.parse('{"let": [{"__proto__": 5}, {"var": "__proto__"}]}');
    expect(jsonLogic.apply(expr, {})).toBe(5);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('Object-form let key ordering (UTF-16 code units)', () => {
  it('orders supplementary-plane keys by UTF-16 code units, not code points', () => {
    // U+1F4A9 (surrogates D83D DCA9) sorts BEFORE U+FB03 in UTF-16 code-unit
    // order even though its code point is larger. So the binding for "\u{1F4A9}"
    // (=1) is evaluated first and "ﬃ" (= \u{1F4A9} + 1 = 2) second.
    const expr = JSON.parse('{"let": [{"ﬃ": {"+": [{"var": "💩"}, 1]}, "💩": 1}, {"var": "ﬃ"}]}');
    expect(jsonLogic.apply(expr, {})).toBe(2);
  });

  it('array-form let keeps insertion order', () => {
    const expr = JSON.parse('{"let": [[["a", 1], ["b", {"+": [{"var": "a"}, 1]}]], {"var": "b"}]}');
    expect(jsonLogic.apply(expr, {})).toBe(2);
  });
});

describe('substr / slice index bounds (match Rust op_substr/op_slice)', () => {
  it('clamps in-range indices', () => {
    expect(jsonLogic.apply({ substr: ['hello', 1, 100] }, {})).toBe('ello');
    expect(jsonLogic.apply({ substr: ['hello', -100] }, {})).toBe('hello');
    expect(jsonLogic.apply({ substr: ['hello', 10] }, {})).toBe('');
    expect(jsonLogic.apply({ slice: [[1, 2, 3], 1, 100] }, {})).toEqual([2, 3]);
    expect(jsonLogic.apply({ slice: [[1, 2, 3], -100] }, {})).toEqual([1, 2, 3]);
  });

  it('errors when an index exceeds the i64 range', () => {
    const big = (2n ** 63n).toString(); // i64::MAX + 1
    expect(() =>
      jsonLogic.apply(JSON.parse(`{"substr": ["hello", {"var": "i"}]}`), { i: BigInt(big) })
    ).toThrow();
    expect(() =>
      jsonLogic.apply(JSON.parse(`{"slice": [[1,2,3], {"var": "i"}]}`), { i: BigInt(big) })
    ).toThrow();
  });

  it('errors on non-integer (float) indices', () => {
    expect(() => jsonLogic.apply({ substr: ['hello', 1.5] }, {})).toThrow();
  });

  it('indexes by UTF-16 code units', () => {
    expect(jsonLogic.apply({ substr: ['a\u{1F600}b', 1, 2] }, {})).toBe('\u{1F600}');
    expect(jsonLogic.apply({ length: 'a\u{1F600}b' }, {})).toBe(4);
  });
});

describe('Typed API exactness', () => {
  it('round-trips >2^53 integers through parseValue/evaluate', () => {
    const expr = parseExpression({ '+': [{ var: 'a' }, { var: 'b' }] });
    const data = parseValue({ a: 2n ** 80n, b: 1n });
    const result = evaluate(expr, data);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.tag).toBe('int');
      expect(result.value.tag === 'int' && result.value.value).toBe(2n ** 80n + 1n);
    }
  });

  it('treats integral JSON floats as integers (1e21 is an Int like Rust serde path)', () => {
    const v = parseValue(1e21);
    expect(v.tag).toBe('int');
    expect(v.tag === 'int' && v.value).toBe(10n ** 21n);
  });
});
