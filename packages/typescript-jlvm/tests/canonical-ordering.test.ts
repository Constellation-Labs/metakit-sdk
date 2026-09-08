import { evaluate, evaluateWithGas, parseExpression, parseValue } from '../src';
import { canonicalizeNoDropNulls } from '../src/canonical-json';

// Metakit #66: expected arrays follow raw UTF-16 keys, never value order.
const keys = ['', '10', '2', 'e', 'e\u0301', '\u00e9', '\ud83d\ude00', '\ue000'];
for (const op of ['keys', 'values', 'entries']) {
  for (const reverse of [false, true]) {
    test(`${op} preserves associations in UTF-16 order; reverse=${reverse}`, () => {
      const entries = keys.map((k, i) => [k, keys.length - i] as const);
      const input = Object.fromEntries(reverse ? [...entries].reverse() : entries);
      const expected = parseValue(
        op === 'keys' ? keys : op === 'values' ? entries.map(([, v]) => v) : entries
      );
      const expr = parseExpression({ [op]: [{ var: '' }] });
      const data = parseValue(input);
      expect(evaluate(expr, data)).toEqual({ ok: true, value: expected });
      const metered = evaluateWithGas(expr, data, 1000000);
      expect(metered.ok).toBe(true);
      if (metered.ok) expect(metered.value.value).toEqual(expected);
    });
  }
  test(`${op} orders maps produced by set`, () => {
    const expr = parseExpression({ [op]: [{ set: [{ set: [{}, 'z', 1] }, 'a', 3] }] });
    const expected = parseValue(
      op === 'keys'
        ? ['a', 'z']
        : op === 'values'
          ? [3, 1]
          : [
              ['a', 3],
              ['z', 1],
            ]
    );
    expect(evaluate(expr, parseValue({}))).toEqual({ ok: true, value: expected });
    const metered = evaluateWithGas(expr, parseValue({}), 1000000);
    expect(metered.ok).toBe(true);
    if (metered.ok) expect(metered.value.value).toEqual(expected);
  });
  test(`${op} preserves distinct malformed keys until the JCS boundary`, () => {
    const expr = parseExpression({ [op]: [{ var: '' }] });
    const expected = parseValue(
      op === 'keys'
        ? ['\ud800', '\ud801']
        : op === 'values'
          ? [1, 2]
          : [
              ['\ud800', 1],
              ['\ud801', 2],
            ]
    );
    for (const input of ['{"\\ud800":1,"\\ud801":2}', '{"\\ud801":2,"\\ud800":1}']) {
      const data = parseValue(JSON.parse(input));
      expect(evaluate(expr, data)).toEqual({ ok: true, value: expected });
      const metered = evaluateWithGas(expr, data, 1000000);
      expect(metered.ok).toBe(true);
      if (metered.ok) expect(metered.value.value).toEqual(expected);
      expect(() => canonicalizeNoDropNulls(JSON.parse(input))).toThrow(/surrogate/i);
    }
  });
}
