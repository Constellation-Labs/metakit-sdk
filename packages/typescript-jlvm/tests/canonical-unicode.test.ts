import { canonicalizeNoDropNulls } from '../src/canonical-json';

const malformed = [
  '\ud800',
  '\ud801',
  '\udbff',
  '\udc00',
  '\udfff',
  'x\ud800',
  '\ud800x',
  '\udc00\ud800',
  '\ud800\ud800',
  '\ud800\udc00\udc00',
];
for (const [index, bad] of malformed.entries()) {
  test(`rejects malformed keys, values and nested strings ${index}`, () => {
    for (const value of [
      bad,
      { [bad]: 1 },
      { nested: [{ value: bad }] },
      { nested: [{ [bad]: 1 }] },
    ]) {
      expect(() => canonicalizeNoDropNulls(value)).toThrow(/surrogate/i);
    }
  });
}
test('rejects every isolated surrogate, including null-valued raw keys', () => {
  for (let unit = 0xd800; unit <= 0xdfff; unit++) {
    const bad = String.fromCharCode(unit);
    expect(() => canonicalizeNoDropNulls(bad)).toThrow(/surrogate/i);
    expect(() => canonicalizeNoDropNulls({ [bad]: null })).toThrow(/surrogate/i);
  }
});
test('preserves valid pairs, replacement characters and escaping', () => {
  for (const value of [
    '',
    '\ufffd',
    '\ud800\udc00',
    '\udbff\udfff',
    'x\ud83d\ude00y',
    '\ud83d\ude00\ud800\udc00',
    '\u0000\n"\\',
  ]) {
    expect(canonicalizeNoDropNulls({ [value]: value })).toBe(
      `{${JSON.stringify(value)}:${JSON.stringify(value)}}`
    );
  }
  expect(canonicalizeNoDropNulls({ z: null, a: [null, -0] })).toBe('{"a":[null,0],"z":null}');
});
