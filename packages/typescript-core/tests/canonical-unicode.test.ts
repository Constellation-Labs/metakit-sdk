import { canonicalize } from '../src/canonicalize';

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
      expect(() => canonicalize(value)).toThrow(/surrogate/i);
    }
  });
}
test('rejects every isolated surrogate as string or retained key', () => {
  for (let unit = 0xd800; unit <= 0xdfff; unit++) {
    const bad = String.fromCharCode(unit);
    expect(() => canonicalize(bad)).toThrow(/surrogate/i);
    expect(() => canonicalize({ [bad]: 1 })).toThrow(/surrogate/i);
  }
});
test('preserves valid pairs, replacement characters, escaping and drop-nulls', () => {
  for (const value of [
    '',
    '\ufffd',
    '\ud800\udc00',
    '\udbff\udfff',
    'x\ud83d\ude00y',
    '\ud83d\ude00\ud800\udc00',
    '\u0000\n"\\',
  ]) {
    expect(canonicalize({ [value]: value })).toBe(
      `{${JSON.stringify(value)}:${JSON.stringify(value)}}`
    );
  }
  // Like the Scala signing codec, null-valued fields are removed before JCS.
  expect(canonicalize({ '\ud800': null, keep: [null, -0] })).toBe('{"keep":[null,0]}');
});
