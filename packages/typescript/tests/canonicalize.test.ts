import { canonicalize, dropNullFields } from '../src/canonicalize';

describe('canonicalize', () => {
  describe('basic functionality', () => {
    it('should sort object keys alphabetically', () => {
      const result = canonicalize({ b: 2, a: 1 });
      expect(result).toBe('{"a":1,"b":2}');
    });

    it('should handle nested objects', () => {
      const result = canonicalize({ b: { d: 4, c: 3 }, a: 1 });
      expect(result).toBe('{"a":1,"b":{"c":3,"d":4}}');
    });

    it('should handle arrays', () => {
      const result = canonicalize({ arr: [3, 1, 2] });
      // Arrays maintain their order
      expect(result).toBe('{"arr":[3,1,2]}');
    });

    it('should handle strings with special characters', () => {
      const result = canonicalize({ text: 'hello "world"' });
      expect(result).toBe('{"text":"hello \\"world\\""}');
    });

    it('should handle unicode', () => {
      const result = canonicalize({ text: 'caf\u00e9' });
      expect(result).toBe('{"text":"caf\u00e9"}');
    });

    it('should drop null-valued object fields (server-aligned)', () => {
      // RFC 8785 would keep `"a":null`, but the authoritative Scala server
      // (metakit JsonBinaryCodec.dropNulls) drops null object members before
      // canonicalizing. The client must match so signatures verify on chain.
      const result = canonicalize({ a: null, b: 1 });
      expect(result).toBe('{"b":1}');
    });

    it('should handle boolean values', () => {
      const result = canonicalize({ active: true, deleted: false });
      expect(result).toBe('{"active":true,"deleted":false}');
    });

    it('should handle numbers', () => {
      const result = canonicalize({ int: 42, float: 3.14, neg: -1 });
      expect(result).toBe('{"float":3.14,"int":42,"neg":-1}');
    });
  });

  describe('edge cases', () => {
    it('should handle empty object', () => {
      const result = canonicalize({});
      expect(result).toBe('{}');
    });

    it('should handle empty array', () => {
      const result = canonicalize([]);
      expect(result).toBe('[]');
    });

    it('should handle deeply nested structures', () => {
      const result = canonicalize({
        level1: {
          level2: {
            level3: { value: 'deep' },
          },
        },
      });
      expect(result).toBe('{"level1":{"level2":{"level3":{"value":"deep"}}}}');
    });

    it('should be deterministic', () => {
      const data = { id: 'test', value: 42, nested: { a: 1, b: 2 } };
      const result1 = canonicalize(data);
      const result2 = canonicalize(data);
      expect(result1).toBe(result2);
    });
  });

  describe('null-field dropping (server alignment)', () => {
    it('should drop a nested null object field', () => {
      const result = canonicalize({ outer: { inner: null, keep: 2 } });
      expect(result).toBe('{"outer":{"keep":2}}');
    });

    it('should clean null fields inside objects nested in arrays', () => {
      // Arrays are preserved positionally, but object elements are still cleaned.
      const result = canonicalize({ arr: [{ x: null, y: 1 }] });
      expect(result).toBe('{"arr":[{"y":1}]}');
    });

    it('should preserve null elements inside arrays', () => {
      const result = canonicalize({ arr: [1, null, 3] });
      expect(result).toBe('{"arr":[1,null,3]}');
    });

    it('should preserve empty arrays and empty objects', () => {
      const result = canonicalize({ e: [], o: {} });
      expect(result).toBe('{"e":[],"o":{}}');
    });

    it('should drop a state-machine state metadata:null field', () => {
      // Real-world trigger: a state-machine definition whose states carry
      // `metadata: null`. The dropped field must not appear in the canonical.
      const definition = {
        name: 'order',
        states: [
          { id: 'created', metadata: null },
          { id: 'shipped', metadata: { carrier: 'dhl' } },
        ],
      };
      const result = canonicalize(definition);
      // The dropped null `metadata` must be gone; the non-null one is kept.
      expect(result).not.toContain('"metadata":null');
      expect(result).not.toContain('null');
      expect(result).toContain('{"id":"created"}');
      expect(result).toBe(
        '{"name":"order","states":[{"id":"created"},{"id":"shipped","metadata":{"carrier":"dhl"}}]}'
      );
    });
  });
});

describe('RFC 8785 conformance (vendored serializer)', () => {
  it('sorts object keys by UTF-16 code units, not code points', () => {
    // From RFC 8785 section 3.2.3: the surrogate-pair key (U+1F600, UTF-16
    // D83D DE00) sorts BEFORE U+FB33 because comparison is on UTF-16 code
    // units (0xD83D < 0xFB33), even though its code point is higher.
    const result = canonicalize({ '\u{1F600}': 2, 'דּ': 1 });
    expect(result).toBe('{"\u{1F600}":2,"דּ":1}');
  });

  it('orders the RFC 8785 section 3.2.3 sample keys correctly', () => {
    const input: Record<string, unknown> = {};
    // Insertion deliberately scrambled.
    Object.assign(input, {
      '€': 'Euro Sign',
      '\r': 'Carriage Return',
      'דּ': 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '\u{1F600}': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      'ö': 'Latin Small Letter O With Diaeresis',
    });
    const result = canonicalize(input);
    expect(result).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control",' +
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",' +
        '"\u{1F600}":"Emoji: Grinning Face","\uFB33":"Hebrew Letter Dalet With Dagesh"}'
    );
  });

  it('serializes numbers with ECMAScript shortest representation', () => {
    expect(canonicalize([1, 1.5, 0.1, 1e21, 1e-7, 100, 1000000000000000000000.5])).toBe(
      '[1,1.5,0.1,1e+21,1e-7,100,1e+21]'
    );
  });

  it('serializes -0 as 0', () => {
    expect(canonicalize([-0])).toBe('[0]');
    expect(canonicalize([0])).toBe('[0]');
  });

  it('throws on NaN and Infinity', () => {
    expect(() => canonicalize([NaN])).toThrow();
    expect(() => canonicalize([Infinity])).toThrow();
    expect(() => canonicalize([-Infinity])).toThrow();
  });

  it('uses the JCS escaping set for control characters', () => {
    expect(canonicalize(['\u0000\u0001\b\t\n\f\r"\\'])).toBe(
      '["\\u0000\\u0001\\b\\t\\n\\f\\r\\"\\\\"]'
    );
  });

  it('omits undefined object members and nullifies undefined array elements', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(canonicalize([1, undefined, 3])).toBe('[1,null,3]');
  });

  it('handles top-level primitives', () => {
    expect(canonicalize('hello')).toBe('"hello"');
    expect(canonicalize(42)).toBe('42');
    expect(canonicalize(true)).toBe('true');
    expect(canonicalize(null)).toBe('null');
  });
});

describe('dropNullFields', () => {
  it('should drop top-level null object fields and recurse', () => {
    const cleaned = dropNullFields({ a: null, b: 1, c: { d: null, e: 2 } });
    expect(cleaned).toEqual({ b: 1, c: { e: 2 } });
  });

  it('should preserve arrays positionally including null elements', () => {
    const cleaned = dropNullFields({ arr: [1, null, { x: null, y: 2 }] });
    expect(cleaned).toEqual({ arr: [1, null, { y: 2 }] });
  });

  it('should preserve empty containers and pass primitives through', () => {
    expect(dropNullFields({ e: [], o: {} })).toEqual({ e: [], o: {} });
    expect(dropNullFields(null)).toBeNull();
    expect(dropNullFields(5)).toBe(5);
    expect(dropNullFields('s')).toBe('s');
    expect(dropNullFields(true)).toBe(true);
  });
});
