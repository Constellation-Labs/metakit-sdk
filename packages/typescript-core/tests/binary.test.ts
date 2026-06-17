import { toBytes, encodeDataUpdate } from '../src/binary';

describe('binary encoding', () => {
  describe('toBytes()', () => {
    it('should encode simple object to UTF-8 bytes', () => {
      const data = { a: 1 };
      const bytes = toBytes(data);
      const decoded = new TextDecoder().decode(bytes);
      expect(decoded).toBe('{"a":1}');
    });

    it('should canonicalize before encoding', () => {
      const data = { b: 2, a: 1 };
      const bytes = toBytes(data);
      const decoded = new TextDecoder().decode(bytes);
      expect(decoded).toBe('{"a":1,"b":2}');
    });

    it('should be deterministic', () => {
      const data = { id: 'test', value: 42 };
      const bytes1 = toBytes(data);
      const bytes2 = toBytes(data);
      expect(Buffer.from(bytes1).toString('hex')).toBe(Buffer.from(bytes2).toString('hex'));
    });

    describe('regular encoding (isDataUpdate=false)', () => {
      it('should return plain UTF-8 bytes', () => {
        const data = { test: 'value' };
        const bytes = toBytes(data, false);
        const decoded = new TextDecoder().decode(bytes);
        expect(decoded).toBe('{"test":"value"}');
      });
    });

    describe('DataUpdate encoding (isDataUpdate=true)', () => {
      it('should include Constellation prefix', () => {
        const data = { test: 'value' };
        const bytes = toBytes(data, true);
        const decoded = new TextDecoder().decode(bytes);
        expect(decoded.startsWith('\x19Constellation Signed Data:\n')).toBe(true);
      });

      it('should base64 encode the canonical JSON', () => {
        const data = { id: 'test' };
        const bytes = toBytes(data, true);
        const decoded = new TextDecoder().decode(bytes);

        // Extract base64 from format: \x19Constellation Signed Data:\n{length}\n{base64}
        const parts = decoded.split('\n');
        expect(parts.length).toBe(3);

        const base64Part = parts[2];
        const decodedBase64 = Buffer.from(base64Part, 'base64').toString('utf-8');
        expect(decodedBase64).toBe('{"id":"test"}');
      });

      it('should include correct length', () => {
        const data = { id: 'test' };
        const bytes = toBytes(data, true);
        const decoded = new TextDecoder().decode(bytes);

        const parts = decoded.split('\n');
        const length = parseInt(parts[1], 10);
        const base64Part = parts[2];
        expect(length).toBe(base64Part.length);
      });
    });
  });

  describe('encodeDataUpdate()', () => {
    it('should be equivalent to toBytes with isDataUpdate=true', () => {
      const data = { action: 'update', value: 123 };
      const bytes1 = toBytes(data, true);
      const bytes2 = encodeDataUpdate(data);
      expect(Buffer.from(bytes1).toString('hex')).toBe(Buffer.from(bytes2).toString('hex'));
    });
  });

  describe('null-field dropping in signing bytes (server alignment)', () => {
    // The bytes produced here are exactly what gets hashed and signed. They
    // must never contain a null object-field, or the on-chain (server) verify
    // re-derives a different canonical and rejects the signature (HTTP 400).
    const definition = {
      name: 'order',
      states: [
        { id: 'created', metadata: null },
        { id: 'shipped', metadata: { carrier: 'dhl' } },
      ],
      config: null,
      tags: [],
    };

    it('regular signing bytes omit null object-fields but keep empty containers', () => {
      const decoded = new TextDecoder().decode(toBytes(definition, false));
      expect(decoded).not.toContain('null');
      expect(decoded).not.toContain('metadata":null');
      expect(decoded).not.toContain('"config"');
      // Empty array preserved, and null array element (added below) preserved.
      expect(decoded).toContain('"tags":[]');
      expect(decoded).toBe(
        '{"name":"order","states":[{"id":"created"},{"id":"shipped","metadata":{"carrier":"dhl"}}],"tags":[]}'
      );
    });

    it('DataUpdate signing bytes (base64 payload) omit null object-fields', () => {
      const bytes = toBytes(definition, true);
      const decoded = new TextDecoder().decode(bytes);
      const base64Part = decoded.split('\n')[2];
      const payload = Buffer.from(base64Part, 'base64').toString('utf-8');
      expect(payload).not.toContain('null');
      expect(payload).not.toContain('"config"');
      expect(payload).toBe(
        '{"name":"order","states":[{"id":"created"},{"id":"shipped","metadata":{"carrier":"dhl"}}],"tags":[]}'
      );
    });

    it('preserves null elements inside arrays in the signing bytes', () => {
      const decoded = new TextDecoder().decode(toBytes({ arr: [1, null, 3] }, false));
      expect(decoded).toBe('{"arr":[1,null,3]}');
    });
  });
});
