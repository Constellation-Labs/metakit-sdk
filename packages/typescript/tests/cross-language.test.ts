import * as fs from 'fs';
import * as path from 'path';
import { canonicalize } from '../src/canonicalize';
import { toBytes } from '../src/binary';
import { hashBytes } from '../src/hash';
import { verifyHash } from '../src/verify';

interface TestVector {
  source: string;
  type: 'TestData' | 'TestDataUpdate';
  data: Record<string, unknown>;
  canonical_json: string;
  utf8_bytes_hex: string;
  sha256_hash_hex: string;
  signature_hex: string;
  public_key_hex: string;
}

describe('Cross-language compatibility', () => {
  let testVectors: TestVector[];

  beforeAll(() => {
    const vectorsPath = path.join(__dirname, '../../..', 'shared/test_vectors.json');
    const content = fs.readFileSync(vectorsPath, 'utf-8');
    testVectors = JSON.parse(content);
  });

  describe('Canonicalization', () => {
    it('should match canonical JSON from all test vectors', () => {
      for (const vector of testVectors) {
        const canonical = canonicalize(vector.data);
        expect(canonical).toBe(vector.canonical_json);
      }
    });
  });

  describe('Binary encoding', () => {
    it('should match UTF-8 bytes from all test vectors', () => {
      for (const vector of testVectors) {
        const isDataUpdate = vector.type === 'TestDataUpdate';
        const bytes = toBytes(vector.data, isDataUpdate);
        const bytesHex = Buffer.from(bytes).toString('hex');
        expect(bytesHex).toBe(vector.utf8_bytes_hex);
      }
    });
  });

  describe('Hashing', () => {
    it('should match SHA-256 hashes from all test vectors', () => {
      for (const vector of testVectors) {
        const isDataUpdate = vector.type === 'TestDataUpdate';
        const bytes = toBytes(vector.data, isDataUpdate);
        const hashResult = hashBytes(bytes);
        expect(hashResult.value).toBe(vector.sha256_hash_hex);
      }
    });
  });

  describe('Signature verification', () => {
    it('should verify signatures from all test vectors', async () => {
      for (const vector of testVectors) {
        const isValid = await verifyHash(
          vector.sha256_hash_hex,
          vector.signature_hex,
          vector.public_key_hex
        );
        expect(isValid).toBe(true);
      }
    });

    it('should reject tampered signatures', async () => {
      const vector = testVectors[0];
      // Modify the hash slightly
      const tamperedHash = vector.sha256_hash_hex.replace(/0/g, '1');
      const isValid = await verifyHash(tamperedHash, vector.signature_hex, vector.public_key_hex);
      expect(isValid).toBe(false);
    });
  });

  describe('By source language', () => {
    const languages = ['python', 'javascript', 'rust', 'go'];

    for (const language of languages) {
      describe(`${language} vectors`, () => {
        it(`should verify ${language} regular data signatures`, async () => {
          const vectors = testVectors.filter(
            (v) => v.source === language && v.type === 'TestData'
          );
          expect(vectors.length).toBeGreaterThan(0);

          for (const vector of vectors) {
            const bytes = toBytes(vector.data, false);
            const hashResult = hashBytes(bytes);
            expect(hashResult.value).toBe(vector.sha256_hash_hex);

            const isValid = await verifyHash(
              vector.sha256_hash_hex,
              vector.signature_hex,
              vector.public_key_hex
            );
            expect(isValid).toBe(true);
          }
        });

        it(`should verify ${language} DataUpdate signatures`, async () => {
          const vectors = testVectors.filter(
            (v) => v.source === language && v.type === 'TestDataUpdate'
          );
          expect(vectors.length).toBeGreaterThan(0);

          for (const vector of vectors) {
            const bytes = toBytes(vector.data, true);
            const hashResult = hashBytes(bytes);
            expect(hashResult.value).toBe(vector.sha256_hash_hex);

            const isValid = await verifyHash(
              vector.sha256_hash_hex,
              vector.signature_hex,
              vector.public_key_hex
            );
            expect(isValid).toBe(true);
          }
        });
      });
    }
  });
});
