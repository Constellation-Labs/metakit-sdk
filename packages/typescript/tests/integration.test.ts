/**
 * Integration tests for the full signing workflow
 */

import {
  generateKeyPair,
  keyPairFromPrivateKey,
  createSignedObject,
  addSignature,
  batchSign,
  verify,
  sign,
  signDataUpdate,
  verifySignature,
  isValidPrivateKey,
  isValidPublicKey,
} from '../src';

describe('Integration tests', () => {
  describe('Key generation', () => {
    it('should generate valid key pair', () => {
      const keyPair = generateKeyPair();

      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.address).toBeDefined();

      expect(isValidPrivateKey(keyPair.privateKey)).toBe(true);
      expect(isValidPublicKey(keyPair.publicKey)).toBe(true);
      expect(keyPair.address).toMatch(/^DAG/);
    });

    it('should derive same key pair from same private key', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = keyPairFromPrivateKey(keyPair1.privateKey);

      expect(keyPair2.publicKey).toBe(keyPair1.publicKey);
      expect(keyPair2.address).toBe(keyPair1.address);
    });
  });

  describe('Signing workflow', () => {
    let keyPair: ReturnType<typeof generateKeyPair>;

    beforeAll(() => {
      keyPair = generateKeyPair();
    });

    describe('Regular signing', () => {
      it('should sign and verify data', () => {
        const data = { action: 'test', value: 42 };
        const proof = sign(data, keyPair.privateKey);

        expect(proof.id).toBeDefined();
        expect(proof.signature).toBeDefined();
        expect(proof.id.length).toBe(128); // Without 04 prefix

        const isValid = verifySignature(data, proof, false);
        expect(isValid).toBe(true);
      });

      it('should create signed object', () => {
        const data = { action: 'test', value: 123 };
        const signed = createSignedObject(data, keyPair.privateKey);

        expect(signed.value).toEqual(data);
        expect(signed.proofs.length).toBe(1);

        const result = verify(signed, false);
        expect(result.isValid).toBe(true);
        expect(result.validProofs.length).toBe(1);
        expect(result.invalidProofs.length).toBe(0);
      });
    });

    describe('DataUpdate signing', () => {
      it('should sign and verify DataUpdate', () => {
        const data = { action: 'update', payload: { key: 'value' } };
        const proof = signDataUpdate(data, keyPair.privateKey);

        expect(proof.id).toBeDefined();
        expect(proof.signature).toBeDefined();

        const isValid = verifySignature(data, proof, true);
        expect(isValid).toBe(true);
      });

      it('should create signed DataUpdate object', () => {
        const data = { action: 'update', value: 999 };
        const signed = createSignedObject(data, keyPair.privateKey, {
          isDataUpdate: true,
        });

        expect(signed.value).toEqual(data);
        expect(signed.proofs.length).toBe(1);

        const result = verify(signed, true);
        expect(result.isValid).toBe(true);
      });
    });

    describe('Multi-signature', () => {
      it('should add signature to existing signed object', () => {
        const keyPair2 = generateKeyPair();
        const data = { action: 'multi-sig', value: 'test' };

        // First signature
        let signed = createSignedObject(data, keyPair.privateKey);
        expect(signed.proofs.length).toBe(1);

        // Add second signature
        signed = addSignature(signed, keyPair2.privateKey);
        expect(signed.proofs.length).toBe(2);

        // Both proofs should be valid
        const result = verify(signed, false);
        expect(result.isValid).toBe(true);
        expect(result.validProofs.length).toBe(2);
      });

      it('should batch sign with multiple keys', () => {
        const keyPair2 = generateKeyPair();
        const keyPair3 = generateKeyPair();
        const data = { action: 'batch', value: 'test' };

        const signed = batchSign(data, [
          keyPair.privateKey,
          keyPair2.privateKey,
          keyPair3.privateKey,
        ]);

        expect(signed.proofs.length).toBe(3);

        const result = verify(signed, false);
        expect(result.isValid).toBe(true);
        expect(result.validProofs.length).toBe(3);
      });
    });

    describe('Tamper detection', () => {
      it('should detect modified data', () => {
        const data = { action: 'test', value: 42 };
        const signed = createSignedObject(data, keyPair.privateKey);

        // Modify the data
        const tampered = {
          ...signed,
          value: { action: 'test', value: 999 },
        };

        const result = verify(tampered, false);
        expect(result.isValid).toBe(false);
        expect(result.invalidProofs.length).toBe(1);
      });

      it('should detect wrong signing mode on legacy object', () => {
        const data = { action: 'test', value: 42 };
        // Sign as regular
        const signed = createSignedObject(data, keyPair.privateKey, {
          isDataUpdate: false,
        });

        // Simulate legacy object without mode field (e.g., deserialized from old wire format)
        const legacy = { value: signed.value, proofs: signed.proofs };

        // Verify as DataUpdate (should fail — no mode field, so isDataUpdate param is used)
        const result = verify(legacy, true);
        expect(result.isValid).toBe(false);
      });
    });
  });

  describe('SigningMode on Signed<T>', () => {
    let keyPair: ReturnType<typeof generateKeyPair>;

    beforeAll(() => {
      keyPair = generateKeyPair();
    });

    it('should set mode to standard by default', () => {
      const signed = createSignedObject({ test: 1 }, keyPair.privateKey);
      expect(signed.mode).toBe('standard');
    });

    it('should set mode to dataUpdate with new API', () => {
      const signed = createSignedObject({ test: 1 }, keyPair.privateKey, {
        mode: 'dataUpdate',
      });
      expect(signed.mode).toBe('dataUpdate');
    });

    it('should set mode to dataUpdate with legacy API', () => {
      const signed = createSignedObject({ test: 1 }, keyPair.privateKey, {
        isDataUpdate: true,
      });
      expect(signed.mode).toBe('dataUpdate');
    });

    it('should auto-verify using mode without explicit isDataUpdate', () => {
      const data = { action: 'auto-mode', value: 42 };

      // Sign as DataUpdate using new mode API
      const signed = createSignedObject(data, keyPair.privateKey, {
        mode: 'dataUpdate',
      });

      // Verify WITHOUT passing isDataUpdate — mode is read from signed object
      const result = verify(signed);
      expect(result.isValid).toBe(true);
    });

    it('should auto-verify standard mode without explicit parameter', () => {
      const data = { action: 'auto-standard', value: 99 };
      const signed = createSignedObject(data, keyPair.privateKey);

      // No second argument — mode defaults from signed.mode
      const result = verify(signed);
      expect(result.isValid).toBe(true);
    });

    it('should detect tampered mode field', () => {
      const data = { action: 'tamper-mode', value: 7 };
      const signed = createSignedObject(data, keyPair.privateKey);

      // Tamper: change mode from 'standard' to 'dataUpdate'
      const tampered = { ...signed, mode: 'dataUpdate' as const };
      const result = verify(tampered);
      expect(result.isValid).toBe(false);
    });

    it('should inherit mode in addSignature', () => {
      const keyPair2 = generateKeyPair();
      const data = { action: 'inherit-mode', value: 1 };

      const signed = createSignedObject(data, keyPair.privateKey, {
        mode: 'dataUpdate',
      });

      // addSignature without options should inherit mode
      const multiSigned = addSignature(signed, keyPair2.privateKey);
      expect(multiSigned.mode).toBe('dataUpdate');

      // Verify should work without explicit isDataUpdate
      const result = verify(multiSigned);
      expect(result.isValid).toBe(true);
      expect(result.validProofs.length).toBe(2);
    });

    it('should set mode on batchSign', () => {
      const keyPair2 = generateKeyPair();
      const data = { action: 'batch-mode', value: 2 };

      const signed = batchSign(data, [keyPair.privateKey, keyPair2.privateKey], {
        mode: 'dataUpdate',
      });
      expect(signed.mode).toBe('dataUpdate');

      const result = verify(signed);
      expect(result.isValid).toBe(true);
      expect(result.validProofs.length).toBe(2);
    });

    it('should handle legacy objects without mode field', () => {
      const data = { action: 'legacy', value: 3 };
      const proof = sign(data, keyPair.privateKey);

      // Simulate a legacy Signed<T> without mode (e.g., deserialized from old wire format)
      const legacySigned = { value: data, proofs: [proof] };

      // Without mode, verify defaults to standard
      const result = verify(legacySigned);
      expect(result.isValid).toBe(true);
    });
  });

  describe('Error handling', () => {
    it('should throw on invalid key for batchSign', () => {
      expect(() => batchSign({ test: 1 }, [])).toThrow('At least one private key');
    });
  });
});
