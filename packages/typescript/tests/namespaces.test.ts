/**
 * Tests for namespaced exports
 */

import { wallet, data, currency, network, jlvm } from '../src';

describe('Namespaced exports', () => {
  describe('wallet namespace', () => {
    it('should export key generation functions', () => {
      expect(typeof wallet.generateKeyPair).toBe('function');
      expect(typeof wallet.keyPairFromPrivateKey).toBe('function');
      expect(typeof wallet.getPublicKeyHex).toBe('function');
      expect(typeof wallet.getPublicKeyId).toBe('function');
      expect(typeof wallet.getAddress).toBe('function');
      expect(typeof wallet.isValidPrivateKey).toBe('function');
      expect(typeof wallet.isValidPublicKey).toBe('function');
    });

    it('should generate a valid key pair', () => {
      const kp = wallet.generateKeyPair();
      expect(kp.address).toMatch(/^DAG/);
      expect(wallet.isValidPrivateKey(kp.privateKey)).toBe(true);
      expect(wallet.isValidPublicKey(kp.publicKey)).toBe(true);
    });
  });

  describe('data namespace', () => {
    it('should export signing and verification functions', () => {
      expect(typeof data.sign).toBe('function');
      expect(typeof data.signDataUpdate).toBe('function');
      expect(typeof data.signHash).toBe('function');
      expect(typeof data.verify).toBe('function');
      expect(typeof data.verifyHash).toBe('function');
      expect(typeof data.verifySignature).toBe('function');
      expect(typeof data.createSignedObject).toBe('function');
      expect(typeof data.addSignature).toBe('function');
      expect(typeof data.batchSign).toBe('function');
    });

    it('should export encoding and hashing functions', () => {
      expect(typeof data.canonicalize).toBe('function');
      expect(typeof data.toBytes).toBe('function');
      expect(typeof data.encodeDataUpdate).toBe('function');
      expect(typeof data.hash).toBe('function');
      expect(typeof data.hashBytes).toBe('function');
      expect(typeof data.hashData).toBe('function');
      expect(typeof data.computeDigest).toBe('function');
      expect(typeof data.decodeDataUpdate).toBe('function');
    });

    it('should export constants', () => {
      expect(data.ALGORITHM).toBe('SECP256K1_RFC8785_V1');
      expect(data.CONSTELLATION_PREFIX).toBeDefined();
    });

    it('should sign and verify via namespace', () => {
      const kp = wallet.generateKeyPair();
      const payload = { action: 'namespace-test', value: 42 };
      const signed = data.createSignedObject(payload, kp.privateKey);

      expect(signed.value).toEqual(payload);
      expect(signed.proofs.length).toBe(1);

      const result = data.verify(signed);
      expect(result.isValid).toBe(true);
    });
  });

  describe('currency namespace', () => {
    it('should export transaction functions with shorter names', () => {
      expect(typeof currency.createTransaction).toBe('function');
      expect(typeof currency.createTransactionBatch).toBe('function');
      expect(typeof currency.signTransaction).toBe('function');
      expect(typeof currency.verifyTransaction).toBe('function');
      expect(typeof currency.encodeTransaction).toBe('function');
      expect(typeof currency.hashTransaction).toBe('function');
      expect(typeof currency.getTransactionReference).toBe('function');
    });

    it('should export utility functions', () => {
      expect(typeof currency.isValidDagAddress).toBe('function');
      expect(typeof currency.tokenToUnits).toBe('function');
      expect(typeof currency.unitsToToken).toBe('function');
      expect(currency.TOKEN_DECIMALS).toBeDefined();
    });

    it('should convert token amounts via namespace', () => {
      expect(currency.tokenToUnits(1)).toBe(1e8);
      expect(currency.unitsToToken(1e8)).toBe(1);
    });
  });

  describe('network namespace', () => {
    it('should export client classes', () => {
      expect(typeof network.MetagraphClient).toBe('function');
      expect(typeof network.createMetagraphClient).toBe('function');
      expect(typeof network.HttpClient).toBe('function');
      expect(typeof network.NetworkError).toBe('function');
    });
  });

  describe('jlvm namespace', () => {
    it('should export the jsonLogic high-level API', () => {
      expect(typeof jlvm.jsonLogic).toBe('object');
      expect(typeof jlvm.jsonLogic.apply).toBe('function');
      expect(typeof jlvm.jsonLogic.applyTyped).toBe('function');
      expect(typeof jlvm.jsonLogic.truthy).toBe('function');
    });

    it('should export value constructors and type guards', () => {
      expect(typeof jlvm.intValue).toBe('function');
      expect(typeof jlvm.strValue).toBe('function');
      expect(typeof jlvm.boolValue).toBe('function');
      expect(typeof jlvm.nullValue).toBe('function');
      expect(typeof jlvm.isInt).toBe('function');
      expect(typeof jlvm.isStr).toBe('function');
      expect(typeof jlvm.isTruthy).toBe('function');
    });

    it('should export expression constructors', () => {
      expect(typeof jlvm.applyExpr).toBe('function');
      expect(typeof jlvm.constExpr).toBe('function');
      expect(typeof jlvm.varExpr).toBe('function');
      expect(typeof jlvm.parseExpression).toBe('function');
      expect(typeof jlvm.encodeValue).toBe('function');
    });

    it('should export evaluator and gas', () => {
      expect(typeof jlvm.evaluate).toBe('function');
      expect(typeof jlvm.gasCost).toBe('function');
      expect(typeof jlvm.consumeGas).toBe('function');
      expect(jlvm.DEFAULT_GAS_CONFIG).toBeDefined();
    });

    it('should export error classes', () => {
      expect(typeof jlvm.JsonLogicError).toBe('function');
      expect(typeof jlvm.JsonLogicTypeError).toBe('function');
      expect(typeof jlvm.JsonLogicParseError).toBe('function');
    });

    it('should evaluate expressions via namespace', () => {
      const result = jlvm.jsonLogic.apply({ '+': [1, 2] }, {});
      expect(result).toBe(3);

      const varResult = jlvm.jsonLogic.apply({ var: 'x' }, { x: 42 });
      expect(varResult).toBe(42);
    });
  });
});
