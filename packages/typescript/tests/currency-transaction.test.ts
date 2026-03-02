/**
 * Currency transaction tests
 */

import {
  generateKeyPair,
  createCurrencyTransaction,
  createCurrencyTransactionBatch,
  signCurrencyTransaction,
  verifyCurrencyTransaction,
  hashCurrencyTransaction,
  getTransactionReference,
  isValidDagAddress,
  tokenToUnits,
  unitsToToken,
  TOKEN_DECIMALS,
  type TransactionReference,
} from '../src';

describe('Currency Transactions', () => {
  describe('Utility Functions', () => {
    test('tokenToUnits converts correctly', () => {
      expect(tokenToUnits(100.5)).toBe(10050000000);
      expect(tokenToUnits(0.00000001)).toBe(1);
      expect(tokenToUnits(1)).toBe(100000000);
    });

    test('unitsToToken converts correctly', () => {
      expect(unitsToToken(10050000000)).toBe(100.5);
      expect(unitsToToken(1)).toBe(0.00000001);
      expect(unitsToToken(100000000)).toBe(1);
    });

    test('TOKEN_DECIMALS constant', () => {
      expect(TOKEN_DECIMALS).toBe(1e-8);
    });

    test('isValidDagAddress validates addresses', () => {
      const keyPair = generateKeyPair();
      expect(isValidDagAddress(keyPair.address)).toBe(true);
      expect(isValidDagAddress('invalid')).toBe(false);
      expect(isValidDagAddress('')).toBe(false);
    });
  });

  describe('Transaction Creation', () => {
    test('createCurrencyTransaction creates valid transaction', () => {
      const keyPair = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      const tx = createCurrencyTransaction(
        {
          destination: keyPair2.address,
          amount: 100.5,
          fee: 0,
        },
        keyPair.privateKey,
        lastRef
      );

      expect(tx).toBeDefined();
      expect(tx.value.source).toBe(keyPair.address);
      expect(tx.value.destination).toBe(keyPair2.address);
      expect(tx.value.amount).toBe(10050000000); // 100.5 * 1e8
      expect(tx.value.fee).toBe(0);
      expect(tx.value.parent).toEqual(lastRef);
      expect(tx.proofs).toHaveLength(1);
      expect(tx.proofs[0]).toHaveProperty('id');
      expect(tx.proofs[0]).toHaveProperty('signature');
    });

    test('createCurrencyTransaction throws on invalid addresses', () => {
      const keyPair = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      expect(() =>
        createCurrencyTransaction(
          {
            destination: 'invalid',
            amount: 100,
            fee: 0,
          },
          keyPair.privateKey,
          lastRef
        )
      ).toThrow('Invalid destination address');
    });

    test('createCurrencyTransaction throws on same source and destination', () => {
      const keyPair = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      expect(() =>
        createCurrencyTransaction(
          {
            destination: keyPair.address,
            amount: 100,
            fee: 0,
          },
          keyPair.privateKey,
          lastRef
        )
      ).toThrow('Source and destination addresses cannot be the same');
    });

    test('createCurrencyTransaction throws on amount too small', () => {
      const keyPair = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      expect(() =>
        createCurrencyTransaction(
          {
            destination: keyPair2.address,
            amount: 0.000000001, // Less than 1e-8
            fee: 0,
          },
          keyPair.privateKey,
          lastRef
        )
      ).toThrow('Transfer amount must be greater than 1e-8');
    });

    test('createCurrencyTransaction throws on negative fee', () => {
      const keyPair = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      expect(() =>
        createCurrencyTransaction(
          {
            destination: keyPair2.address,
            amount: 100,
            fee: -1,
          },
          keyPair.privateKey,
          lastRef
        )
      ).toThrow('Fee must be greater than or equal to zero');
    });
  });

  describe('Batch Transactions', () => {
    test('createCurrencyTransactionBatch creates multiple transactions', () => {
      const keyPair = generateKeyPair();
      const recipient1 = generateKeyPair();
      const recipient2 = generateKeyPair();
      const recipient3 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 5,
      };

      const transfers = [
        { destination: recipient1.address, amount: 10 },
        { destination: recipient2.address, amount: 20 },
        { destination: recipient3.address, amount: 30 },
      ];

      const txns = createCurrencyTransactionBatch(transfers, keyPair.privateKey, lastRef);

      expect(txns).toHaveLength(3);
      expect(txns[0].value.amount).toBe(1000000000); // 10 * 1e8
      expect(txns[1].value.amount).toBe(2000000000); // 20 * 1e8
      expect(txns[2].value.amount).toBe(3000000000); // 30 * 1e8

      // Check parent references are chained
      expect(txns[0].value.parent).toEqual(lastRef);
      expect(txns[1].value.parent.ordinal).toBe(6);
      expect(txns[2].value.parent.ordinal).toBe(7);
    });
  });

  describe('Transaction Verification', () => {
    test('verifyCurrencyTransaction validates correct signatures', () => {
      const keyPair = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      const tx = createCurrencyTransaction(
        {
          destination: keyPair2.address,
          amount: 100,
          fee: 0,
        },
        keyPair.privateKey,
        lastRef
      );

      const result = verifyCurrencyTransaction(tx);

      expect(result.isValid).toBe(true);
      expect(result.validProofs).toHaveLength(1);
      expect(result.invalidProofs).toHaveLength(0);
    });

    test('verifyCurrencyTransaction detects invalid signatures', () => {
      const keyPair = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      const tx = createCurrencyTransaction(
        {
          destination: keyPair2.address,
          amount: 100,
          fee: 0,
        },
        keyPair.privateKey,
        lastRef
      );

      // Corrupt the signature
      tx.proofs[0].signature = 'invalid_signature';

      const result = verifyCurrencyTransaction(tx);

      expect(result.isValid).toBe(false);
      expect(result.validProofs).toHaveLength(0);
      expect(result.invalidProofs).toHaveLength(1);
    });
  });

  describe('Multi-Signature Support', () => {
    test('signCurrencyTransaction adds additional signature', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const recipient = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      // Create transaction with first signature
      let tx = createCurrencyTransaction(
        {
          destination: recipient.address,
          amount: 100,
          fee: 0,
        },
        keyPair1.privateKey,
        lastRef
      );

      expect(tx.proofs).toHaveLength(1);

      // Add second signature
      tx = signCurrencyTransaction(tx, keyPair2.privateKey);

      expect(tx.proofs).toHaveLength(2);

      // Verify both signatures
      const result = verifyCurrencyTransaction(tx);

      expect(result.isValid).toBe(true);
      expect(result.validProofs).toHaveLength(2);
      expect(result.invalidProofs).toHaveLength(0);
    });
  });

  describe('Transaction Hashing', () => {
    test('hashCurrencyTransaction produces consistent hashes', () => {
      const keyPair = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      const tx = createCurrencyTransaction(
        {
          destination: keyPair2.address,
          amount: 100,
          fee: 0,
        },
        keyPair.privateKey,
        lastRef
      );

      const hash1 = hashCurrencyTransaction(tx);
      const hash2 = hashCurrencyTransaction(tx);

      expect(hash1.value).toBe(hash2.value);
      expect(hash1.value).toHaveLength(64); // SHA-256 hex string
      expect(hash1.bytes).toHaveLength(32); // 32 bytes
    });

    test('getTransactionReference creates correct reference', () => {
      const keyPair = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const lastRef: TransactionReference = {
        hash: 'a'.repeat(64),
        ordinal: 0,
      };

      const tx = createCurrencyTransaction(
        {
          destination: keyPair2.address,
          amount: 100,
          fee: 0,
        },
        keyPair.privateKey,
        lastRef
      );

      const ref = getTransactionReference(tx, 1);

      expect(ref.ordinal).toBe(1);
      expect(ref.hash).toHaveLength(64);
    });
  });
});
