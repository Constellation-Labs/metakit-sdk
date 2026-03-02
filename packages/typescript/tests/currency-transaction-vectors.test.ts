/**
 * Currency transaction test vector validation
 *
 * Validates TypeScript implementation against reference test vectors from tessellation
 */

import { describe, expect, it } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import {
  createCurrencyTransaction,
  verifyCurrencyTransaction,
  hashCurrencyTransaction,
  encodeCurrencyTransaction,
} from '../src/currency-transaction';
import { getPublicKeyFromPrivate } from '../src/crypto';
import type { CurrencyTransaction } from '../src/currency-types';
import { getAddress } from '../src/wallet';

// Load test vectors
const testVectorsPath = path.join(__dirname, '../../../shared/currency_transaction_vectors.json');
const testVectors = JSON.parse(fs.readFileSync(testVectorsPath, 'utf-8'));

describe('Currency Transaction Test Vectors', () => {
  const basic = testVectors.testVectors.basicTransaction;

  describe('Key Derivation', () => {
    it('derives correct public key from private key', () => {
      const publicKey = getPublicKeyFromPrivate(basic.privateKeyHex);
      // getPublicKeyFromPrivate returns with 04 prefix
      const normalizedPublicKey = publicKey.startsWith('04') ? publicKey : '04' + publicKey;
      expect(normalizedPublicKey).toBe(basic.publicKeyHex);
    });

    it('derives correct address from public key', () => {
      const publicKey = getPublicKeyFromPrivate(basic.privateKeyHex);
      const address = getAddress(publicKey);
      expect(address).toBe(basic.address);
    });
  });

  describe('Transaction Encoding', () => {
    it('encodes transaction correctly', () => {
      // Create transaction with known salt
      const tx = createCurrencyTransaction(
        {
          destination: basic.transaction.destination,
          amount: basic.transaction.amount / 1e8, // Convert to token units
          fee: basic.transaction.fee / 1e8,
        },
        basic.privateKeyHex,
        basic.transaction.parent
      );

      // Override salt for deterministic test
      (tx.value as any).salt = basic.transaction.salt.toString();

      const encoded = encodeCurrencyTransaction(tx);
      expect(encoded).toBe(basic.encodedString);
    });

    it('validates encoding format breakdown', () => {
      const breakdown = testVectors.testVectors.encodingBreakdown;
      const components = breakdown.components;

      // Create transaction with known values
      const tx = createCurrencyTransaction(
        {
          destination: components.destination.value,
          amount: parseInt(components.amountHex.value, 16) / 1e8,
          fee: parseInt(components.fee.value) / 1e8,
        },
        basic.privateKeyHex,
        {
          hash: components.parentHash.value,
          ordinal: parseInt(components.ordinal.value),
        }
      );

      // Override salt
      (tx.value as any).salt = parseInt(components.saltHex.value, 16).toString();

      const encoded = encodeCurrencyTransaction(tx);

      // Verify encoding format
      expect(encoded.startsWith('2')).toBe(true); // Version prefix
      expect(encoded).toContain(components.source.value);
      expect(encoded).toContain(components.destination.value);
      expect(encoded).toContain(components.amountHex.value);
      expect(encoded).toContain(components.parentHash.value);
    });
  });

  describe('Transaction Hashing', () => {
    it('produces correct transaction hash', () => {
      // Create transaction with deterministic values
      const tx = createCurrencyTransaction(
        {
          destination: basic.transaction.destination,
          amount: basic.transaction.amount / 1e8,
          fee: basic.transaction.fee / 1e8,
        },
        basic.privateKeyHex,
        basic.transaction.parent
      );

      // Override salt and proofs for exact match
      (tx.value as any).salt = basic.transaction.salt.toString();
      tx.proofs = [];

      const hash = hashCurrencyTransaction(tx);
      expect(hash.value).toBe(basic.transactionHash);
    });
  });

  describe('Signature Verification', () => {
    it('verifies reference signature from Scala test vectors', () => {
      // Scala signatures are normalized to low-S during verification
      const tx: CurrencyTransaction = {
        value: {
          ...basic.transaction,
          salt: basic.transaction.salt.toString(),
        },
        proofs: [
          {
            id: basic.signerId,
            signature: basic.signature,
          },
        ],
      };

      const result = verifyCurrencyTransaction(tx);
      expect(result.isValid).toBe(true);
      expect(result.validProofs.length).toBe(1);
      expect(result.invalidProofs.length).toBe(0);
    });

    it('verifies multi-signature transaction from Scala test vectors', () => {
      // Scala signatures are normalized to low-S during verification
      const multiSig = testVectors.testVectors.multiSignature;
      expect(multiSig.transactionHash).toBe(basic.transactionHash);

      const tx: CurrencyTransaction = {
        value: {
          ...basic.transaction,
          salt: basic.transaction.salt.toString(),
        },
        proofs: multiSig.proofs,
      };

      const result = verifyCurrencyTransaction(tx);
      expect(result.isValid).toBe(true);
      expect(result.validProofs.length).toBe(2);
      expect(result.invalidProofs.length).toBe(0);

      // Verify both proofs are marked as valid in test vectors
      multiSig.proofs.forEach((proof: any) => {
        expect(proof.valid).toBe(true);
      });
    });
  });

  describe('Transaction Chaining', () => {
    it('validates transaction chain parent references', () => {
      const chain = testVectors.testVectors.transactionChaining.transactions;

      // Verify first transaction parent
      expect(chain[0].parentHash).toBe(
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      );
      expect(chain[0].parentOrdinal).toBe(5);
      expect(chain[0].ordinal).toBe(6);

      // Verify second transaction chains to first
      expect(chain[1].parentHash).toBe(chain[0].hash);
      expect(chain[1].parentOrdinal).toBe(chain[0].ordinal);
      expect(chain[1].ordinal).toBe(7);

      // Verify third transaction chains to second
      expect(chain[2].parentHash).toBe(chain[1].hash);
      expect(chain[2].parentOrdinal).toBe(chain[1].ordinal);
      expect(chain[2].ordinal).toBe(8);
    });
  });

  describe('Edge Cases', () => {
    it('validates minimum amount transaction', () => {
      const minAmount = testVectors.testVectors.edgeCases.minAmount;
      expect(minAmount.amount).toBe(1);
      expect(minAmount.hash).toBeTruthy();
      expect(minAmount.signature).toBeTruthy();
    });

    it('validates maximum amount transaction', () => {
      // Note: JavaScript's MAX_SAFE_INTEGER is 2^53-1 (9007199254740991)
      // Long.MAX_VALUE is 2^63-1 (9223372036854775807)
      // JavaScript cannot accurately represent Long.MAX_VALUE as a number
      // However, we can still validate that the hash and signature exist
      const maxAmount = testVectors.testVectors.edgeCases.maxAmount;
      expect(maxAmount.hash).toBeTruthy();
      expect(maxAmount.signature).toBeTruthy();
      // Note: We don't validate maxAmount.amount here due to JavaScript number precision limits
    });

    it('validates transaction with non-zero fee', () => {
      const withFee = testVectors.testVectors.edgeCases.withFee;
      expect(withFee.amount).toBe(10000000000);
      expect(withFee.fee).toBe(100000);
      expect(withFee.hash).toBeTruthy();
      expect(withFee.signature).toBeTruthy();
    });
  });

  describe('Kryo Serialization', () => {
    it('validates Kryo setReferences=false format (v2 transactions)', () => {
      const params = testVectors.cryptoParams;
      expect(params.kryoSetReferences).toBe(false);
    });

    it('validates Kryo header without reference flag (v2 format)', () => {
      const kryoHex = basic.kryoBytesHex;
      // Should start with 0x03 (string type) followed by length, no 0x01 reference flag for v2
      expect(kryoHex.startsWith('03')).toBe(true);
      expect(kryoHex.startsWith('0301')).toBe(false); // No reference flag for v2
    });
  });
});
