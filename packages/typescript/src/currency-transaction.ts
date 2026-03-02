/**
 * Currency transaction operations for metagraph token transfers
 *
 * @packageDocumentation
 */

import {
  constellationDigest,
  ecdsaSign,
  ecdsaVerify,
  getPublicKeyFromPrivate,
  getDagAddressFromPublicKey,
  validateDagAddress,
  sha256Hex,
} from './crypto';
import {
  encodeTransaction,
  kryoSerialize,
  generateSalt,
} from './transaction-encoding';
import type {
  CurrencyTransaction,
  TransactionReference,
  TransferParams,
} from './currency-types';
import { TOKEN_DECIMALS } from './currency-types';
import type { VerificationResult, SignatureProof } from './types';

/**
 * Convert token amount to smallest units
 *
 * @param amount - Amount in token units (e.g., 100.5)
 * @returns Amount in smallest units (1e-8)
 *
 * @example
 * ```typescript
 * const units = tokenToUnits(100.5); // 10050000000
 * ```
 */
export function tokenToUnits(amount: number): number {
  return Math.floor(amount * 1e8);
}

/**
 * Convert smallest units to token amount
 *
 * @param units - Amount in smallest units
 * @returns Amount in token units
 *
 * @example
 * ```typescript
 * const tokens = unitsToToken(10050000000); // 100.5
 * ```
 */
export function unitsToToken(units: number): number {
  return units * TOKEN_DECIMALS;
}

/**
 * Validate DAG address format
 *
 * @param address - DAG address to validate
 * @returns True if address is valid
 *
 * @example
 * ```typescript
 * const valid = isValidDagAddress('DAG...');
 * ```
 */
export function isValidDagAddress(address: string): boolean {
  return validateDagAddress(address);
}

/**
 * Create a metagraph token transaction
 *
 * @param params - Transfer parameters
 * @param privateKey - Private key to sign with (hex string)
 * @param lastRef - Reference to last accepted transaction
 * @returns Signed currency transaction
 *
 * @throws If addresses are invalid or amount is too small
 *
 * @example
 * ```typescript
 * const tx = createCurrencyTransaction(
 *   { destination: 'DAG...', amount: 100.5, fee: 0 },
 *   privateKey,
 *   { hash: 'abc123...', ordinal: 5 }
 * );
 * ```
 */
export function createCurrencyTransaction(
  params: TransferParams,
  privateKey: string,
  lastRef: TransactionReference
): CurrencyTransaction {
  // Get source address from private key
  const publicKey = getPublicKeyFromPrivate(privateKey);
  const source = getDagAddressFromPublicKey(publicKey);

  // Validate addresses
  if (!isValidDagAddress(source)) {
    throw new Error('Invalid source address');
  }
  if (!isValidDagAddress(params.destination)) {
    throw new Error('Invalid destination address');
  }
  if (source === params.destination) {
    throw new Error('Source and destination addresses cannot be the same');
  }

  // Convert amounts to smallest units
  const amount = tokenToUnits(params.amount);
  const fee = tokenToUnits(params.fee ?? 0);

  // Validate amounts
  if (amount < 1) {
    throw new Error('Transfer amount must be greater than 1e-8');
  }
  if (fee < 0) {
    throw new Error('Fee must be greater than or equal to zero');
  }

  // Generate salt
  const salt = generateSalt();

  // Build transaction
  const tx: CurrencyTransaction = {
    value: {
      source,
      destination: params.destination,
      amount,
      fee,
      parent: lastRef,
      salt,
    },
    proofs: [],
  };

  // Encode -> Kryo serialize -> SHA-256 -> sign
  const encoded = encodeTransaction(tx);
  const serialized = kryoSerialize(encoded, false);
  const hash = sha256Hex(serialized);
  const digest = constellationDigest(hash);
  const signature = ecdsaSign(digest, privateKey);

  // Verify signature
  const uncompressedPublicKey =
    publicKey.length === 128 ? '04' + publicKey : publicKey;
  const verified = ecdsaVerify(digest, signature, uncompressedPublicKey);
  if (!verified) {
    throw new Error('Sign-Verify failed');
  }

  // Add signature proof
  tx.proofs.push({
    id: uncompressedPublicKey.substring(2),
    signature,
  });

  return tx;
}

/**
 * Create multiple metagraph token transactions (batch)
 *
 * @param transfers - Array of transfer parameters
 * @param privateKey - Private key to sign with
 * @param lastRef - Reference to last accepted transaction
 * @returns Array of signed currency transactions
 *
 * @throws If any address is invalid or amount is too small
 *
 * @example
 * ```typescript
 * const txns = createCurrencyTransactionBatch(
 *   [
 *     { destination: 'DAG...1', amount: 10 },
 *     { destination: 'DAG...2', amount: 20 },
 *   ],
 *   privateKey,
 *   { hash: 'abc123...', ordinal: 5 }
 * );
 * ```
 */
export function createCurrencyTransactionBatch(
  transfers: TransferParams[],
  privateKey: string,
  lastRef: TransactionReference
): CurrencyTransaction[] {
  const transactions: CurrencyTransaction[] = [];
  let currentRef = { ...lastRef };

  for (const transfer of transfers) {
    const tx = createCurrencyTransaction(transfer, privateKey, currentRef);

    // Calculate hash for next transaction's parent reference
    const hash = hashCurrencyTransaction(tx);

    // Update reference for next transaction
    currentRef = {
      hash: hash.value,
      ordinal: currentRef.ordinal + 1,
    };

    transactions.push(tx);
  }

  return transactions;
}

/**
 * Add a signature to an existing currency transaction (for multi-sig)
 *
 * @param transaction - Transaction to sign
 * @param privateKey - Private key to sign with
 * @returns Transaction with additional signature
 *
 * @throws If sign-verify fails
 *
 * @example
 * ```typescript
 * const signedTx = signCurrencyTransaction(tx, privateKey2);
 * ```
 */
export function signCurrencyTransaction(
  transaction: CurrencyTransaction,
  privateKey: string
): CurrencyTransaction {
  // Encode and hash
  const encoded = encodeTransaction(transaction);
  const serialized = kryoSerialize(encoded, false);
  const hash = sha256Hex(serialized);
  const digest = constellationDigest(hash);

  // Sign
  const publicKey = getPublicKeyFromPrivate(privateKey);
  const signature = ecdsaSign(digest, privateKey);

  // Verify signature
  const uncompressedPublicKey =
    publicKey.length === 128 ? '04' + publicKey : publicKey;
  const verified = ecdsaVerify(digest, signature, uncompressedPublicKey);
  if (!verified) {
    throw new Error('Sign-Verify failed');
  }

  // Create new transaction with additional proof
  const proof: SignatureProof = {
    id: uncompressedPublicKey.substring(2),
    signature,
  };

  return {
    value: transaction.value,
    proofs: [...transaction.proofs, proof],
  };
}

/**
 * Verify all signatures on a currency transaction
 *
 * @param transaction - Transaction to verify
 * @returns Verification result with valid/invalid proofs
 *
 * @example
 * ```typescript
 * const result = verifyCurrencyTransaction(tx);
 * console.log('Valid:', result.isValid);
 * ```
 */
export function verifyCurrencyTransaction(
  transaction: CurrencyTransaction
): VerificationResult {
  // Encode and hash
  const encoded = encodeTransaction(transaction);
  const serialized = kryoSerialize(encoded, false);
  const hash = sha256Hex(serialized);
  const digest = constellationDigest(hash);

  const validProofs: SignatureProof[] = [];
  const invalidProofs: SignatureProof[] = [];

  // Verify each proof
  for (const proof of transaction.proofs) {
    const publicKey = '04' + proof.id;
    const isValid = ecdsaVerify(digest, proof.signature, publicKey);

    if (isValid) {
      validProofs.push(proof);
    } else {
      invalidProofs.push(proof);
    }
  }

  return {
    isValid: invalidProofs.length === 0 && validProofs.length > 0,
    validProofs,
    invalidProofs,
  };
}

/**
 * Encode a currency transaction for hashing
 *
 * @param transaction - Transaction to encode
 * @returns Encoded transaction string
 *
 * @example
 * ```typescript
 * const encoded = encodeCurrencyTransaction(tx);
 * ```
 */
export function encodeCurrencyTransaction(
  transaction: CurrencyTransaction
): string {
  return encodeTransaction(transaction);
}

/**
 * Hash a currency transaction
 *
 * @param transaction - Transaction to hash
 * @returns Hash object with value and bytes
 *
 * @example
 * ```typescript
 * const hash = hashCurrencyTransaction(tx);
 * console.log('Hash:', hash.value);
 * ```
 */
export function hashCurrencyTransaction(
  transaction: CurrencyTransaction
): { value: string; bytes: Uint8Array } {
  const encoded = encodeTransaction(transaction);
  const serialized = kryoSerialize(encoded, false);
  const hashValue = sha256Hex(serialized);

  return {
    value: hashValue,
    bytes: new Uint8Array(Buffer.from(hashValue, 'hex')),
  };
}

/**
 * Get transaction reference from a currency transaction
 * Useful for chaining transactions
 *
 * @param transaction - Transaction to extract reference from
 * @param ordinal - Ordinal number for this transaction
 * @returns Transaction reference
 *
 * @example
 * ```typescript
 * const ref = getTransactionReference(tx, 6);
 * // Use ref as lastRef for next transaction
 * ```
 */
export function getTransactionReference(
  transaction: CurrencyTransaction,
  ordinal: number
): TransactionReference {
  const hash = hashCurrencyTransaction(transaction);
  return {
    hash: hash.value,
    ordinal,
  };
}
