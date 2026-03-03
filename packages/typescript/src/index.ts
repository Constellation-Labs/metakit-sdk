/**
 * Constellation Metagraph SDK
 *
 * TypeScript SDK for signing operations on Constellation Network metagraphs.
 *
 * This is the **core** module containing signing, hashing, verification,
 * wallet, and currency transaction operations. It works fully offline
 * with no network dependencies.
 *
 * Optional subpath imports for additional features:
 *
 * ```typescript
 * // Network client (ML0/CL1/DL1 nodes)
 * import { createMetagraphClient } from '@constellation-network/metagraph-sdk/network';
 *
 * // JSON Logic VM
 * import { jsonLogic } from '@constellation-network/metagraph-sdk/json-logic';
 * ```
 *
 * @packageDocumentation
 */

// Core types
export type {
  SignatureProof,
  Signed,
  KeyPair,
  Hash,
  VerificationResult,
  SigningOptions,
  SigningMode,
} from './types';

export { ALGORITHM, CONSTELLATION_PREFIX } from './types';

// Canonicalization
export { canonicalize } from './canonicalize';

// Binary encoding
export { toBytes, encodeDataUpdate } from './binary';

// Hashing
export { hash, hashBytes, hashData, computeDigest } from './hash';

// Codec utilities
export { decodeDataUpdate } from './codec';

// Signing
export { sign, signDataUpdate, signHash } from './sign';

// Verification
export { verify, verifyHash, verifySignature } from './verify';

// High-level API
export { createSignedObject, addSignature, batchSign } from './signed-object';

// Wallet utilities
export {
  generateKeyPair,
  keyPairFromPrivateKey,
  getPublicKeyHex,
  getPublicKeyId,
  getAddress,
  isValidPrivateKey,
  isValidPublicKey,
} from './wallet';

// Currency transaction types
export type {
  TransactionReference,
  CurrencyTransactionValue,
  CurrencyTransaction,
  TransferParams,
  TransferResult,
} from './currency-types';

export { TOKEN_DECIMALS } from './currency-types';

// Currency transaction operations
export {
  createCurrencyTransaction,
  createCurrencyTransactionBatch,
  signCurrencyTransaction,
  verifyCurrencyTransaction,
  encodeCurrencyTransaction,
  hashCurrencyTransaction,
  getTransactionReference,
  isValidDagAddress,
  tokenToUnits,
  unitsToToken,
} from './currency-transaction';

// Namespaced exports (network and jlvm are separate subpath imports)
export { wallet, data, currency } from './namespaces';
