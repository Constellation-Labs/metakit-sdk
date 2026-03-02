/**
 * Constellation Metagraph SDK
 *
 * TypeScript SDK for signing operations on Constellation Network metagraphs.
 *
 * This is the **core** module containing signing, hashing, verification,
 * and JSON Logic operations. It has no network dependencies.
 *
 * For network operations (connecting to ML0/CL1/DL1 nodes), import from
 * the separate network module:
 *
 * ```typescript
 * import { MetagraphClient, createMetagraphClient } from '@constellation-network/metagraph-sdk/network';
 *
 * const cl1 = createMetagraphClient('http://localhost:9300', 'cl1');
 * const dl1 = createMetagraphClient('http://localhost:9400', 'dl1');
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

// Network exports (from submodule)
export { HttpClient, NetworkError } from './network';
export type {
  RequestOptions,
  TransactionStatus,
  PendingTransaction,
  PostTransactionResponse,
  EstimateFeeResponse,
  PostDataResponse,
} from './network';

// Namespaced exports
export { wallet, data, currency, network, jlvm } from './namespaces';
