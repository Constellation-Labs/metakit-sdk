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
 * import { MetagraphClient } from '@constellation-network/metagraph-sdk/network';
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

// ============================================================
// DEPRECATED: Network exports moved to separate entrypoint
// ============================================================
//
// Network operations are now in a separate module to keep the
// core SDK network-free. Import from '@constellation-network/metagraph-sdk/network'
//
// These re-exports are maintained for backwards compatibility
// but will be removed in a future major version.
//

export { CurrencyL1Client, DataL1Client, HttpClient, NetworkError } from './network';
export type {
  NetworkConfig,
  RequestOptions,
  TransactionStatus,
  PendingTransaction,
  PostTransactionResponse,
  EstimateFeeResponse,
  PostDataResponse,
} from './network';
