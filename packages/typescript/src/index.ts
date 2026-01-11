/**
 * Constellation Metagraph SDK
 *
 * TypeScript SDK for signing operations on Constellation Network metagraphs.
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

// Network operations
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
