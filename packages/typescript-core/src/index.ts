/**
 * Constellation Metagraph SDK — Core
 *
 * The kernel of the Constellation metagraph SDK: hashing, canonical
 * serialization, and signing primitives. Generic and fully offline — no
 * currency-transaction layer, no network client, no JSON Logic VM.
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
export { canonicalize, dropNullFields } from './canonicalize';

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

// Low-level crypto primitives (consumed by the metagraph-sdk currency +
// network layers, which live in a separate package and resolve these here).
export {
  constellationDigest,
  ecdsaSign,
  ecdsaVerify,
  getPublicKeyFromPrivate,
  getDagAddressFromPublicKey,
  validateDagAddress,
  sha256Hex,
  sha256Bytes,
  generatePrivateKey,
  getCompressedPublicKey,
  bytesToHex,
  hexToBytes,
} from './crypto';

// Committed-roots light-client codecs (byte-aligned with the metakit reference)
export type {
  SparseMerkleRoot,
  CommittedRoots,
  CommittedBreadcrumb,
  CommitKeyErrorCode,
} from './committed-roots';
export {
  committedRootsCombinedHash,
  encodeCommittedRoots,
  decodeCommittedRoots,
  encodeCommittedBreadcrumb,
  decodeCommittedBreadcrumb,
  CommitKey,
  CommitKeyError,
} from './committed-roots';

// Namespaced exports
export { wallet, data } from './namespaces';
