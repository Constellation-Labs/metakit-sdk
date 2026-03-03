/**
 * Data namespace — signing, verification, and encoding for metagraph data
 */

// Signing
export { sign, signDataUpdate, signHash } from '../sign';

// Verification
export { verify, verifyHash, verifySignature } from '../verify';

// High-level signing API
export { createSignedObject, addSignature, batchSign } from '../signed-object';

// Encoding and hashing
export { canonicalize } from '../canonicalize';
export { toBytes, encodeDataUpdate } from '../binary';
export { hash, hashBytes, hashData, computeDigest } from '../hash';
export { decodeDataUpdate } from '../codec';

// Types
export type {
  SignatureProof,
  Signed,
  Hash,
  VerificationResult,
  SigningOptions,
  SigningMode,
} from '../types';

export { ALGORITHM, CONSTELLATION_PREFIX } from '../types';
