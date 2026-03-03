/**
 * Hashing Utilities
 *
 * SHA-256 and SHA-512 hashing for the Constellation signature protocol.
 */

import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex } from '@noble/curves/abstract/utils';
import { Hash } from './types';
import type { SigningMode } from './types';
import { toBytes } from './binary';

/**
 * Compute SHA-256 hash of canonical JSON data
 *
 * @param data - Any JSON-serializable object
 * @returns Hash object with hex string and raw bytes
 *
 * @example
 * ```typescript
 * const hashResult = hash({ action: 'test' });
 * console.log(hashResult.value); // 64-char hex string
 * ```
 */
export function hash<T>(data: T): Hash {
  const bytes = toBytes(data, false);
  return hashBytes(bytes);
}

/**
 * Compute SHA-256 hash of raw bytes
 *
 * @param bytes - Input bytes
 * @returns Hash object with hex string and raw bytes
 */
export function hashBytes(bytes: Uint8Array): Hash {
  const hashUint8 = sha256(bytes);
  const hashHex = bytesToHex(hashUint8);

  return {
    value: hashHex,
    bytes: hashUint8,
  };
}

/**
 * Compute the full signing digest according to Constellation protocol
 *
 * Protocol:
 * 1. Serialize data to binary (with optional DataUpdate prefix)
 * 2. Compute SHA-256 hash
 * 3. Convert hash to hex string
 * 4. Treat hex string as UTF-8 bytes (NOT hex decode)
 * 5. Compute SHA-512 of those bytes
 * 6. Truncate to 32 bytes for secp256k1 signing
 *
 * @param data - Any JSON-serializable object
 * @param mode - SigningMode ('standard' | 'dataUpdate') or boolean for backward compat
 * @returns 32-byte digest ready for ECDSA signing
 */
export function computeDigest<T>(data: T, mode: SigningMode | boolean = false): Uint8Array {
  // Step 1: Serialize to binary
  const dataBytes = toBytes(data, mode);

  // Step 2: SHA-256 hash
  const sha256Hash = hashBytes(dataBytes);

  // Step 3-4: Hex string as UTF-8 bytes (critical: NOT hex decode)
  const hexAsUtf8 = new TextEncoder().encode(sha256Hash.value);

  // Step 5: SHA-512
  const sha512Hash = sha512(hexAsUtf8);

  // Step 6: Truncate to 32 bytes
  return sha512Hash.slice(0, 32);
}

/**
 * Compute SHA-256 hash of data with optional DataUpdate encoding
 *
 * @param data - Any JSON-serializable object
 * @param mode - SigningMode ('standard' | 'dataUpdate') or boolean for backward compat
 * @returns Hash object
 */
export function hashData<T>(data: T, mode: SigningMode | boolean = false): Hash {
  const bytes = toBytes(data, mode);
  return hashBytes(bytes);
}
