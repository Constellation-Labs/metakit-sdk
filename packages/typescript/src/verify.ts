/**
 * Signature Verification
 *
 * Verify ECDSA signatures using secp256k1 curve via @noble/curves.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/curves/abstract/utils';
import { Signed, SignatureProof, VerificationResult } from './types';
import { toBytes } from './binary';
import { constellationDigest, ecdsaVerify } from './crypto';

/**
 * Verify a signed object
 *
 * When the signed object has a `mode` field (set by createSignedObject/addSignature/batchSign),
 * verification automatically uses the correct mode. The `isDataUpdate` parameter is only
 * needed for objects without a `mode` field (e.g., deserialized from older wire format).
 *
 * @param signed - Signed object with value and proofs
 * @param isDataUpdate - Whether the value was signed as a DataUpdate (ignored if signed.mode is set)
 * @returns VerificationResult with valid/invalid proof lists
 *
 * @example
 * ```typescript
 * // Mode is auto-detected from signed object
 * const result = verify(signedObject);
 * if (result.isValid) {
 *   console.log('All signatures valid');
 * }
 * ```
 */
export function verify<T>(
  signed: Signed<T>,
  isDataUpdate: boolean = false
): VerificationResult {
  // Prefer mode from signed object; fall back to isDataUpdate parameter
  const useDataUpdate = signed.mode
    ? signed.mode === 'dataUpdate'
    : isDataUpdate;
  const bytes = toBytes(signed.value, useDataUpdate);
  const hashHex = bytesToHex(sha256(bytes));

  const validProofs: SignatureProof[] = [];
  const invalidProofs: SignatureProof[] = [];

  for (const proof of signed.proofs) {
    try {
      const isValid = verifyHash(hashHex, proof.signature, proof.id);
      if (isValid) {
        validProofs.push(proof);
      } else {
        invalidProofs.push(proof);
      }
    } catch {
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
 * Verify a signature against a SHA-256 hash
 *
 * Protocol:
 * 1. Treat hash hex as UTF-8 bytes (NOT hex decode)
 * 2. SHA-512 hash
 * 3. Truncate to 32 bytes
 * 4. Verify ECDSA signature (with low-S normalization)
 *
 * @param hashHex - SHA-256 hash as 64-character hex string
 * @param signature - DER-encoded signature in hex format
 * @param publicKeyId - Public key in hex (with or without 04 prefix)
 * @returns true if signature is valid
 */
export function verifyHash(
  hashHex: string,
  signature: string,
  publicKeyId: string
): boolean {
  try {
    const fullPublicKey = normalizePublicKey(publicKeyId);
    const digest = constellationDigest(hashHex);
    return ecdsaVerify(digest, signature, fullPublicKey);
  } catch {
    return false;
  }
}

/**
 * Verify a single signature proof against data
 *
 * @param data - The original data that was signed
 * @param proof - The signature proof to verify
 * @param isDataUpdate - Whether data was signed as DataUpdate
 * @returns true if signature is valid
 */
export function verifySignature<T>(
  data: T,
  proof: SignatureProof,
  isDataUpdate: boolean = false
): boolean {
  const bytes = toBytes(data, isDataUpdate);
  const hashHex = bytesToHex(sha256(bytes));
  return verifyHash(hashHex, proof.signature, proof.id);
}

/**
 * Normalize public key to full format (with 04 prefix)
 */
function normalizePublicKey(publicKey: string): string {
  if (publicKey.length === 128) {
    return '04' + publicKey;
  }
  if (publicKey.length === 130 && publicKey.startsWith('04')) {
    return publicKey;
  }
  return publicKey;
}
