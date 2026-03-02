/**
 * Signing Functions
 *
 * ECDSA signing using secp256k1 curve via @noble/curves.
 * Implements the Constellation signature protocol.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/curves/abstract/utils';
import { SignatureProof } from './types';
import { canonicalize } from './canonicalize';
import { toBytes } from './binary';
import { constellationDigest, ecdsaSign, getPublicKeyFromPrivate } from './crypto';

/**
 * Sign data using the regular Constellation protocol (non-DataUpdate)
 *
 * Protocol:
 * 1. Canonicalize JSON (RFC 8785)
 * 2. SHA-256 hash the canonical JSON string
 * 3. Compute Constellation digest (SHA-512 of hash-as-UTF-8, truncated to 32 bytes)
 * 4. Sign with ECDSA secp256k1
 *
 * @param data - Any JSON-serializable object
 * @param privateKey - Private key in hex format
 * @returns SignatureProof with public key ID and signature
 *
 * @example
 * ```typescript
 * const proof = sign({ action: 'test' }, privateKeyHex);
 * console.log(proof.id);        // public key (128 chars)
 * console.log(proof.signature); // DER signature
 * ```
 */
export function sign<T>(data: T, privateKey: string): SignatureProof {
  const canonicalJson = canonicalize(data);
  const hashHex = bytesToHex(sha256(new TextEncoder().encode(canonicalJson)));
  const digest = constellationDigest(hashHex);
  const signature = ecdsaSign(digest, privateKey);
  const publicKey = getPublicKeyFromPrivate(privateKey);
  const id = normalizePublicKeyId(publicKey);

  return { id, signature };
}

/**
 * Sign data as a DataUpdate (with Constellation prefix)
 *
 * Protocol:
 * 1. Canonicalize JSON (RFC 8785)
 * 2. Encode with Constellation prefix via toBytes(data, true)
 * 3. SHA-256 hash the encoded bytes
 * 4. Compute Constellation digest
 * 5. Sign with ECDSA secp256k1
 *
 * @param data - Any JSON-serializable object
 * @param privateKey - Private key in hex format
 * @returns SignatureProof
 */
export function signDataUpdate<T>(data: T, privateKey: string): SignatureProof {
  const dataBytes = toBytes(data, true);
  const hashHex = bytesToHex(sha256(dataBytes));
  const digest = constellationDigest(hashHex);
  const signature = ecdsaSign(digest, privateKey);
  const publicKey = getPublicKeyFromPrivate(privateKey);
  const id = normalizePublicKeyId(publicKey);

  return { id, signature };
}

/**
 * Sign a pre-computed SHA-256 hash
 *
 * This is the low-level signing function. Use `sign()` or `signDataUpdate()`
 * for most use cases.
 *
 * Protocol:
 * 1. Treat hashHex as UTF-8 bytes (64 ASCII characters = 64 bytes)
 * 2. SHA-512 hash those bytes (produces 64 bytes)
 * 3. Truncate to first 32 bytes (for secp256k1 curve order)
 * 4. Sign with ECDSA secp256k1
 * 5. Return DER-encoded signature
 *
 * @param hashHex - SHA-256 hash as 64-character hex string
 * @param privateKey - Private key in hex format (64 characters)
 * @returns DER-encoded signature in hex format
 *
 * @example
 * ```typescript
 * const hashHex = hash(myData).value;
 * const signature = signHash(hashHex, privateKey);
 * ```
 */
export function signHash(hashHex: string, privateKey: string): string {
  const digest = constellationDigest(hashHex);
  return ecdsaSign(digest, privateKey);
}

/**
 * Normalize public key to ID format (without 04 prefix, 128 chars)
 */
function normalizePublicKeyId(publicKey: string): string {
  if (publicKey.length === 130 && publicKey.startsWith('04')) {
    return publicKey.substring(2);
  }
  if (publicKey.length === 128) {
    return publicKey;
  }
  return publicKey;
}
