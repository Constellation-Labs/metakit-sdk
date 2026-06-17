/**
 * Wallet and Key Management Utilities
 *
 * Functions for generating and managing cryptographic keys.
 */

import {
  generatePrivateKey,
  getPublicKeyFromPrivate,
  getCompressedPublicKey,
  getDagAddressFromPublicKey,
} from './crypto';
import { KeyPair } from './types';

/**
 * Generate a new random key pair
 *
 * @returns KeyPair with private key, public key, and DAG address
 *
 * @example
 * ```typescript
 * const keyPair = generateKeyPair();
 * console.log(keyPair.address);    // DAG address
 * console.log(keyPair.privateKey); // 64 char hex
 * console.log(keyPair.publicKey);  // 130 char hex (with 04 prefix)
 * ```
 */
export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivateKey();
  return keyPairFromPrivateKey(privateKey);
}

/**
 * Derive a key pair from an existing private key
 *
 * @param privateKey - Private key in hex format (64 characters)
 * @returns KeyPair with private key, public key, and DAG address
 *
 * @example
 * ```typescript
 * const keyPair = keyPairFromPrivateKey(existingPrivateKey);
 * ```
 */
export function keyPairFromPrivateKey(privateKey: string): KeyPair {
  const publicKey = getPublicKeyFromPrivate(privateKey);
  const address = getDagAddressFromPublicKey(publicKey);

  return {
    privateKey,
    publicKey: normalizePublicKey(publicKey),
    address,
  };
}

/**
 * Get the public key hex from a private key
 *
 * @param privateKey - Private key in hex format
 * @param compressed - If true, returns compressed public key (33 bytes)
 * @returns Public key in hex format
 */
export function getPublicKeyHex(privateKey: string, compressed: boolean = false): string {
  if (compressed) {
    return getCompressedPublicKey(privateKey);
  }
  return getPublicKeyFromPrivate(privateKey);
}

/**
 * Get the public key ID (without 04 prefix) from a private key
 *
 * This format is used in SignatureProof.id
 *
 * @param privateKey - Private key in hex format
 * @returns Public key ID (128 characters, no 04 prefix)
 */
export function getPublicKeyId(privateKey: string): string {
  const publicKey = getPublicKeyFromPrivate(privateKey);
  if (publicKey.length === 130 && publicKey.startsWith('04')) {
    return publicKey.substring(2);
  }
  return publicKey;
}

/**
 * Get DAG address from a public key
 *
 * @param publicKey - Public key in hex format (with or without 04 prefix)
 * @returns DAG address string
 */
export function getAddress(publicKey: string): string {
  const normalizedKey = normalizePublicKey(publicKey);
  return getDagAddressFromPublicKey(normalizedKey);
}

/**
 * Validate that a private key is correctly formatted
 *
 * @param privateKey - Private key to validate
 * @returns true if valid hex string of correct length
 */
export function isValidPrivateKey(privateKey: string): boolean {
  if (typeof privateKey !== 'string') return false;
  if (privateKey.length !== 64) return false;
  return /^[0-9a-fA-F]+$/.test(privateKey);
}

/**
 * Validate that a public key is correctly formatted
 *
 * @param publicKey - Public key to validate
 * @returns true if valid hex string of correct length
 */
export function isValidPublicKey(publicKey: string): boolean {
  if (typeof publicKey !== 'string') return false;
  if (publicKey.length !== 128 && publicKey.length !== 130) return false;
  return /^[0-9a-fA-F]+$/.test(publicKey);
}

/**
 * Normalize public key to include 04 prefix
 */
function normalizePublicKey(publicKey: string): string {
  if (publicKey.length === 128) {
    return '04' + publicKey;
  }
  return publicKey;
}
