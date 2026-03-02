/**
 * Cryptographic Primitives
 *
 * Native secp256k1 operations using @noble/curves, replacing dag4 dependency.
 * Provides signing, verification, key generation, and DAG address derivation.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import bs58 from 'bs58';

/** X.509 DER encoding header for secp256k1 uncompressed public keys */
const PKCS_PREFIX = '3056301006072a8648ce3d020106052b8104000a034200';

/**
 * Compute the Constellation signing digest from a SHA-256 hash hex string.
 *
 * Protocol:
 * 1. Treat hashHex as UTF-8 bytes (NOT hex decode -- 64 ASCII chars = 64 bytes)
 * 2. SHA-512 hash those bytes (produces 64 bytes)
 * 3. Truncate to first 32 bytes (for secp256k1 curve order)
 */
export function constellationDigest(hashHex: string): Uint8Array {
  const hexAsUtf8 = new TextEncoder().encode(hashHex);
  const sha512Hash = sha512(hexAsUtf8);
  return sha512Hash.slice(0, 32);
}

/**
 * SHA-256 hash of bytes, returns hex string.
 */
export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

/**
 * SHA-256 hash of bytes, returns Uint8Array.
 */
export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Sign a 32-byte digest with ECDSA secp256k1, return DER-encoded hex.
 * Uses lowS=true (default) for BIP 62/146 compatibility.
 */
export function ecdsaSign(digest: Uint8Array, privateKeyHex: string): string {
  const sig = secp256k1.sign(digest, privateKeyHex, { lowS: true });
  return sig.toDERHex();
}

/**
 * Verify a DER-encoded ECDSA signature against a 32-byte digest.
 * Normalizes high-S to low-S before verification.
 */
export function ecdsaVerify(
  digest: Uint8Array,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    const sig = secp256k1.Signature.fromDER(signatureHex);
    const normalizedSig = sig.hasHighS() ? sig.normalizeS() : sig;
    const pubKeyBytes = hexToBytes(publicKeyHex);
    return secp256k1.verify(normalizedSig.toDERRawBytes(), digest, pubKeyBytes, { lowS: false });
  } catch {
    return false;
  }
}

/**
 * Generate a random 32-byte private key as hex.
 */
export function generatePrivateKey(): string {
  return bytesToHex(secp256k1.utils.randomPrivateKey());
}

/**
 * Get uncompressed public key (with 04 prefix) from private key.
 * Returns 130-character hex string.
 */
export function getPublicKeyFromPrivate(privateKeyHex: string): string {
  const pubKeyBytes = secp256k1.getPublicKey(privateKeyHex, false);
  return bytesToHex(pubKeyBytes);
}

/**
 * Get compressed public key from private key.
 * Returns 66-character hex string.
 */
export function getCompressedPublicKey(privateKeyHex: string): string {
  const pubKeyBytes = secp256k1.getPublicKey(privateKeyHex, true);
  return bytesToHex(pubKeyBytes);
}

/**
 * Derive DAG address from uncompressed public key hex.
 *
 * Algorithm:
 * 1. Normalize pubkey to include 04 prefix
 * 2. Prepend PKCS prefix (X.509 DER header for secp256k1)
 * 3. SHA-256 hash the full hex bytes
 * 4. Base58 encode (Bitcoin alphabet)
 * 5. Take last 36 characters
 * 6. Parity = sum of digit characters mod 9
 * 7. Address = "DAG" + parity + last36
 */
export function getDagAddressFromPublicKey(publicKeyHex: string): string {
  let normalized = publicKeyHex;
  if (normalized.length === 128) {
    normalized = '04' + normalized;
  }

  const fullHex = PKCS_PREFIX + normalized;
  const fullBytes = hexToBytes(fullHex);
  const hashResult = sha256(fullBytes);
  const base58Encoded = bs58.encode(hashResult);

  const last36 = base58Encoded.slice(-36);

  let digitSum = 0;
  for (const c of last36) {
    if (c >= '0' && c <= '9') {
      digitSum += parseInt(c, 10);
    }
  }
  const parity = digitSum % 9;

  return `DAG${parity}${last36}`;
}

/**
 * Validate DAG address format.
 * DAG + parity digit (0-8) + 36 base58 chars = 40 chars total.
 */
export function validateDagAddress(address: string): boolean {
  if (!address.startsWith('DAG')) return false;
  if (address.length !== 40) return false;
  const parityChar = address[3];
  if (!/^[0-8]$/.test(parityChar)) return false;
  const base58Regex =
    /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{36}$/;
  return base58Regex.test(address.slice(4));
}

export { bytesToHex, hexToBytes };
