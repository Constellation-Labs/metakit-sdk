/**
 * High-Level Signed Object API
 *
 * Convenience functions for creating and managing signed objects.
 */

import { Signed, SignatureProof, SigningOptions, SigningMode } from './types';
import { sign, signDataUpdate } from './sign';

/**
 * Resolve the signing mode from options, supporting both legacy and new API.
 * Priority: options.mode > options.isDataUpdate > 'standard'
 */
function resolveMode(options: SigningOptions): SigningMode {
  if (options.mode) return options.mode;
  if (options.isDataUpdate) return 'dataUpdate';
  return 'standard';
}

/**
 * Create a signed object with a single signature
 *
 * @param value - Any JSON-serializable object
 * @param privateKey - Private key in hex format
 * @param options - Signing options
 * @returns Signed object ready for submission
 *
 * @example
 * ```typescript
 * // Sign a regular data object
 * const signed = createSignedObject(myData, privateKey);
 *
 * // Sign as DataUpdate for L1 submission (new API)
 * const signedUpdate = createSignedObject(myData, privateKey, { mode: 'dataUpdate' });
 *
 * // Legacy API still works
 * const signedLegacy = createSignedObject(myData, privateKey, { isDataUpdate: true });
 * ```
 */
export function createSignedObject<T>(
  value: T,
  privateKey: string,
  options: SigningOptions = {}
): Signed<T> {
  const mode = resolveMode(options);

  const proof = mode === 'dataUpdate'
    ? signDataUpdate(value, privateKey)
    : sign(value, privateKey);

  return {
    value,
    proofs: [proof],
    mode,
  };
}

/**
 * Add an additional signature to an existing signed object
 *
 * This allows building multi-signature objects where multiple parties
 * need to sign the same data.
 *
 * When no options are provided, inherits the mode from the existing signed object.
 *
 * @param signed - Existing signed object
 * @param privateKey - Private key in hex format
 * @param options - Signing options (if omitted, inherits mode from signed object)
 * @returns New signed object with additional proof
 *
 * @example
 * ```typescript
 * // First party signs
 * let signed = createSignedObject(data, party1Key);
 *
 * // Second party adds signature (inherits mode automatically)
 * signed = addSignature(signed, party2Key);
 *
 * // Now has 2 proofs
 * console.log(signed.proofs.length); // 2
 * ```
 */
export function addSignature<T>(
  signed: Signed<T>,
  privateKey: string,
  options?: SigningOptions
): Signed<T> {
  // Inherit mode from existing signed object if no options provided
  const mode = options ? resolveMode(options) : (signed.mode ?? 'standard');

  const newProof = mode === 'dataUpdate'
    ? signDataUpdate(signed.value, privateKey)
    : sign(signed.value, privateKey);

  return {
    value: signed.value,
    proofs: [...signed.proofs, newProof],
    mode,
  };
}

/**
 * Create a signed object with multiple signatures at once
 *
 * Useful when you have access to multiple private keys and want
 * to create a multi-sig object in one operation.
 *
 * @param value - Any JSON-serializable object
 * @param privateKeys - Array of private keys in hex format
 * @param options - Signing options
 * @returns Signed object with multiple proofs
 *
 * @example
 * ```typescript
 * const signed = batchSign(data, [key1, key2, key3]);
 * console.log(signed.proofs.length); // 3
 * ```
 */
export function batchSign<T>(
  value: T,
  privateKeys: string[],
  options: SigningOptions = {}
): Signed<T> {
  if (privateKeys.length === 0) {
    throw new Error('At least one private key is required');
  }

  const mode = resolveMode(options);

  const proofs: SignatureProof[] = privateKeys.map((key) =>
    mode === 'dataUpdate' ? signDataUpdate(value, key) : sign(value, key)
  );

  return {
    value,
    proofs,
    mode,
  };
}
