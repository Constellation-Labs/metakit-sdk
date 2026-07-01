/**
 * Ordinal-catalog attestation verifier.
 *
 * Given a trusted catalog root (from a signed `CommittedBreadcrumb`) and the
 * chain-wide `epochSize`, verify an `OrdinalCatalogProof` — the catalog-side
 * attestation of "was an MPT root committed at snapshot ordinal N, and if so
 * which one?". Byte-for-byte aligned with the metakit (Scala) reference
 * (`lifecycle/committed/{CommitCatalog,OrdinalCatalogProof}.scala`), verified
 * against the shared `ordinal_catalog_test_vectors.json`. See
 * `docs/committed-roots.md`.
 *
 * The proof is a two-tier epoch rollup: the TOP catalog surfaces the hot-epoch
 * and level-1 (sealed) roots; a hot ordinal is one inclusion, an ancient ordinal
 * is two fixed-depth inclusions (level-1 -> sealed epoch tree), non-membership is
 * absence at both levels. Nothing inside the proof chooses which keys are
 * checked — they are recomputed locally from `ordinal` and `epochSize`, so a
 * prover cannot prove absence in the wrong epoch tree.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { checkSmtProof } from './crypto-ops';

// --- catalog key derivation (CommitCatalog) ---
// Every catalog SMT key is: lowercaseHex( SHA-256( UTF-8(name) ) ) — a 64-char
// hex string, no `0x`. Integers inside names are plain decimal, unpadded.

const bytesToHex = (bytes: Uint8Array): string => {
  let s = '';
  for (const b of bytes) {
    s += b.toString(16).padStart(2, '0');
  }
  return s;
};

const catalogKey = (name: string): string => bytesToHex(sha256(new TextEncoder().encode(name)));

const HOT_EPOCHS_KEY = catalogKey('epoch:hot');
const SEALED_EPOCHS_KEY = catalogKey('epoch:sealed');
const ordinalKey = (ordinal: bigint): string => catalogKey(`ordinal:${ordinal.toString()}`);
const epochKey = (epoch: bigint): string => catalogKey(`epoch:${epoch.toString()}`);

/**
 * `rootFromValueBytes`: the SMT leaf value bound to a child root is the raw 32
 * digest bytes, so the sub-tree root is their lowercase hex — a hex-encode, NOT
 * a hash.
 */
const rootFromValueBytes = (bytes: Uint8Array): string => bytesToHex(bytes);

// --- results ---

export type OrdinalAttestation =
  | { type: 'CommittedAt'; ordinal: bigint; mptRoot: string }
  | { type: 'NotCommitted'; ordinal: bigint };

export type OrdinalCatalogError =
  | { error: 'WrongProofKey'; component: string }
  | { error: 'ProofInvalid'; component: string }
  | { error: 'MalformedOrdinalProof'; reason: string };

export type OrdinalCatalogResult = OrdinalAttestation | OrdinalCatalogError;

/** True if a result is an error (rather than an attestation). */
export function isOrdinalCatalogError(r: OrdinalCatalogResult): r is OrdinalCatalogError {
  return 'error' in r;
}

const asObject = (v: unknown, ctx: string): Record<string, unknown> => {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new Error(`${ctx}: expected an object`);
  }
  return v as Record<string, unknown>;
};

/**
 * Verify an `OrdinalCatalogProof` against a trusted `catalogRoot` (raw lowercase
 * hex, no `0x`) under the chain-wide `epochSize`.
 *
 * Note: `ordinal` is a 64-bit value; it is read from the (already-parsed) proof
 * JSON. For ordinals beyond 2^53 the JSON must be parsed with a bigint-aware
 * parser upstream so the value reaches here intact.
 *
 * @throws on undecodable proof JSON or a non-positive `epochSize`.
 */
export function verifyOrdinalCatalogProof(
  catalogRoot: string,
  proof: unknown,
  epochSize: number | bigint
): OrdinalCatalogResult {
  const p = asObject(proof, 'OrdinalCatalogProof');
  const ordinalRaw = p.ordinal;
  if (typeof ordinalRaw !== 'number' && typeof ordinalRaw !== 'bigint') {
    throw new Error('OrdinalCatalogProof: `ordinal` must be an integer');
  }
  const ordinal = BigInt(ordinalRaw);
  const es = BigInt(epochSize);
  if (es <= 0n) {
    throw new Error('epochSize must be positive');
  }
  const epoch = ordinal / es; // floor division for non-negative ordinals

  // 1. topHot -> the hot epoch tree root (must be an inclusion in the top catalog).
  const topHot = checkSmtProof(catalogRoot, p.topHot, HOT_EPOCHS_KEY);
  if (topHot.status === 'wrongKey') return { error: 'WrongProofKey', component: 'topHot' };
  if (topHot.status === 'invalid') return { error: 'ProofInvalid', component: 'topHot' };
  if (topHot.status === 'absent') {
    return {
      error: 'MalformedOrdinalProof',
      reason: 'topHot must be an inclusion in the top catalog',
    };
  }
  const hotRoot = rootFromValueBytes(topHot.value);

  // 2. topSealed -> the level-1 (sealed epochs) tree root (must be an inclusion).
  const topSealed = checkSmtProof(catalogRoot, p.topSealed, SEALED_EPOCHS_KEY);
  if (topSealed.status === 'wrongKey') return { error: 'WrongProofKey', component: 'topSealed' };
  if (topSealed.status === 'invalid') return { error: 'ProofInvalid', component: 'topSealed' };
  if (topSealed.status === 'absent') {
    return {
      error: 'MalformedOrdinalProof',
      reason: 'topSealed must be an inclusion in the top catalog',
    };
  }
  const level1Root = rootFromValueBytes(topSealed.value);

  // 3. hot: is the ordinal in the current hot epoch?
  const hot = checkSmtProof(hotRoot, p.hot, ordinalKey(ordinal));
  if (hot.status === 'wrongKey') return { error: 'WrongProofKey', component: 'hot' };
  if (hot.status === 'invalid') return { error: 'ProofInvalid', component: 'hot' };
  if (hot.status === 'present') {
    return { type: 'CommittedAt', ordinal, mptRoot: rootFromValueBytes(hot.value) };
  }

  // hot-absent -> 4. level1: was the ordinal's epoch ever sealed?
  const level1 = checkSmtProof(level1Root, p.level1, epochKey(epoch));
  if (level1.status === 'wrongKey') return { error: 'WrongProofKey', component: 'level1' };
  if (level1.status === 'invalid') return { error: 'ProofInvalid', component: 'level1' };
  if (level1.status === 'absent') {
    // hot-absent AND the epoch was never sealed => provably not committed.
    return { type: 'NotCommitted', ordinal };
  }
  const sealedRoot = rootFromValueBytes(level1.value);

  // 5. sealedEntry: inclusion of the ordinal inside its sealed epoch tree.
  if (p.sealedEntry === null || p.sealedEntry === undefined) {
    return {
      error: 'MalformedOrdinalProof',
      reason: `epoch ${epoch} is sealed; a sealedEntry proof is required`,
    };
  }
  const sealed = checkSmtProof(sealedRoot, p.sealedEntry, ordinalKey(ordinal));
  if (sealed.status === 'wrongKey') return { error: 'WrongProofKey', component: 'sealedEntry' };
  if (sealed.status === 'invalid') return { error: 'ProofInvalid', component: 'sealedEntry' };
  if (sealed.status === 'present') {
    return { type: 'CommittedAt', ordinal, mptRoot: rootFromValueBytes(sealed.value) };
  }
  return { type: 'NotCommitted', ordinal };
}

/** The catalog keys, exposed for testing / advanced callers. */
export const catalogKeys = {
  hotEpochsKey: HOT_EPOCHS_KEY,
  sealedEpochsKey: SEALED_EPOCHS_KEY,
  ordinalKey,
  epochKey,
} as const;
