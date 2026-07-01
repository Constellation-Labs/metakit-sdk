/**
 * Committed-roots light-client codecs
 *
 * The constant-size on-chain commitment a syncing (light) client trusts: the
 * two-tier state-root pair a metagraph commits at each snapshot, plus the
 * validated commit-key universe for MPT state lookups.
 *
 * These are byte-for-byte aligned with the metakit (Scala) reference
 * (`lifecycle/committed/CommittedRoots.scala`, `CommitKey.scala`, verified by
 * `CommittedRootsCodecKatSuite`). See `docs/committed-roots.md` for the
 * light-client verification flow (anchor the roots via `combinedHash`, then
 * verify inclusion with the JLVM `smt_verify` / `mpt_verify` opcodes).
 *
 * Wire forms (matching the Scala circe codecs exactly):
 *   - `SparseMerkleRoot`     -> `{ "value": <hash-hex> }`
 *   - `CommittedRoots`       -> `{ "mptRoot": <hash-hex>, "catalogRoot": { "value": <hash-hex> } }`
 *   - `CommittedBreadcrumb`  -> `{ "ordinal": <number>, "roots": <CommittedRoots> }`
 *   - `CommitKey`            -> a bare validated string (e.g. `"fiber/abc-1"`)
 *
 * `mptRoot` is a bare hash hex (Scala `Hash`); `catalogRoot` is a
 * `SparseMerkleRoot` object; `ordinal` is a bare non-negative integer (Scala
 * `SnapshotOrdinal`, whose encoder is `Encoder[NonNegLong].contramap`).
 */

import { sha256Bytes, bytesToHex, hexToBytes } from './crypto';

/** A Sparse Merkle tree root — wire form `{ "value": <hash-hex> }`. */
export interface SparseMerkleRoot {
  /** Lowercase hex of the 32-byte root digest. */
  value: string;
}

/**
 * The two-tier commitment of a snapshot: the state-dict MPT root (tier 1) and
 * the live catalog root (tier 2 — the full-history epoch rollup).
 */
export interface CommittedRoots {
  /** State-dict MPT root, a bare hash hex (Scala `Hash`). */
  mptRoot: string;
  /** Catalog root (the full root-history rollup). */
  catalogRoot: SparseMerkleRoot;
}

/**
 * The constant-size on-chain breadcrumb: the {@link CommittedRoots} pair
 * committed at one ordinal. The latest signed breadcrumb transitively commits
 * the whole root history, so a light client obtains the catalog root in O(1).
 */
export interface CommittedBreadcrumb {
  /** Snapshot ordinal — a bare non-negative integer. */
  ordinal: number;
  roots: CommittedRoots;
}

/**
 * `sha256(rawBytes(mptRoot) ++ rawBytes(catalogRoot))` — the single hash binding
 * the pair, mpt first, both roots as their raw digest bytes. Returns the digest
 * as a lowercase hex string. This is exactly what a snapshot's on-chain
 * calculated-state proof anchors, so a light client checks a received breadcrumb
 * by comparing this against the snapshot's `calculatedStateHash`.
 *
 * @throws if either root is not valid hex.
 */
export function committedRootsCombinedHash(roots: CommittedRoots): string {
  const mpt = hexToBytes(roots.mptRoot);
  const cat = hexToBytes(roots.catalogRoot.value);
  const buf = new Uint8Array(mpt.length + cat.length);
  buf.set(mpt, 0);
  buf.set(cat, mpt.length);
  return bytesToHex(sha256Bytes(buf));
}

// --- codecs (canonical key order, matching Scala `.asJson.noSpaces`) ---

/** Serialize {@link CommittedRoots} in the reference key order `[mptRoot, catalogRoot]`. */
export function encodeCommittedRoots(roots: CommittedRoots): string {
  return JSON.stringify({
    mptRoot: roots.mptRoot,
    catalogRoot: { value: roots.catalogRoot.value },
  });
}

/** Parse and validate {@link CommittedRoots} from JSON (string or parsed object). */
export function decodeCommittedRoots(input: string | unknown): CommittedRoots {
  const obj = typeof input === 'string' ? JSON.parse(input) : input;
  if (obj === null || typeof obj !== 'object') {
    throw new Error('CommittedRoots: expected an object');
  }
  const rec = obj as Record<string, unknown>;
  const mptRoot = rec.mptRoot;
  const catalogRoot = rec.catalogRoot as Record<string, unknown> | undefined;
  if (typeof mptRoot !== 'string') {
    throw new Error('CommittedRoots: `mptRoot` must be a string');
  }
  if (
    catalogRoot === null ||
    typeof catalogRoot !== 'object' ||
    typeof catalogRoot.value !== 'string'
  ) {
    throw new Error('CommittedRoots: `catalogRoot.value` must be a string');
  }
  return { mptRoot, catalogRoot: { value: catalogRoot.value } };
}

/** Serialize {@link CommittedBreadcrumb} in the reference key order `[ordinal, roots]`. */
export function encodeCommittedBreadcrumb(b: CommittedBreadcrumb): string {
  return JSON.stringify({
    ordinal: b.ordinal,
    roots: { mptRoot: b.roots.mptRoot, catalogRoot: { value: b.roots.catalogRoot.value } },
  });
}

/** Parse and validate {@link CommittedBreadcrumb} from JSON (string or parsed object). */
export function decodeCommittedBreadcrumb(input: string | unknown): CommittedBreadcrumb {
  const obj = typeof input === 'string' ? JSON.parse(input) : input;
  if (obj === null || typeof obj !== 'object') {
    throw new Error('CommittedBreadcrumb: expected an object');
  }
  const rec = obj as Record<string, unknown>;
  const ordinal = rec.ordinal;
  if (typeof ordinal !== 'number' || !Number.isInteger(ordinal) || ordinal < 0) {
    throw new Error('CommittedBreadcrumb: `ordinal` must be a non-negative integer');
  }
  return { ordinal, roots: decodeCommittedRoots(rec.roots) };
}

// --- CommitKey: validated, namespaced path into the committed state dict ---

/** Reasons a string fails {@link CommitKey} validation (mirrors Scala `CommitKeyError`). */
export type CommitKeyErrorCode =
  | 'EMPTY_KEY'
  | 'KEY_TOO_LONG'
  | 'TOO_MANY_SEGMENTS'
  | 'EMPTY_SEGMENT'
  | 'SEGMENT_TOO_LONG'
  | 'INVALID_SEGMENT';

/** Error thrown when a commit key is malformed. */
export class CommitKeyError extends Error {
  constructor(
    readonly code: CommitKeyErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'CommitKeyError';
  }
}

const MAX_SEGMENT_LENGTH = 64;
const MAX_SEGMENTS = 16;
const MAX_KEY_LENGTH = 256;
const SEGMENT_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

function validateCommitKey(value: string): void {
  if (value.length === 0) {
    throw new CommitKeyError('EMPTY_KEY', 'commit key must not be empty');
  }
  if (value.length > MAX_KEY_LENGTH) {
    throw new CommitKeyError('KEY_TOO_LONG', `commit key exceeds ${MAX_KEY_LENGTH} chars: ${value.length}`);
  }
  const segments = value.split('/');
  if (value.startsWith('/') || value.endsWith('/') || segments.some((s) => s.length === 0)) {
    throw new CommitKeyError('EMPTY_SEGMENT', `commit key has an empty segment: '${value}'`);
  }
  if (segments.length > MAX_SEGMENTS) {
    throw new CommitKeyError('TOO_MANY_SEGMENTS', `commit key exceeds ${MAX_SEGMENTS} segments: ${segments.length}`);
  }
  for (const s of segments) {
    if (s.length > MAX_SEGMENT_LENGTH) {
      throw new CommitKeyError('SEGMENT_TOO_LONG', `commit key segment exceeds ${MAX_SEGMENT_LENGTH} chars: '${s}'`);
    }
    if (!SEGMENT_PATTERN.test(s)) {
      throw new CommitKeyError('INVALID_SEGMENT', `commit key segment must match ${SEGMENT_PATTERN.source}: '${s}'`);
    }
  }
}

/**
 * A validated, namespaced path into the committed state dictionary — the MPT
 * key universe. The MPT path of a key is the lowercase hex of its UTF-8 bytes
 * ({@link CommitKey.toHex}); because `/` is a single byte (0x2f), the hex of
 * `"ns/"` is a strict prefix of every key under namespace `ns`.
 */
export class CommitKey {
  private constructor(readonly value: string) {}

  /** Validate and construct. @throws {@link CommitKeyError} on malformed input. */
  static from(value: string): CommitKey {
    validateCommitKey(value);
    return new CommitKey(value);
  }

  /** True if `value` is a well-formed commit key. */
  static isValid(value: string): boolean {
    try {
      validateCommitKey(value);
      return true;
    } catch {
      return false;
    }
  }

  /** The MPT path: lowercase hex of the UTF-8 bytes of the key. */
  toHex(): string {
    return bytesToHex(new TextEncoder().encode(this.value));
  }

  /** The UTF-8 bytes of the key. */
  toBytes(): Uint8Array {
    return new TextEncoder().encode(this.value);
  }

  segments(): string[] {
    return this.value.split('/');
  }

  /** The top-level namespace (first segment). */
  get namespace(): string {
    return this.segments()[0];
  }

  toString(): string {
    return this.value;
  }
}
