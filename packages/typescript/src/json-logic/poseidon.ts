/**
 * Poseidon hash over the BN254 / alt_bn128 scalar field (Fr) and the
 * authentication-path fold of the fixed-depth Poseidon Merkle tree.
 *
 * Byte-for-byte port of rust/poseidon-bn254 (`lib.rs` + `merkle.rs`), itself a
 * port of metakit's circomlib-compatible Scala `Poseidon` /
 * `PoseidonMerkleTree`. All arithmetic is plain bigint reduced mod R — no
 * Montgomery form — guaranteeing identical outputs across all three impls.
 *
 * Construction (identical to circomlib's `poseidon([...])`):
 *   - S-box `x^5`, RF = 8 full rounds, RP partial rounds (per width t);
 *   - state initialised as `[0, in_0, ..., in_{n-1}]` (capacity element = 0),
 *     width `t = n + 1`;
 *   - the permutation runs once and `state[0]` is returned.
 *
 * HARD ACCEPTANCE VECTOR (circomlibjs):
 *   poseidon([1, 2]) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
 */

import { JsonLogicRuntimeError } from './errors';
import {
  FULL_ROUNDS,
  MAX_WIDTH,
  MDS_MATRIX,
  PARTIAL_ROUNDS,
  ROUND_CONSTANTS,
} from './poseidon-constants';

/** The BN254 (alt_bn128) scalar field modulus R. */
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Maximum number of inputs supported (width t = n + 1, bundled t <= 5). */
export const MAX_INPUTS = MAX_WIDTH - 1;

const fail = (message: string): never => {
  throw new JsonLogicRuntimeError(message);
};

/** `x^5 mod R`, the Poseidon S-box. */
const pow5 = (a: bigint): bigint => {
  const a2 = (a * a) % R;
  const a4 = (a2 * a2) % R;
  return (a4 * a) % R;
};

/**
 * Hash a list of canonical Fr elements with circomlib semantics. Errors on an
 * empty list, more than MAX_INPUTS inputs, or a non-canonical element
 * (mirroring the Scala `require`s / Rust asserts, surfaced as eval errors).
 */
export const poseidonHash = (inputs: ReadonlyArray<bigint>): bigint => {
  if (inputs.length === 0) {
    return fail('Poseidon hash requires at least one input');
  }
  const t = inputs.length + 1;
  if (t > MAX_WIDTH) {
    return fail(
      `Poseidon hash supports at most ${MAX_INPUTS} inputs (width t <= ${MAX_WIDTH}); got ${inputs.length}`
    );
  }
  inputs.forEach((x, i) => {
    if (x < 0n || x >= R) {
      fail(`Poseidon input[${i}] is not a canonical BN254 field element (must be in [0, R)): ${x}`);
    }
  });

  const c = ROUND_CONSTANTS.get(t);
  const m = MDS_MATRIX.get(t);
  if (c === undefined || m === undefined) {
    return fail(`Poseidon width t=${t} unsupported`);
  }
  const rp = PARTIAL_ROUNDS[t];
  const totalRounds = FULL_ROUNDS + rp;
  const halfRf = FULL_ROUNDS / 2;

  // State is [capacity=0, in_0, in_1, ...].
  let s: bigint[] = [0n, ...inputs];

  for (let round = 0; round < totalRounds; round++) {
    // ARK: add round constants.
    const afterArk: bigint[] = s.map((x, i) => (x + c[round * t + i]) % R);

    // S-box: full rounds apply x^5 to every element; partial rounds only to state[0].
    const isFullRound = round < halfRf || round >= halfRf + rp;
    if (isFullRound) {
      for (let i = 0; i < t; i++) {
        afterArk[i] = pow5(afterArk[i]);
      }
    } else {
      afterArk[0] = pow5(afterArk[0]);
    }

    // Mix: state[i] = sum_j M[i][j] * state[j].
    const mixed: bigint[] = new Array<bigint>(t);
    for (let i = 0; i < t; i++) {
      let acc = 0n;
      const row = m[i];
      for (let j = 0; j < t; j++) {
        acc = (acc + row[j] * afterArk[j]) % R;
      }
      mixed[i] = acc;
    }
    s = mixed;
  }

  return s[0];
};

/** Convenience 2-to-1 compression (width t = 3) for Merkle node hashing. */
export const poseidonCompress = (left: bigint, right: bigint): bigint =>
  poseidonHash([left, right]);

/**
 * Fold `leaf` up an authentication path and return the recomputed root.
 * Port of rust/poseidon-bn254 `merkle::compute_root`: `siblings` is ROOT-FIRST
 * (top-down) and consumed in reverse (bottom-up); bit `i` of `position`
 * (LSB-first, level 0 adjacent to the leaf) selects left/right:
 *   - bit==0 => path node is the LEFT child:  parent = compress(current, sibling)
 *   - bit==1 => path node is the RIGHT child: parent = compress(sibling, current)
 */
export const merkleComputeRoot = (
  leaf: bigint,
  position: bigint,
  siblings: ReadonlyArray<bigint>
): bigint => {
  const depth = siblings.length;
  if (position < 0n || position >= 1n << BigInt(depth)) {
    return fail(`proof position out of range for depth ${depth}: ${position}`);
  }
  let current = leaf;
  for (let level = 0; level < depth; level++) {
    const sibling = siblings[depth - 1 - level]; // root-first -> bottom-up
    const bit = (position >> BigInt(level)) & 1n;
    current = bit === 1n ? poseidonCompress(sibling, current) : poseidonCompress(current, sibling);
  }
  return current;
};

/** Verify an INCLUSION proof: `leaf` is committed at `position` under `root`. */
export const merkleVerifyInclusion = (
  leaf: bigint,
  position: bigint,
  siblings: ReadonlyArray<bigint>,
  root: bigint
): boolean => merkleComputeRoot(leaf, position, siblings) === root;
