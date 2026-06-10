/**
 * Pure, deterministic implementations of the JLVM ZK / crypto opcodes that the
 * TypeScript evaluator supports: `poseidon`, `pmt_verify`, `schnorr_verify`,
 * `bls_verify`, `bls_aggregate_verify`.
 *
 * Byte-for-byte port of rust/jlvm-core/src/crypto.rs (itself a port of the
 * Scala `json_logic.ops.CryptoOps`):
 *   - every malformed input (bad hex, wrong width, non-canonical field
 *     element, wrong arg count/type) throws — surfaced as a normal evaluation
 *     error;
 *   - a well-formed-but-wrong proof / signature simply verifies to `false`.
 *
 * BLS12-381 verification (eth2 / IETF ProofOfPossession ciphersuite,
 * minimal-pubkey-size: 48B G1 pubkeys, 96B G2 signatures, DST
 * BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_) is backed by @noble/curves,
 * matching blst (Rust) and BouncyCastle (Scala) against the published
 * ethereum/bls12-381-tests vectors. BN254 G1 arithmetic for `schnorr_verify`
 * is implemented directly over bigint (affine, cofactor-1 curve y^2 = x^3 + 3,
 * generator (1, 2), EVM (0,0)-infinity convention).
 */

import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { JsonLogicRuntimeError } from './errors';
import type { JsonLogicValue } from './value';
import { boolValue, strValue } from './value';
import * as hb from './hex-bytes';
import { MAX_INPUTS, merkleVerifyInclusion, poseidonHash } from './poseidon';

const fail = (message: string): never => {
  throw new JsonLogicRuntimeError(message);
};

// ---------------------------------------------------------------------------
// Shared argument helpers (mirroring CryptoOps.expectStr / expectIndex).
// ---------------------------------------------------------------------------

const expectStr = (role: string, v: JsonLogicValue): string => {
  if (v.tag === 'string') return v.value;
  return fail(`${role}: expected a hex string, got ${v.tag}`);
};

const expectIndex = (role: string, v: JsonLogicValue): bigint => {
  if (v.tag === 'int') {
    if (v.value < 0n) return fail(`${role}: must be non-negative, got ${v.value}`);
    return v.value;
  }
  return fail(`${role}: expected a non-negative integer, got ${v.tag}`);
};

// ---------------------------------------------------------------------------
// poseidon: variadic field elements -> Fr hash (32B hex).
// ---------------------------------------------------------------------------

/** `poseidon([hexFr, ...]) -> hexFr`. Mirrors Rust `crypto::poseidon`. */
export const opPoseidon = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length === 0) {
    return fail('poseidon: requires at least one field element');
  }
  let hexes: string[];
  if (values.length === 1 && values[0].tag === 'array' && values[0].value.length > 0) {
    hexes = values[0].value.map((v) => expectStr('poseidon input', v));
  } else {
    hexes = values.map((v) => expectStr('poseidon input', v));
  }
  if (hexes.length === 0) {
    return fail('poseidon: requires at least one field element');
  }
  if (hexes.length > MAX_INPUTS) {
    return fail(`poseidon: supports at most ${MAX_INPUTS} inputs, got ${hexes.length}`);
  }
  const inputs = hexes.map((h, i) => hb.parseFr(h, `poseidon input[${i}]`));
  return strValue(hb.encodeFr(poseidonHash(inputs)));
};

// ---------------------------------------------------------------------------
// pmt_verify: [root, leaf, index, [siblings...]] -> bool.
// ---------------------------------------------------------------------------

/** `pmt_verify([rootHex, leafHex, index, [siblingsHex]]) -> bool`. */
export const opPmtVerify = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length === 4 && values[3].tag === 'array') {
    const root = hb.parseFr(expectStr('pmt_verify root', values[0]), 'pmt_verify root');
    const leaf = hb.parseFr(expectStr('pmt_verify leaf', values[1]), 'pmt_verify leaf');
    const index = expectIndex('pmt_verify index', values[2]);
    const siblings = values[3].value.map((s, i) =>
      hb.parseFr(expectStr(`pmt_verify sibling[${i}]`, s), `pmt_verify sibling[${i}]`)
    );
    const depth = siblings.length;
    if (index >= 1n << BigInt(depth)) {
      return fail(`pmt_verify: index ${index} out of range for depth ${depth}`);
    }
    return boolValue(merkleVerifyInclusion(leaf, index, siblings, root));
  }
  return fail('pmt_verify: expected [rootHex, leafHex, index, [siblingHex...]]');
};

// ---------------------------------------------------------------------------
// BN254 G1 affine arithmetic (cofactor 1; y^2 = x^3 + 3 over Fq; G = (1, 2);
// the all-zero point (0, 0) is the EVM point-at-infinity).
// ---------------------------------------------------------------------------

const P = hb.FQ_MODULUS;
const GROUP_ORDER = hb.FR_MODULUS;

interface G1 {
  readonly x: bigint;
  readonly y: bigint;
  readonly inf: boolean;
}

const G1_INF: G1 = { x: 0n, y: 0n, inf: true };
const G1_GEN: G1 = { x: 1n, y: 2n, inf: false };

const modP = (a: bigint): bigint => ((a % P) + P) % P;

/** Modular inverse via extended Euclid (P is prime; a != 0 mod P). */
const invP = (a: bigint): bigint => {
  let [old_r, r] = [modP(a), P];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return modP(old_s);
};

const g1Double = (p: G1): G1 => {
  if (p.inf || p.y === 0n) return G1_INF;
  const lambda = modP(3n * p.x * p.x * invP(2n * p.y));
  const x = modP(lambda * lambda - 2n * p.x);
  const y = modP(lambda * (p.x - x) - p.y);
  return { x, y, inf: false };
};

const g1Add = (a: G1, b: G1): G1 => {
  if (a.inf) return b;
  if (b.inf) return a;
  if (a.x === b.x) {
    if (a.y === b.y) return g1Double(a);
    return G1_INF; // a == -b
  }
  const lambda = modP((b.y - a.y) * invP(b.x - a.x));
  const x = modP(lambda * lambda - a.x - b.x);
  const y = modP(lambda * (a.x - x) - a.y);
  return { x, y, inf: false };
};

/** Scalar multiply with the scalar reduced mod R (matches `Bn254.G1.multiply`). */
const g1Mul = (p: G1, scalar: bigint): G1 => {
  let k = scalar % GROUP_ORDER;
  let acc = G1_INF;
  let base = p;
  while (k > 0n) {
    if (k & 1n) acc = g1Add(acc, base);
    base = g1Double(base);
    k >>= 1n;
  }
  return acc;
};

/**
 * Build an on-curve G1 point from parsed `(x, y)`; reject off-curve points.
 * The all-zero point (0, 0) is the EVM point-at-infinity (on-curve identity).
 * BN254 G1 has cofactor 1, so on-curve implies in-subgroup.
 */
const g1OnCurve = (coords: { x: bigint; y: bigint }, role: string): G1 => {
  const { x, y } = coords;
  if (x === 0n && y === 0n) return G1_INF;
  if (modP(y * y) === modP(x * x * x + 3n)) {
    return { x, y, inf: false };
  }
  return fail(`${role}: point is not on the BN254 curve`);
};

/** Equality on the EVM convention: infinity renders as (0, 0). */
const g1Eq = (a: G1, b: G1): boolean => {
  const ax = a.inf ? 0n : a.x;
  const ay = a.inf ? 0n : a.y;
  const bx = b.inf ? 0n : b.x;
  const by = b.inf ? 0n : b.y;
  return ax === bx && ay === by;
};

// ---------------------------------------------------------------------------
// schnorr_verify: [pkHex(64B G1), msgHex, proofHex(96B)] -> bool.
//   proof = R(64B) || s(32B); challenge c = SHA256(R || pk || msg) mod r;
//   accept iff s*G == R + c*pk.
// ---------------------------------------------------------------------------

/** `schnorr_verify([pkHex(64B), msgHex, proofHex(96B)]) -> bool`. */
export const opSchnorrVerify = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length !== 3) {
    return fail('schnorr_verify: expected [pkHex(64B), msgHex, proofHex(96B)]');
  }
  const pkHex = expectStr('schnorr_verify pk', values[0]);
  const msgHex = expectStr('schnorr_verify msg', values[1]);
  const proofHex = expectStr('schnorr_verify proof', values[2]);

  const pkCoords = hb.parseG1(pkHex, 'schnorr_verify pk');
  const msg = hb.parseBytes(msgHex, null, 'schnorr_verify msg');
  const proof = hb.parseBytes(proofHex, hb.G1_BYTES + hb.SCALAR_BYTES, 'schnorr_verify proof');
  const rBytes = proof.subarray(0, hb.G1_BYTES);
  const sBytes = proof.subarray(hb.G1_BYTES, hb.G1_BYTES + hb.SCALAR_BYTES);

  const rCoords = hb.parseG1(hb.encodeBytes(rBytes), 'schnorr_verify R');
  const s = hb.bytesToBigInt(sBytes);

  // On-curve checks (the all-zero point (0,0) is the on-curve infinity).
  const pk = g1OnCurve(pkCoords, 'schnorr_verify pk');
  const r = g1OnCurve(rCoords, 'schnorr_verify R');

  // SOUNDNESS: reject the identity / point-at-infinity public key — with
  // pk = O the equation collapses to s*G == R, a universal forgery. The
  // identity pk is correct-width but cryptographically invalid: `false`,
  // NOT an error (malformed-width inputs error above). Mirrors Rust.
  if (pk.inf) {
    return boolValue(false);
  }

  // c = SHA256(R || pk || msg) mod groupOrder
  const pkBytes = hb.parseBytes(pkHex, hb.G1_BYTES, 'schnorr_verify pk');
  const preimage = new Uint8Array(rBytes.length + pkBytes.length + msg.length);
  preimage.set(rBytes, 0);
  preimage.set(pkBytes, rBytes.length);
  preimage.set(msg, rBytes.length + pkBytes.length);
  const c = hb.bytesToBigInt(sha256(preimage)) % GROUP_ORDER;

  // accept iff s*G == R + c*pk
  const lhs = g1Mul(G1_GEN, s % GROUP_ORDER);
  const rhs = g1Add(r, g1Mul(pk, c));
  return boolValue(g1Eq(lhs, rhs));
};

// ---------------------------------------------------------------------------
// BLS12-381 signatures (eth2 / IETF PoP ciphersuite, minimal-pubkey-size).
// ---------------------------------------------------------------------------

const BLS_PUBLIC_KEY_BYTES = 48;
const BLS_SIGNATURE_BYTES = 96;
const BLS_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';

const blsSigs = bls12_381.longSignatures;

/**
 * Verify one signature; `false` (never a throw) on any malformed /
 * non-canonical / wrong-subgroup point or failed check. The infinity pubkey
 * is rejected (`false`), matching blst's `key_validate` / BC's decompressG1.
 */
const blsVerifyRaw = (pk: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean => {
  if (pk.length !== BLS_PUBLIC_KEY_BYTES || sig.length !== BLS_SIGNATURE_BYTES) {
    return false;
  }
  try {
    const pkPoint = bls12_381.G1.Point.fromBytes(pk);
    if (pkPoint.is0()) return false;
    const msgPoint = blsSigs.hash(message, BLS_DST);
    return blsSigs.verify(sig, msgPoint, pkPoint);
  } catch {
    return false;
  }
};

/**
 * Same-message fastAggregateVerify: decompress + subgroup-check every pubkey,
 * aggregate, verify once. `false` (never a throw) on an empty list, any bad
 * point, or a failed pairing check.
 */
const blsFastAggregateVerifyRaw = (
  pks: Uint8Array[],
  message: Uint8Array,
  agg: Uint8Array
): boolean => {
  if (pks.length === 0 || agg.length !== BLS_SIGNATURE_BYTES) {
    return false;
  }
  try {
    const points = pks.map((pk) => {
      if (pk.length !== BLS_PUBLIC_KEY_BYTES) {
        throw new Error('bad pk width');
      }
      const p = bls12_381.G1.Point.fromBytes(pk);
      if (p.is0()) {
        throw new Error('infinity pk');
      }
      return p;
    });
    const aggPk = points.reduce((a, b) => a.add(b));
    const msgPoint = blsSigs.hash(message, BLS_DST);
    return blsSigs.verify(agg, msgPoint, aggPk);
  } catch {
    return false;
  }
};

/**
 * `bls_verify([pkHex(48B), msgHex, sigHex(96B)]) -> bool`. Wrong WIDTH pk/sig
 * is an error (like Scala/Rust); a bad point or failed check is `false`.
 */
export const opBlsVerify = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length !== 3) {
    return fail('bls_verify: expected [pkHex(48B), msgHex, sigHex(96B)]');
  }
  const pk = hb.parseBytes(
    expectStr('bls_verify pk', values[0]),
    BLS_PUBLIC_KEY_BYTES,
    'bls_verify pk'
  );
  const msg = hb.parseBytes(expectStr('bls_verify msg', values[1]), null, 'bls_verify msg');
  const sig = hb.parseBytes(
    expectStr('bls_verify sig', values[2]),
    BLS_SIGNATURE_BYTES,
    'bls_verify sig'
  );
  return boolValue(blsVerifyRaw(pk, msg, sig));
};

/**
 * `bls_aggregate_verify([[pkHex(48B), ...], msgHex, aggSigHex(96B)]) -> bool`.
 * Empty pubkey list / wrong widths are errors; bad points or a failed pairing
 * check are `false`.
 */
export const opBlsAggregateVerify = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length === 3 && values[0].tag === 'array') {
    const pksV = values[0].value;
    if (pksV.length === 0) {
      return fail('bls_aggregate_verify: at least one public key required');
    }
    const pks = pksV.map((pkV, i) => {
      const role = `bls_aggregate_verify pk[${i}]`;
      return hb.parseBytes(expectStr(role, pkV), BLS_PUBLIC_KEY_BYTES, role);
    });
    const msg = hb.parseBytes(
      expectStr('bls_aggregate_verify msg', values[1]),
      null,
      'bls_aggregate_verify msg'
    );
    const agg = hb.parseBytes(
      expectStr('bls_aggregate_verify aggSig', values[2]),
      BLS_SIGNATURE_BYTES,
      'bls_aggregate_verify aggSig'
    );
    return boolValue(blsFastAggregateVerifyRaw(pks, msg, agg));
  }
  return fail('bls_aggregate_verify: expected [[pkHex(48B), ...], msgHex, aggSigHex(96B)]');
};
