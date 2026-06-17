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

/**
 * Reject a NON-CANONICAL response scalar (`z`/`s` >= R) as a hard error (audit #4). A response is a
 * curve scalar, so `z` and `z + R` are congruent mod R and verify identically; accepting raw 32-byte
 * responses makes the proof bytes malleable. Requiring `z < R` makes the response encoding canonical.
 * Mirrors the Scala/Rust `requireCanonicalScalar`. (Challenges are already canonical: 31 bytes < R.)
 */
const requireCanonicalScalar = (z: bigint, role: string): bigint =>
  z < GROUP_ORDER ? z : fail(`${role}: non-canonical response scalar (must be < R)`);

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

/** Point negation: `-P = (x, -y)`. Infinity negates to itself. */
const g1Negate = (p: G1): G1 => (p.inf ? G1_INF : { x: p.x, y: modP(-p.y), inf: false });

/** Re-encode an on-curve G1 point to its canonical 64-byte big-endian bytes. */
const encodeG1Bytes = (p: G1): Uint8Array => {
  const x = p.inf ? 0n : p.x;
  const y = p.inf ? 0n : p.y;
  return hb.parseBytes(hb.encodeG1(x, y), hb.G1_BYTES, 'encodeG1Bytes');
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
  const s = requireCanonicalScalar(hb.bytesToBigInt(sBytes), 'schnorr_verify s');

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

// ===========================================================================
// SIGMA PROTOCOLS (classical, no-trusted-setup, Ergo / EIP-11 family).
//   Byte-for-byte port of the Rust crypto.rs Sigma section (itself a port of
//   the Scala CryptoOps Sigma object):
//     - prove_dlog_verify    : first-class ALIAS for schnorr_verify (DLog leaf).
//     - prove_dhtuple_verify : the DDH / Diffie-Hellman-tuple Σ-leaf.
//     - sigma_verify         : the recursive CDS proposition verifier
//                              (AND / OR / THRESHOLD), strong Fiat-Shamir over
//                              the FROZEN serialization.
// ===========================================================================

// ---------------------------------------------------------------------------
// prove_dlog_verify: [pkHex(64B G1), msgHex, proofHex(96B)] -> bool.
//   First-class sigma-leaf ALIAS for schnorr_verify (identical inputs and
//   semantics). The only difference is the error-message role label, matching
//   Rust `.map_err(|e| e.replace("schnorr_verify", "prove_dlog_verify"))`.
// ---------------------------------------------------------------------------

/** `prove_dlog_verify([pkHex(64B), msgHex, proofHex(96B)]) -> bool`. */
export const opProveDlogVerify = (values: JsonLogicValue[]): JsonLogicValue => {
  try {
    return opSchnorrVerify(values);
  } catch (e) {
    if (e instanceof JsonLogicRuntimeError) {
      throw new JsonLogicRuntimeError(e.message.replace('schnorr_verify', 'prove_dlog_verify'));
    }
    throw e;
  }
};

// ---------------------------------------------------------------------------
// prove_dhtuple_verify:
//   [gHex(64B), hHex(64B), uHex(64B), vHex(64B), msgHex, proofHex(160B)] -> bool.
//   DDH / Diffie-Hellman-tuple Σ-leaf on BN254 G1. Statement (g,h,u,v) ∈ G1⁴,
//   claim ∃w. u = g^w ∧ v = h^w. Convention:
//     proof = a1(64B) || a2(64B) || z(32B)   (total 160 bytes)
//     STRONG Fiat-Shamir: e = SHA256(g‖h‖u‖v‖a1‖a2‖msg) mod R
//     accept iff  z·g == a1 + e·u  AND  z·h == a2 + e·v
// ---------------------------------------------------------------------------

/** Total proof width: a1(64B) || a2(64B) || z(32B). */
const DHTUPLE_PROOF_BYTES = hb.G1_BYTES + hb.G1_BYTES + hb.SCALAR_BYTES;

/** `prove_dhtuple_verify([gHex, hHex, uHex, vHex, msgHex, proofHex(160B)]) -> bool`. */
export const opProveDhtupleVerify = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length !== 6) {
    return fail(
      'prove_dhtuple_verify: expected [gHex(64B), hHex(64B), uHex(64B), vHex(64B), msgHex, proofHex(160B)]'
    );
  }
  const gHex = expectStr('prove_dhtuple_verify g', values[0]);
  const hHex = expectStr('prove_dhtuple_verify h', values[1]);
  const uHex = expectStr('prove_dhtuple_verify u', values[2]);
  const vHex = expectStr('prove_dhtuple_verify v', values[3]);
  const msgHex = expectStr('prove_dhtuple_verify msg', values[4]);
  const proofHex = expectStr('prove_dhtuple_verify proof', values[5]);

  const gCoords = hb.parseG1(gHex, 'prove_dhtuple_verify g');
  const hCoords = hb.parseG1(hHex, 'prove_dhtuple_verify h');
  const uCoords = hb.parseG1(uHex, 'prove_dhtuple_verify u');
  const vCoords = hb.parseG1(vHex, 'prove_dhtuple_verify v');
  const msg = parseSigmaMessage(msgHex, 'prove_dhtuple_verify msg');
  // proof = a1(64B) || a2(64B) || z(32B) -> total 160 bytes.
  const proof = hb.parseBytes(proofHex, DHTUPLE_PROOF_BYTES, 'prove_dhtuple_verify proof');
  const a1Bytes = proof.subarray(0, hb.G1_BYTES);
  const a2Bytes = proof.subarray(hb.G1_BYTES, hb.G1_BYTES * 2);
  const zBytes = proof.subarray(hb.G1_BYTES * 2, DHTUPLE_PROOF_BYTES);

  const a1Coords = hb.parseG1(hb.encodeBytes(a1Bytes), 'prove_dhtuple_verify a1');
  const a2Coords = hb.parseG1(hb.encodeBytes(a2Bytes), 'prove_dhtuple_verify a2');
  const z = requireCanonicalScalar(hb.bytesToBigInt(zBytes), 'prove_dhtuple_verify z');

  const g = g1OnCurve(gCoords, 'prove_dhtuple_verify g');
  const h = g1OnCurve(hCoords, 'prove_dhtuple_verify h');
  const u = g1OnCurve(uCoords, 'prove_dhtuple_verify u');
  const v = g1OnCurve(vCoords, 'prove_dhtuple_verify v');
  const a1 = g1OnCurve(a1Coords, 'prove_dhtuple_verify a1');
  const a2 = g1OnCurve(a2Coords, 'prove_dhtuple_verify a2');

  // SOUNDNESS: reject the identity on any of the four statement points
  // (g/h base => equation collapse, u/v image => degenerate hiding). a1/a2 may
  // legitimately be the identity (r ≡ 0). Correct-WIDTH but cryptographically
  // invalid -> false, NOT an error.
  if (g.inf || h.inf || u.inf || v.inf) {
    return boolValue(false);
  }

  // STRONG Fiat-Shamir: bind the full statement AND both commitments AND the
  // message. Re-encode each statement point to its canonical fixed-width 64-byte
  // form; a1/a2 are taken as their raw proof bytes (already 64B).
  const gBytes = hb.parseBytes(gHex, hb.G1_BYTES, 'prove_dhtuple_verify g');
  const hBytes = hb.parseBytes(hHex, hb.G1_BYTES, 'prove_dhtuple_verify h');
  const uBytes = hb.parseBytes(uHex, hb.G1_BYTES, 'prove_dhtuple_verify u');
  const vBytes = hb.parseBytes(vHex, hb.G1_BYTES, 'prove_dhtuple_verify v');
  const preimage = new Uint8Array(
    gBytes.length +
      hBytes.length +
      uBytes.length +
      vBytes.length +
      a1Bytes.length +
      a2Bytes.length +
      msg.length
  );
  let off = 0;
  for (const part of [gBytes, hBytes, uBytes, vBytes, a1Bytes, a2Bytes, msg]) {
    preimage.set(part, off);
    off += part.length;
  }
  const e = hb.bytesToBigInt(sha256(preimage)) % GROUP_ORDER;

  // accept iff z·g == a1 + e·u  AND  z·h == a2 + e·v
  const zr = z % GROUP_ORDER;
  const lhs1 = g1Mul(g, zr);
  const rhs1 = g1Add(g1Mul(u, e), a1);
  const lhs2 = g1Mul(h, zr);
  const rhs2 = g1Add(g1Mul(v, e), a2);
  return boolValue(g1Eq(lhs1, rhs1) && g1Eq(lhs2, rhs2));
};

// ===========================================================================
// sigma_verify: the RECURSIVE CDS Σ-protocol proposition verifier.
//
//   {"sigma_verify": [ <proposition>, <proof>, <messageHex> ]} -> bool
//
// Byte-for-byte port of the Rust crypto.rs sigma_verify. The FROZEN canonical
// serialization MUST match the Rust/Scala byte layout exactly — it is the
// strong-FS transcript.
//
//   Node tags: dlog=0x00, dhtuple=0x01, and=0x02, or=0x03, threshold=0x04.
//   k and every child-count: 4-byte big-endian.
//   Points (pk,g,h,u,v and reconstructed a/a1/a2): canonical 64-byte x‖y.
//   Root challenge := low31( SHA256( DomainSep ‖ serializeTree(root) ‖ message ) ),
//   DomainSep = ascii("sigma_verify:v1").
//
// CHALLENGE DOMAIN: 31-byte (248-bit) values, NOT 32-byte. `2^248 < R`, so the
// byte↔Fr-scalar map `e ↦ bytesToBigInt(e)` is a BIJECTION onto `[0, 2^248)`
// (no raw-vs-mod-R duality). The SAME 31-byte value is the GF(2)^248 / XOR
// object AND, unchanged (no mod R), the Fr scalar `z·G − e·pk`.
//
// ERROR-VS-FALSE: malformed (bad hex/width, off-curve, structurally invalid
// tree, k<=0 or k>n, prop/proof shape mismatch) => throw. Well-formed-but-
// cryptographically-wrong (root hash mismatch, OR challenges don't XOR,
// threshold doesn't interpolate, identity statement point) => false.
// ===========================================================================

const SIGMA_TAG_DLOG = 0x00;
const SIGMA_TAG_DHTUPLE = 0x01;
const SIGMA_TAG_AND = 0x02;
const SIGMA_TAG_OR = 0x03;
const SIGMA_TAG_THRESHOLD = 0x04;

/** Domain separator for the sigma_verify root hash. */
const SIGMA_DOMAIN_SEP = new TextEncoder().encode('sigma_verify:v1');

/**
 * Fixed challenge width in bytes — 31 (248-bit), the INJECTIVE-into-Fr domain.
 * `2^248 < R`, so a 31-byte challenge is always a canonical Fr element and the
 * byte↔scalar map is a bijection.
 */
const SIGMA_CHALLENGE_BYTES = 31;

/**
 * Absolute backstop on a sigma tree's size/depth (DoS bound). Applied to BOTH the proposition
 * (before its recursive parse — IMPL-1) and the proof. The gas estimator bounds its proposition
 * shape walk with the same depth.
 */
const SIGMA_MAX_PROOF_NODES = 4096;
const SIGMA_MAX_PROOF_DEPTH = 64;

/**
 * IMPL-3 (DoS): absolute cap on a sigma message length, in bytes. The message is hashed into the
 * challenge but is NOT part of the gas-priced proposition shape; without a cap a caller could force
 * unbounded hex-decode + SHA-256 work outside the Sigma-tree pricing. Shared by `sigma_verify` and
 * `prove_dhtuple_verify`. Byte-for-byte the Scala `CryptoOps.SigmaMaxMessageBytes`.
 */
const SIGMA_MAX_MESSAGE_BYTES = 4096;

/**
 * Canonical challenge derivation: the LOW-ORDER 31 bytes of a 32-byte SHA-256
 * digest (`digest[1..]`). Result is in `[0, 2^248)`, a canonical Fr element.
 * Mirrors Rust `sigma_low31`.
 */
const sigmaLow31 = (digest32: Uint8Array): Uint8Array =>
  digest32.subarray(digest32.length - SIGMA_CHALLENGE_BYTES);

/**
 * The 31-byte challenge as its Fr SCALAR, taken DIRECTLY from the bytes (no
 * mod-R reduction). Injective because `bytesToBigInt(e) < 2^248 < R`.
 */
const sigmaChallengeScalar = (e: Uint8Array): bigint => hb.bytesToBigInt(e);

// --- Parsed PROPOSITION tree (statement only; no challenges/responses). ---
type PropNode =
  | { kind: 'dlog'; pk: G1; pkBytes: Uint8Array }
  | {
      kind: 'dhtuple';
      g: G1;
      h: G1;
      u: G1;
      v: G1;
      gBytes: Uint8Array;
      hBytes: Uint8Array;
      uBytes: Uint8Array;
      vBytes: Uint8Array;
    }
  | { kind: 'and'; children: PropNode[] }
  | { kind: 'or'; children: PropNode[] }
  | { kind: 'threshold'; k: number; children: PropNode[] };

// --- Parsed PROOF tree (per-node challenge `e`; per-leaf response `z`). ---
type ProofNode =
  | { kind: 'dlog'; e: Uint8Array; z: bigint }
  | { kind: 'dhtuple'; e: Uint8Array; z: bigint }
  | { kind: 'and'; e: Uint8Array; children: ProofNode[] }
  | { kind: 'or'; e: Uint8Array; children: ProofNode[] }
  | { kind: 'threshold'; e: Uint8Array; k: number; children: ProofNode[] };

const proofChallenge = (n: ProofNode): Uint8Array => n.e;

// --- Map / field accessors over a parsed MapValue (insertion-ordered Map). ---

const sigmaField = (role: string, m: Map<string, JsonLogicValue>, key: string): JsonLogicValue => {
  const v = m.get(key);
  if (v === undefined) {
    return fail(`${role}: missing required field '${key}'`);
  }
  return v;
};

/**
 * IMPL-2 / IMPL-5: reject any field outside the canonical schema for this node kind, so the raw
 * proposition / proof encoding is canonical (no ignored field can inflate the DoS shape bound or
 * leave the bytes ambiguous for logs / caches / external signing layers). Mirrors the Scala
 * `sigmaRejectUnknownFields` / Rust `sigma_reject_unknown_fields`.
 */
const sigmaRejectUnknownFields = (
  role: string,
  m: Map<string, JsonLogicValue>,
  allowed: readonly string[]
): void => {
  for (const k of m.keys()) {
    if (!allowed.includes(k)) {
      fail(`${role}: unknown field '${k}' (allowed: ${allowed.join(', ')})`);
    }
  }
};

/**
 * IMPL-3 (DoS): parse a sigma message (arbitrary-width hex) and enforce the absolute length cap.
 * Shared by `sigma_verify` and `prove_dhtuple_verify`. Mirrors the Scala/Rust `parseSigmaMessage`.
 */
const parseSigmaMessage = (hex: string, role: string): Uint8Array => {
  const bytes = hb.parseBytes(hex, null, role);
  if (bytes.length > SIGMA_MAX_MESSAGE_BYTES) {
    return fail(
      `${role}: message too long (${bytes.length} > ${SIGMA_MAX_MESSAGE_BYTES} bytes) — DoS bound`
    );
  }
  return bytes;
};

const sigmaType = (role: string, m: Map<string, JsonLogicValue>): string =>
  expectStr(`${role}.type`, sigmaField(role, m, 'type'));

/** Parse a G1 statement point: on-curve check + canonical 64-byte re-encoding. */
const sigmaPoint = (
  role: string,
  m: Map<string, JsonLogicValue>,
  key: string
): { point: G1; bytes: Uint8Array } => {
  const hex = expectStr(`${role}.${key}`, sigmaField(role, m, key));
  const coords = hb.parseG1(hex, `${role}.${key}`);
  const point = g1OnCurve(coords, `${role}.${key}`);
  const bytes = hb.parseBytes(hex, hb.G1_BYTES, `${role}.${key}`);
  return { point, bytes };
};

const sigmaChildrenValues = (role: string, m: Map<string, JsonLogicValue>): JsonLogicValue[] => {
  const v = sigmaField(role, m, 'children');
  if (v.tag === 'array') {
    if (v.value.length === 0) {
      return fail(`${role}: 'children' must be a non-empty array`);
    }
    return v.value;
  }
  return fail(`${role}: 'children' must be an array, got ${v.tag}`);
};

const sigmaInt = (role: string, m: Map<string, JsonLogicValue>, key: string): number => {
  const v = sigmaField(role, m, key);
  if (v.tag === 'int') {
    // 0 <= i <= Int.MaxValue (the Scala bound).
    if (v.value >= 0n && v.value <= 2147483647n) {
      return Number(v.value);
    }
    return fail(`${role}.${key}: out of range: ${v.value}`);
  }
  return fail(`${role}.${key}: expected an integer, got ${v.tag}`);
};

const sigmaChallenge = (role: string, m: Map<string, JsonLogicValue>): Uint8Array => {
  const hex = expectStr(`${role}.e`, sigmaField(role, m, 'e'));
  // Fixed 31-byte (248-bit) big-endian value — the injective-into-Fr domain.
  return hb.parseBytes(hex, SIGMA_CHALLENGE_BYTES, `${role}.e`);
};

const sigmaResponse = (role: string, m: Map<string, JsonLogicValue>): bigint =>
  requireCanonicalScalar(
    hb.parseScalar(expectStr(`${role}.z`, sigmaField(role, m, 'z')), `${role}.z`),
    `${role}.z`
  );

// --- Proposition parsing (statement only). Malformed => throw. ---

const parsePropNode = (v: JsonLogicValue, role: string): PropNode => {
  if (v.tag !== 'map') {
    return fail(`${role}: expected a proposition node object, got ${v.tag}`);
  }
  const m = v.value;
  const typ = sigmaType(role, m);
  switch (typ) {
    case 'dlog': {
      sigmaRejectUnknownFields(role, m, ['type', 'pk']);
      const { point, bytes } = sigmaPoint(role, m, 'pk');
      return { kind: 'dlog', pk: point, pkBytes: bytes };
    }
    case 'dhtuple': {
      sigmaRejectUnknownFields(role, m, ['type', 'g', 'h', 'u', 'v']);
      const g = sigmaPoint(role, m, 'g');
      const h = sigmaPoint(role, m, 'h');
      const u = sigmaPoint(role, m, 'u');
      const vv = sigmaPoint(role, m, 'v');
      return {
        kind: 'dhtuple',
        g: g.point,
        h: h.point,
        u: u.point,
        v: vv.point,
        gBytes: g.bytes,
        hBytes: h.bytes,
        uBytes: u.bytes,
        vBytes: vv.bytes,
      };
    }
    case 'and': {
      sigmaRejectUnknownFields(role, m, ['type', 'children']);
      const cs = sigmaChildrenValues(role, m);
      return { kind: 'and', children: cs.map((c, i) => parsePropNode(c, `${role}.and[${i}]`)) };
    }
    case 'or': {
      sigmaRejectUnknownFields(role, m, ['type', 'children']);
      const cs = sigmaChildrenValues(role, m);
      return { kind: 'or', children: cs.map((c, i) => parsePropNode(c, `${role}.or[${i}]`)) };
    }
    case 'threshold': {
      sigmaRejectUnknownFields(role, m, ['type', 'k', 'children']);
      const k = sigmaInt(role, m, 'k');
      const cs = sigmaChildrenValues(role, m);
      const children = cs.map((c, i) => parsePropNode(c, `${role}.threshold[${i}]`));
      const n = children.length;
      // Structural validity: 1 <= k <= n; n <= 255 (GF(2^8) child indices 1..n).
      if (k < 1) {
        return fail(`${role}.threshold: k must be >= 1, got ${k}`);
      }
      if (k > n) {
        return fail(`${role}.threshold: k (${k}) > number of children (${n})`);
      }
      if (n > 255) {
        return fail(`${role}.threshold: at most 255 children (GF(2^8) indices), got ${n}`);
      }
      return { kind: 'threshold', k, children };
    }
    default:
      return fail(`${role}: unknown node type '${typ}'`);
  }
};

// --- Proof parsing (per-node challenge + per-leaf response). Malformed => throw. ---

const parseProofNode = (v: JsonLogicValue, role: string): ProofNode => {
  if (v.tag !== 'map') {
    return fail(`${role}: expected a proof node object, got ${v.tag}`);
  }
  const m = v.value;
  const e = sigmaChallenge(role, m);
  const typ = sigmaType(role, m);
  switch (typ) {
    case 'dlog': {
      sigmaRejectUnknownFields(role, m, ['type', 'e', 'z']);
      return { kind: 'dlog', e, z: sigmaResponse(role, m) };
    }
    case 'dhtuple': {
      sigmaRejectUnknownFields(role, m, ['type', 'e', 'z']);
      return { kind: 'dhtuple', e, z: sigmaResponse(role, m) };
    }
    case 'and': {
      sigmaRejectUnknownFields(role, m, ['type', 'e', 'children']);
      const cs = sigmaChildrenValues(role, m);
      return { kind: 'and', e, children: cs.map((c, i) => parseProofNode(c, `${role}.and[${i}]`)) };
    }
    case 'or': {
      sigmaRejectUnknownFields(role, m, ['type', 'e', 'children']);
      const cs = sigmaChildrenValues(role, m);
      return { kind: 'or', e, children: cs.map((c, i) => parseProofNode(c, `${role}.or[${i}]`)) };
    }
    case 'threshold': {
      sigmaRejectUnknownFields(role, m, ['type', 'e', 'k', 'children']);
      const k = sigmaInt(role, m, 'k');
      const cs = sigmaChildrenValues(role, m);
      return {
        kind: 'threshold',
        e,
        k,
        children: cs.map((c, i) => parseProofNode(c, `${role}.threshold[${i}]`)),
      };
    }
    default:
      return fail(`${role}: unknown node type '${typ}'`);
  }
};

// --- DoS shape bound (mirrors Rust sigma_raw_shape / bound_proof_shape). ---

/**
 * Cheap node-count + depth of a parsed sigma tree (JsonLogicValue): one node per
 * map, recursing into a `children` array. Traverses the MapValue/ArrayValue tree
 * DIRECTLY — no plain-object lowering — so the early-abort and prototype-safety
 * properties are preserved (IMPL-4) and it matches the Scala/Rust raw-shape walk.
 */
const sigmaRawShape = (v: JsonLogicValue): [number, number] => {
  if (v.tag === 'map') {
    const children = v.value.get('children');
    if (children !== undefined && children.tag === 'array') {
      let n = 0;
      let d = 0;
      for (const c of children.value) {
        const [cn, cd] = sigmaRawShape(c);
        n += cn;
        d = Math.max(d, cd);
      }
      return [n + 1, d + 1];
    }
    return [1, 1];
  }
  return [1, 1];
};

/**
 * Reject — BEFORE the recursive parse — a parsed sigma tree whose node count or
 * depth exceeds (maxNodes / maxDepth). Applied to the proposition with the absolute
 * caps (IMPL-1) and to the proof with the proposition-derived caps. Traverses the
 * JsonLogicValue tree DIRECTLY with early abort (IMPL-4): no whole-tree plain-object
 * conversion, so a huge tree aborts at the first over-bound node and no attacker keys
 * are written into a plain `{}`. Mirrors the Scala/Rust `boundRawShape`.
 */
const boundRawShape = (
  v: JsonLogicValue,
  maxNodes: number,
  maxDepth: number,
  role: string
): void => {
  const tooLarge = (): never =>
    fail(
      `${role}: sigma tree exceeds the allowed structure ` +
        `(max ${maxNodes} nodes, depth ${maxDepth}) — rejected before traversal (DoS bound)`
    );
  // Returns nodes-so-far or throws as soon as a bound is crossed; depth is 1-based.
  const go = (node: JsonLogicValue, depth: number, nodesSoFar: number): number => {
    if (depth > maxDepth) {
      return tooLarge();
    }
    const n = nodesSoFar + 1;
    if (n > maxNodes) {
      return tooLarge();
    }
    if (node.tag === 'map') {
      const children = node.value.get('children');
      if (children !== undefined && children.tag === 'array') {
        let running = n;
        for (const c of children.value) {
          running = go(c, depth + 1, running);
        }
        return running;
      }
    }
    return n;
  };
  go(v, 1, 0);
};

// --- GF(2^8) Shamir arithmetic for the CTHRESHOLD challenge split (AES 0x11b). ---

/** GF(2^8) multiply (Russian-peasant, AES reduction poly 0x11b). */
const gfMul = (a0: number, b0: number): number => {
  let prod = 0;
  let a = a0 & 0xff;
  let b = b0 & 0xff;
  for (let i = 0; i < 8; i++) {
    if ((b & 1) !== 0) {
      prod ^= a;
    }
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high !== 0) {
      a ^= 0x1b;
    }
    b >>= 1;
  }
  return prod & 0xff;
};

/** GF(2^8) multiplicative inverse via Fermat (a^254 = a^-1 for a != 0). gfInv(0)=0. */
const gfInv = (a: number): number => {
  if ((a & 0xff) === 0) {
    return 0;
  }
  // a^254: square-and-multiply over the 8 bits of 254 = 0b11111110.
  let acc = 1;
  let base = a & 0xff;
  for (let bit = 0; bit < 8; bit++) {
    if (((254 >> bit) & 1) !== 0) {
      acc = gfMul(acc, base);
    }
    base = gfMul(base, base);
  }
  return acc & 0xff;
};

/**
 * Lagrange evaluation in GF(2^8): given DISTINCT sample points `(xs, ys)`,
 * return the interpolating polynomial evaluated at `xEval`. Subtraction == XOR.
 */
const gfLagrangeEval = (xs: number[], ys: number[], xEval: number): number => {
  let acc = 0;
  for (let i = 0; i < xs.length; i++) {
    // basis_i(xEval) = ∏_{j!=i} (xEval - xs_j) / (xs_i - xs_j).
    let num = 1;
    let den = 1;
    for (let j = 0; j < xs.length; j++) {
      if (j !== i) {
        num = gfMul(num, xEval ^ xs[j]);
        den = gfMul(den, xs[i] ^ xs[j]);
      }
    }
    acc ^= gfMul(ys[i], gfMul(num, gfInv(den)));
  }
  return acc & 0xff;
};

/**
 * CTHRESHOLD interpolation check (byte-wise GF(2^8)). The `n` child challenges
 * must be `P(1), …, P(n)` of a degree-`(n-k)` GF(2^8) polynomial with
 * `P(0) = parent challenge`, computed independently per byte-lane. `false`
 * (not error) on mismatch. Mirrors Rust `threshold_interpolates`.
 */
const thresholdInterpolates = (
  parentE: Uint8Array,
  childEs: Uint8Array[],
  k: number,
  n: number
): boolean => {
  const degree = n - k; // (degree + 1) points define the polynomial
  const knownCount = degree + 1;
  // Defining x-coords: 0 (parent), then child indices 1..degree.
  const xs: number[] = [];
  for (let i = 0; i < knownCount; i++) {
    xs.push(i);
  }
  // Each of the 31 byte-lanes must independently interpolate.
  for (let lane = 0; lane < SIGMA_CHALLENGE_BYTES; lane++) {
    const ys: number[] = [];
    for (let j = 0; j < knownCount; j++) {
      // j == 0 -> P(0) = parent challenge; child (j-1) sits at x = j.
      ys.push(j === 0 ? parentE[lane] : childEs[j - 1][lane]);
    }
    // Remaining (unconstrained) children: indices degree .. n-1, i.e. x = degree+1 .. n.
    for (let c = degree; c < n; c++) {
      if (childEs[c][lane] !== gfLagrangeEval(xs, ys, c + 1)) {
        return false;
      }
    }
  }
  return true;
};

// --- Serialization / equality helpers. ---

/** Fixed 4-byte big-endian encoding of a non-negative count / threshold k. */
const uint32be = (v: number): Uint8Array => {
  const out = new Uint8Array(4);
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

/** XOR a list of equal-width byte arrays into one `width`-byte array (CDS OR fold). */
const xorBytes = (arrays: Uint8Array[], width: number): Uint8Array => {
  const out = new Uint8Array(width);
  for (let i = 0; i < width; i++) {
    let acc = 0;
    for (const a of arrays) {
      acc ^= a[i];
    }
    out[i] = acc;
  }
  return out;
};

/** Length-checked, data-independent byte equality (no early-exit timing leak). */
const constantTimeEq = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
};

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

const propNodeKind = (n: PropNode): string => n.kind;
const proofNodeKind = (n: ProofNode): string => n.kind;

/**
 * One recursive node visit. Returns `[cryptoOk, serializedBytes]`:
 * `cryptoOk = false` is a well-formed-but-wrong verdict that propagates up;
 * a throw is a structural/encoding fault (prop/proof shape mismatch is hard).
 * Mirrors Rust `verify_node`.
 */
const verifyNode = (prop: PropNode, proof: ProofNode, role: string): [boolean, Uint8Array] => {
  // --- DLog leaf: reconstruct a = z·G − e·pk, serialize 0x00 ‖ pk ‖ a. ---
  if (prop.kind === 'dlog' && proof.kind === 'dlog') {
    // SOUNDNESS: reject the identity pk (universal forgery).
    if (prop.pk.inf) {
      return [false, new Uint8Array(0)];
    }
    // The 31-byte challenge IS the Fr scalar, taken directly (no mod R).
    const eScalar = sigmaChallengeScalar(proof.e);
    const zScalar = proof.z % GROUP_ORDER;
    const a = g1Add(g1Mul(G1_GEN, zScalar), g1Negate(g1Mul(prop.pk, eScalar)));
    const aBytes = encodeG1Bytes(a);
    return [true, concatBytes([Uint8Array.of(SIGMA_TAG_DLOG), prop.pkBytes, aBytes])];
  }

  // --- DHTuple leaf: a1 = z·g − e·u, a2 = z·h − e·v; 0x01 ‖ g‖h‖u‖v‖a1‖a2. ---
  if (prop.kind === 'dhtuple' && proof.kind === 'dhtuple') {
    // SOUNDNESS: reject identity on any statement point.
    if (prop.g.inf || prop.h.inf || prop.u.inf || prop.v.inf) {
      return [false, new Uint8Array(0)];
    }
    const eScalar = sigmaChallengeScalar(proof.e);
    const zScalar = proof.z % GROUP_ORDER;
    // The single shared response z is used for BOTH coordinate reconstructions.
    const a1 = g1Add(g1Mul(prop.g, zScalar), g1Negate(g1Mul(prop.u, eScalar)));
    const a2 = g1Add(g1Mul(prop.h, zScalar), g1Negate(g1Mul(prop.v, eScalar)));
    return [
      true,
      concatBytes([
        Uint8Array.of(SIGMA_TAG_DHTUPLE),
        prop.gBytes,
        prop.hBytes,
        prop.uBytes,
        prop.vBytes,
        encodeG1Bytes(a1),
        encodeG1Bytes(a2),
      ]),
    ];
  }

  // --- CAND: every child challenge MUST equal the node challenge. ---
  if (prop.kind === 'and' && proof.kind === 'and') {
    if (prop.children.length !== proof.children.length) {
      return fail(
        `${role}.and: proposition/proof child count mismatch ` +
          `(${prop.children.length} vs ${proof.children.length})`
      );
    }
    let allOk = proof.children.every((c) => constantTimeEq(proofChallenge(c), proof.e));
    const body: Uint8Array[] = [];
    for (let i = 0; i < prop.children.length; i++) {
      const [ok, ser] = verifyNode(prop.children[i], proof.children[i], `${role}.and[${i}]`);
      allOk = allOk && ok;
      body.push(ser);
    }
    return [
      allOk,
      concatBytes([Uint8Array.of(SIGMA_TAG_AND), uint32be(prop.children.length), ...body]),
    ];
  }

  // --- COR: child challenges MUST XOR to the node challenge (CDS XOR). ---
  if (prop.kind === 'or' && proof.kind === 'or') {
    if (prop.children.length !== proof.children.length) {
      return fail(
        `${role}.or: proposition/proof child count mismatch ` +
          `(${prop.children.length} vs ${proof.children.length})`
      );
    }
    const childEs = proof.children.map(proofChallenge);
    let allOk = constantTimeEq(xorBytes(childEs, SIGMA_CHALLENGE_BYTES), proof.e);
    const body: Uint8Array[] = [];
    for (let i = 0; i < prop.children.length; i++) {
      const [ok, ser] = verifyNode(prop.children[i], proof.children[i], `${role}.or[${i}]`);
      allOk = allOk && ok;
      body.push(ser);
    }
    return [
      allOk,
      concatBytes([Uint8Array.of(SIGMA_TAG_OR), uint32be(prop.children.length), ...body]),
    ];
  }

  // --- CTHRESHOLD(k,n): child challenges are P(1..n) for a degree-(n-k)
  //     GF(2^8) poly P with P(0) = node challenge. ---
  if (prop.kind === 'threshold' && proof.kind === 'threshold') {
    if (prop.k !== proof.k) {
      return fail(`${role}.threshold: proposition/proof k mismatch (${prop.k} vs ${proof.k})`);
    }
    if (prop.children.length !== proof.children.length) {
      return fail(
        `${role}.threshold: proposition/proof child count mismatch ` +
          `(${prop.children.length} vs ${proof.children.length})`
      );
    }
    const n = prop.children.length;
    const childEs = proof.children.map(proofChallenge);
    let allOk = thresholdInterpolates(proof.e, childEs, prop.k, n);
    const body: Uint8Array[] = [];
    for (let i = 0; i < prop.children.length; i++) {
      const [ok, ser] = verifyNode(prop.children[i], proof.children[i], `${role}.threshold[${i}]`);
      allOk = allOk && ok;
      body.push(ser);
    }
    return [
      allOk,
      concatBytes([Uint8Array.of(SIGMA_TAG_THRESHOLD), uint32be(prop.k), uint32be(n), ...body]),
    ];
  }

  // --- Any other (prop, proof) pairing is a structural shape mismatch. ---
  return fail(
    `${role}: proposition/proof node-type mismatch ` +
      `(${propNodeKind(prop)} vs ${proofNodeKind(proof)})`
  );
};

/**
 * The recursive verifier (Ergo Verifier Steps 1-6). A throw is MALFORMED;
 * `false` is well-formed-but-invalid; `true` is accept. Mirrors Rust
 * `verify_tree`.
 */
const verifyTree = (prop: PropNode, proof: ProofNode, msg: Uint8Array): boolean => {
  const [cryptoOk, serialized] = verifyNode(prop, proof, 'sigma_verify');
  if (!cryptoOk) {
    return false;
  }
  // Steps 5-6: STRONG Fiat-Shamir over (DomainSep ‖ canonical tree ‖ message).
  // The root challenge is the LOW-ORDER 31 bytes of the digest — compared
  // BYTE-FOR-BYTE against the proof's 31-byte root challenge (no mod-R on either
  // side; both < 2^248 < R, so byte equality is exactly Fr equality).
  const digest = sha256(concatBytes([SIGMA_DOMAIN_SEP, serialized, msg]));
  return constantTimeEq(sigmaLow31(digest), proofChallenge(proof));
};

/** `sigma_verify([proposition, proof, messageHex]) -> bool`. */
export const opSigmaVerify = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length !== 3) {
    return fail('sigma_verify: expected [proposition, proof, messageHex]');
  }
  const msgHex = expectStr('sigma_verify message', values[2]);
  const msg = parseSigmaMessage(msgHex, 'sigma_verify message');
  // IMPL-1 (DoS): bound the proposition's raw shape with the absolute caps BEFORE
  // its recursive parse (parsePropNode + sigmaRawShape both descend it).
  boundRawShape(
    values[0],
    SIGMA_MAX_PROOF_NODES,
    SIGMA_MAX_PROOF_DEPTH,
    'sigma_verify.proposition'
  );
  const prop = parsePropNode(values[0], 'sigma_verify.proposition');
  // FINDING #2 (DoS): the proof must mirror the proposition; bound it BEFORE the
  // expensive recursive proof parse. Unknown fields are rejected at parse, so the
  // proposition's raw shape == semantic shape (no bogus children inflates it, IMPL-2).
  const [propNodes, propDepth] = sigmaRawShape(values[0]);
  const maxNodes = Math.min(propNodes, SIGMA_MAX_PROOF_NODES);
  const maxDepth = Math.min(propDepth, SIGMA_MAX_PROOF_DEPTH);
  boundRawShape(values[1], maxNodes, maxDepth, 'sigma_verify.proof');
  const proof = parseProofNode(values[1], 'sigma_verify.proof');
  return boolValue(verifyTree(prop, proof, msg));
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
