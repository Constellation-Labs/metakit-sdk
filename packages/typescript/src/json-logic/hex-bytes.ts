/**
 * Shared hex-encoding codec for the JLVM crypto opcodes.
 *
 * Byte-for-byte port of rust/jlvm-core/src/hex_bytes.rs (itself a port of the
 * Scala `json_logic.ops.HexBytes`).
 *
 * Convention (implemented exactly):
 *   - All byte / field arguments and returns are lowercase, `0x`-prefixed,
 *     big-endian hex strings.
 *   - There is NO new JLVM value type; bytes are a validated special-case of
 *     StrValue, parsed and validated only at the opcode boundary.
 *   - Every malformed input (bad hex, wrong width, non-canonical field
 *     element, ...) throws a JsonLogicError — surfaced as a normal evaluation
 *     error, never a crash.
 */

import { JsonLogicRuntimeError } from './errors';

/** Byte width of a BN254 Fr field element. */
export const FR_BYTES = 32;

/** Byte width of a single BN254 (alt_bn128) base-field coordinate. */
export const FQ_BYTES = 32;

/** Byte width of a serialized BN254 G1 point (`x || y`, 32B each). */
export const G1_BYTES = 64;

/** Byte width of a 256-bit big-endian scalar (e.g. a Schnorr response `s`). */
export const SCALAR_BYTES = 32;

/** The BN254 / alt_bn128 scalar field modulus R (shared with Poseidon). */
export const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** The BN254 / alt_bn128 base-field (Fp) modulus P. */
export const FQ_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const fail = (message: string): never => {
  throw new JsonLogicRuntimeError(message);
};

/** Lowercase-hex / `0x`-prefix validation: `^0x[0-9a-f]*$`. */
const isValidHex = (hex: string): boolean => /^0x[0-9a-f]*$/.test(hex);

/**
 * Parse and validate a lowercase `0x`-prefixed hex string into raw bytes
 * (big-endian). `expectedLen === null` accepts any even-length body
 * (arbitrary-width bytes); otherwise the decoded length must equal it.
 */
export const parseBytes = (hex: string, expectedLen: number | null, role: string): Uint8Array => {
  if (!isValidHex(hex)) {
    return fail(`${role}: malformed hex (expected lowercase ^0x[0-9a-f]*$): '${hex}'`);
  }
  const body = hex.slice(2);
  if (body.length % 2 !== 0) {
    return fail(`${role}: odd-length hex body (${body.length} nibbles): '${hex}'`);
  }
  const bytes = new Uint8Array(body.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  }
  if (expectedLen !== null && bytes.length !== expectedLen) {
    return fail(`${role}: expected ${expectedLen} bytes, got ${bytes.length}`);
  }
  return bytes;
};

/** Big-endian bytes -> non-negative bigint. */
export const bytesToBigInt = (bytes: Uint8Array): bigint => {
  let v = 0n;
  for (const b of bytes) {
    v = (v << 8n) | BigInt(b);
  }
  return v;
};

/**
 * Parse a 32-byte hex string into a canonical BN254 Fr field element
 * (`0 <= value < R`). Rejects wrong width and non-canonical values.
 */
export const parseFr = (hex: string, role: string): bigint => {
  const value = bytesToBigInt(parseBytes(hex, FR_BYTES, role));
  if (value < FR_MODULUS) {
    return value;
  }
  return fail(`${role}: not a canonical BN254 field element (must be < modulus): ${value}`);
};

/**
 * Parse a 32-byte hex string into a non-negative big-endian scalar with NO
 * field-canonicity constraint (any 256-bit value is accepted). Used for
 * Schnorr / sigma responses and similar values that are reduced mod the group
 * order by the consuming primitive. Mirrors Rust `hex_bytes::parse_scalar`.
 */
export const parseScalar = (hex: string, role: string): bigint =>
  bytesToBigInt(parseBytes(hex, SCALAR_BYTES, role));

/**
 * Parse a 64-byte hex string into a BN254 G1 affine coordinate pair `(x, y)`.
 * Each 32-byte half is validated as a canonical Fq element (`< P`). The
 * all-zero point `(0, 0)` is the EVM point-at-infinity and is accepted here;
 * on-curve membership is enforced by the caller.
 */
export const parseG1 = (hex: string, role: string): { x: bigint; y: bigint } => {
  const bytes = parseBytes(hex, G1_BYTES, role);
  const x = bytesToBigInt(bytes.subarray(0, FQ_BYTES));
  const y = bytesToBigInt(bytes.subarray(FQ_BYTES, G1_BYTES));
  if (x >= FQ_MODULUS) {
    return fail(`${role}: x not in base field (>= P): ${x}`);
  }
  if (y >= FQ_MODULUS) {
    return fail(`${role}: y not in base field (>= P): ${y}`);
  }
  return { x, y };
};

/** Encode raw bytes as a lowercase `0x`-prefixed hex string. */
export const encodeBytes = (bytes: Uint8Array): string => {
  let s = '0x';
  for (const b of bytes) {
    s += b.toString(16).padStart(2, '0');
  }
  return s;
};

/**
 * Encode a non-negative bigint as a `0x`-prefixed, big-endian, zero-padded
 * hex of `width` bytes. Errors if it does not fit.
 */
export const encodeUint = (value: bigint, width: number, role: string): string => {
  const raw = value.toString(16);
  if (raw.length > width * 2) {
    return fail(`${role}: value ${value} does not fit in ${width} bytes`);
  }
  return '0x' + raw.padStart(width * 2, '0');
};

/** Encode a canonical Fr element as a 32-byte `0x`-prefixed hex string. */
export const encodeFr = (value: bigint): string => encodeUint(value, FR_BYTES, 'encodeFr');

/**
 * Encode a BN254 G1 point `(x, y)` as a 64-byte `0x`-hex string (`x || y`, 32B
 * each). Mirrors Rust `hex_bytes::encode_g1`. The all-zero point renders the
 * EVM point-at-infinity.
 */
export const encodeG1 = (x: bigint, y: bigint): string => {
  const xs = encodeUint(x, FQ_BYTES, 'encodeG1.x');
  const ys = encodeUint(y, FQ_BYTES, 'encodeG1.y');
  return '0x' + xs.slice(2) + ys.slice(2);
};
