/**
 * The `hex_to_int` opcode.
 *
 * Parses a `0x`-prefixed, lowercase, big-endian hex string into raw bytes
 * (reusing the shared crypto codec `hex-bytes.ts` `parseBytes` — the same
 * arbitrary-width parser `ecvrf_verify`'s alpha arg uses) and interprets those
 * bytes as an UNSIGNED big-endian integer, returning an arbitrary-precision
 * `intValue`. Byte-for-byte aligned with rust/jlvm-core/src/hex.rs and the
 * Scala `json_logic.ops` `hex_to_int`.
 *
 * The result is ALWAYS non-negative. Whatever the reused parser accepts (`0x`
 * prefix, lowercase, even-length body) is inherited; an empty body (`"0x"`)
 * decodes to zero. Malformed hex (odd-length body, non-hex chars) and a
 * non-string / wrong-arity argument throw via the standard fail path.
 */

import { JsonLogicRuntimeError } from './errors';
import type { JsonLogicValue } from './value';
import { intValue } from './value';
import * as hb from './hex-bytes';

const fail = (message: string): never => {
  throw new JsonLogicRuntimeError(message);
};

/**
 * `hex_to_int`: arity-1, string-only. Reuses the arbitrary-width hex byte
 * parser and the big-endian byte fold (`bytesToBigInt`), yielding a
 * non-negative bigint `IntValue`.
 */
export const opHexToInt = (values: JsonLogicValue[]): JsonLogicValue => {
  if (values.length !== 1) {
    return fail('hex_to_int: expected exactly one hex-string argument');
  }
  const arg = values[0];
  if (arg.tag !== 'string') {
    return fail(`hex_to_int: expected a hex string, got ${arg.tag}`);
  }
  // parseBytes enforces ^0x[0-9a-f]*$ + even length; bytesToBigInt folds the
  // bytes big-endian (acc = (acc << 8n) | byte), empty -> 0n. Always >= 0.
  const bytes = hb.parseBytes(arg.value, null, 'hex_to_int');
  return intValue(hb.bytesToBigInt(bytes));
};
