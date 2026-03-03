/**
 * Transaction Encoding
 *
 * Native transaction encoding and Kryo serialization,
 * replacing dag4-keystore's TransactionV2 and txEncode.
 */

import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils';
import type { CurrencyTransaction } from './currency-types';

/** Minimum salt complexity (matching dag4.js: Number.MAX_SAFE_INTEGER - 2^48) */
const MIN_SALT = 2 ** 53 - 2 ** 48;

/**
 * Generate a random salt for transaction uniqueness.
 */
export function generateSalt(): string {
  const bytes = nobleRandomBytes(6);
  let randomInt = 0;
  for (const byte of bytes) {
    randomInt = randomInt * 256 + byte;
  }
  return String(MIN_SALT + randomInt);
}

/**
 * Encode a currency transaction for hashing (length-prefixed format).
 *
 * Format: "2" + length-prefixed fields:
 *   {source_len}{source} + {dest_len}{destination} +
 *   {amount_hex_len}{amount_hex} + {parent_hash_len}{parent_hash} +
 *   {ordinal_len}{ordinal} + {fee_len}{fee} + {salt_hex_len}{salt_hex}
 */
export function encodeTransaction(tx: CurrencyTransaction): string {
  const parentCount = '2';
  const source = tx.value.source;
  const destination = tx.value.destination;
  const amountHex = tx.value.amount.toString(16);
  const parentHash = tx.value.parent.hash;
  const ordinal = String(tx.value.parent.ordinal);
  const fee = String(tx.value.fee);

  const saltInt = BigInt(tx.value.salt);
  const saltHex = saltInt.toString(16);

  return [
    parentCount,
    String(source.length),
    source,
    String(destination.length),
    destination,
    String(amountHex.length),
    amountHex,
    String(parentHash.length),
    parentHash,
    String(ordinal.length),
    ordinal,
    String(fee.length),
    fee,
    String(saltHex.length),
    saltHex,
  ].join('');
}

/**
 * Kryo serialization (v2 format with setReferences=false).
 *
 * Format: [0x03] + [optional 0x01 if setReferences] + [variable-length integer] + [UTF-8 message bytes]
 *
 * The variable-length integer encodes (msg.length + 1).
 */
export function kryoSerialize(msg: string, setReferences: boolean = false): Uint8Array {
  const prefix: number[] = [0x03];
  if (setReferences) {
    prefix.push(0x01);
  }

  const length = msg.length + 1;
  const lengthBytes = encodeVariableLength(length);

  const msgBytes = new TextEncoder().encode(msg);

  const result = new Uint8Array(prefix.length + lengthBytes.length + msgBytes.length);
  result.set(prefix, 0);
  result.set(lengthBytes, prefix.length);
  result.set(msgBytes, prefix.length + lengthBytes.length);

  return result;
}

/**
 * Variable-length integer encoding for Kryo serialization.
 */
function encodeVariableLength(value: number): Uint8Array {
  if (value >> 6 === 0) {
    return new Uint8Array([value | 0x80]);
  } else if (value >> 13 === 0) {
    return new Uint8Array([(value | 0x40 | 0x80) & 0xff, (value >> 6) & 0xff]);
  } else if (value >> 20 === 0) {
    return new Uint8Array([
      (value | 0x40 | 0x80) & 0xff,
      ((value >> 6) | 0x80) & 0xff,
      (value >> 13) & 0xff,
    ]);
  } else if (value >> 27 === 0) {
    return new Uint8Array([
      (value | 0x40 | 0x80) & 0xff,
      ((value >> 6) | 0x80) & 0xff,
      ((value >> 13) | 0x80) & 0xff,
      (value >> 20) & 0xff,
    ]);
  } else {
    return new Uint8Array([
      (value | 0x40 | 0x80) & 0xff,
      ((value >> 6) | 0x80) & 0xff,
      ((value >> 13) | 0x80) & 0xff,
      ((value >> 20) | 0x80) & 0xff,
      (value >> 27) & 0xff,
    ]);
  }
}
