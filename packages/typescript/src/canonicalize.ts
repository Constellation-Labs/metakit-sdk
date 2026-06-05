/**
 * RFC 8785 JSON Canonicalization
 *
 * Provides deterministic JSON serialization according to RFC 8785.
 * This ensures identical JSON objects always produce identical strings.
 */

import canonicalizeLib from 'canonicalize';

/**
 * Recursively drop null-valued object fields prior to canonicalization.
 *
 * RFC 8785 / JCS preserves null-valued object members (it only omits
 * `undefined`). The authoritative Scala server (metakit `JsonBinaryCodec`,
 * which the chain verifies signatures against) instead DROPS null object
 * members before canonicalizing. Without this alignment, any message carrying
 * a null field (e.g. a state-machine definition whose states have
 * `metadata: null`) would be signed by this client over a different canonical
 * form than the server re-derives, causing on-chain signature verification to
 * fail (HTTP 400).
 *
 * Behavior — byte-for-byte matched to metakit's `dropNulls`
 * (`json.arrayOrObject(json, arr => arr.map(dropNulls),
 *   obj => obj.filter(!_.isNull).mapValues(dropNulls))`):
 * - Object entries whose value is `null` are removed; remaining values recurse.
 * - Arrays are preserved as-is: every element (including `null` elements) keeps
 *   its position, and object elements are recursed into.
 * - Empty arrays `[]` and empty objects `{}` are preserved (only `null` is
 *   dropped, never empty containers).
 * - Primitives (string, number, boolean, and top-level `null`) are returned
 *   unchanged.
 *
 * @param data - Any JSON-serializable value
 * @returns The same value with null object-fields recursively removed
 */
export function dropNullFields<T>(data: T): T {
  if (Array.isArray(data)) {
    // Preserve array length and positions, including null elements; recurse
    // into each element so nested objects within arrays are still cleaned.
    return data.map((element) => dropNullFields(element)) as unknown as T;
  }

  if (data !== null && typeof data === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (value === null) {
        continue; // drop null-valued object fields
      }
      result[key] = dropNullFields(value);
    }
    return result as unknown as T;
  }

  // Primitives (and top-level null) pass through unchanged.
  return data;
}

/**
 * Canonicalize JSON data according to RFC 8785
 *
 * Null-valued object fields are dropped before canonicalization to match the
 * authoritative Scala server (see {@link dropNullFields}). This makes the bytes
 * produced for signing/verification here agree with what the chain re-derives.
 *
 * Key features:
 * - Null-valued object fields dropped (server-aligned; arrays/empties preserved)
 * - Object keys sorted by UTF-16BE binary comparison
 * - Numbers serialized in shortest decimal representation
 * - No whitespace
 * - Proper Unicode escaping
 *
 * @param data - Any JSON-serializable object
 * @returns Canonical JSON string
 * @throws Error if data cannot be serialized to JSON
 *
 * @example
 * ```typescript
 * const canonical = canonicalize({ b: 2, a: 1 });
 * // Returns: '{"a":1,"b":2}'
 *
 * // Null object-fields are dropped (server-aligned):
 * canonicalize({ a: null, b: 1 }); // Returns: '{"b":1}'
 * ```
 */
export function canonicalize<T>(data: T): string {
  const result = canonicalizeLib(dropNullFields(data));
  if (result === undefined) {
    throw new Error('Failed to canonicalize data: data cannot be serialized to JSON');
  }
  return result;
}
