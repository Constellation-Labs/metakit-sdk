/**
 * RFC 8785 (JCS) canonical JSON serialization for the auth-DB opcodes'
 * commitment / value-digest pre-images.
 *
 * Byte-for-byte port of rust/jlvm-core/src/canonical.rs `canonicalize_json`
 * (the circe-`Json` analogue), itself mirroring metakit's `JsonBinaryHasher`
 * canonicalization step:
 *   * Object keys are sorted by their UTF-16 code units (the JCS rule).
 *   * Strings use the JCS escaping set (\n \b \f \r \t \" \\, and \u00xx for the
 *     remaining C0 controls), everything else verbatim.
 *   * Numbers serialize as the ECMAScript shortest double (JSON.stringify), the
 *     same value Rust's ryu-js and Scala's DoubleSerializer emit. `-0` -> `0`.
 *
 * IMPORTANT — `canonicalizeNoDropNulls` itself does not drop null object
 * fields, but the `JsonBinaryHasher` pre-image is `canonicalBytes(dropNulls(x))`
 * (`JsonBinaryCodec.serialize` applies `dropNulls` FIRST), so digest call sites
 * must pair it with {@link dropNullObjectFields}. Node commitments never carry
 * nulls (the drop is a no-op for them), but MPT VALUE digests hash arbitrary
 * committed records which DO carry null fields (e.g. a fiber record's
 * `metadata: null`) — hashing them un-dropped made `mpt_verify` reject every
 * such record (caught against live chain proofs, 2026-07).
 */

/** Compare two strings by their UTF-16 code units (RFC 8785 key ordering). */
const utf16Cmp = (a: string, b: string): number => {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) {
      return ca < cb ? -1 : 1;
    }
  }
  return a.length - b.length;
};

/** JCS string escaping (mirrors Rust `serialize_string` / Scala `escapeChar`). */
const serializeString = (s: string): string => {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0) as number;
    switch (ch) {
      case '\n':
        out += '\\n';
        break;
      case '\b':
        out += '\\b';
        break;
      case '\f':
        out += '\\f';
        break;
      case '\r':
        out += '\\r';
        break;
      case '\t':
        out += '\\t';
        break;
      case '"':
        out += '\\"';
        break;
      case '\\':
        out += '\\\\';
        break;
      default:
        if (code < 0x20) {
          out += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
};

/** ECMAScript shortest-double formatting (`-0` -> `0`); throws on non-finite. */
const serializeNumber = (value: number): string => {
  if (value === 0) {
    return '0';
  }
  if (!Number.isFinite(value)) {
    throw new Error('NaN/Infinity not allowed in canonical JSON');
  }
  // JSON.stringify implements ECMAScript Number::toString (shortest round-trip),
  // the same algorithm ryu-js (Rust) and DoubleSerializer (Scala) port.
  return JSON.stringify(value);
};

/**
 * Canonicalize a plain JSON value (the `encodeValue` output of a JsonLogicValue)
 * to its RFC 8785 canonical UTF-8 string, WITHOUT dropping null object fields.
 * `bigint` numbers (from large IntValues) route through the f64 boundary exactly
 * like Rust's `as_f64` / Scala's `num.toDouble`.
 */
export const canonicalizeNoDropNulls = (value: unknown): string => {
  if (value === null) {
    return 'null';
  }
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return serializeNumber(value);
    case 'bigint':
      // Big IntValues go through the f64 boundary (matches Rust/Scala).
      return serializeNumber(Number(value));
    case 'string':
      return serializeString(value);
    case 'object':
      break;
    default:
      // undefined / function / symbol have no JSON form; the auth-DB proof
      // values never contain these, so treat defensively as null.
      return 'null';
  }
  if (Array.isArray(value)) {
    return '[' + value.map((el) => canonicalizeNoDropNulls(el)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort(utf16Cmp);
  const parts: string[] = [];
  for (const key of keys) {
    parts.push(serializeString(key) + ':' + canonicalizeNoDropNulls(obj[key]));
  }
  return '{' + parts.join(',') + '}';
};

/**
 * `JsonBinaryCodec.dropNulls`: recursively remove null-valued OBJECT fields;
 * nulls inside ARRAYS are preserved (they carry index positions). The chain's
 * `JsonBinaryHasher` applies this before canonicalization — pair with
 * {@link canonicalizeNoDropNulls} to reproduce its digest pre-image.
 */
export const dropNullObjectFields = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(dropNullObjectFields);
  }
  if (typeof value === 'object' && value !== null) {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj)) {
      const v = obj[key];
      if (v !== null) {
        out[key] = dropNullObjectFields(v);
      }
    }
    return out;
  }
  return value;
};
