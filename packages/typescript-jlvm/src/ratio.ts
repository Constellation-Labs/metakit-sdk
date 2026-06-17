/**
 * Exact rational `numerator / denominator`, gcd-reduced with a strictly positive
 * denominator at construction time.
 *
 * Port of rust/jlvm-core/src/ratio.rs (itself a direct port of metakit's
 * `io.constellationnetwork.metagraph_sdk.numerics.Ratio` / `RatioOps`).
 * This is the JLVM's numeric backbone so the Scala, Rust, and TypeScript
 * evaluators compute byte-identical results: all arithmetic is exact, and the
 * only rounding happens at canonical serialization (RFC 8785 shortest-double).
 */

const ZERO = 0n;
const ONE = 1n;
const TEN = 10n;

const bigAbs = (v: bigint): bigint => (v < ZERO ? -v : v);

/** Non-negative gcd, matching num-integer's `gcd`. */
const gcd = (a: bigint, b: bigint): bigint => {
  let x = bigAbs(a);
  let y = bigAbs(b);
  while (y !== ZERO) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
};

export class Ratio {
  /** Always gcd-reduced; sign carried by the numerator. */
  readonly numerator: bigint;
  /** Always > 0. */
  readonly denominator: bigint;

  private constructor(numerator: bigint, denominator: bigint) {
    this.numerator = numerator;
    this.denominator = denominator;
  }

  /**
   * Smart constructor: gcd-reduce and canonicalize the sign onto the numerator
   * so the denominator is always > 0. Mirrors `Ratio.apply(n, d)`.
   */
  static of(n: bigint, d: bigint): Ratio {
    if (d === ZERO) {
      throw new Error('Ratio denominator cannot be zero');
    }
    let g = gcd(n, d);
    if (g === ZERO) g = ONE;
    let nn = n / g;
    let dd = d / g;
    if (dd < ZERO) {
      nn = -nn;
      dd = -dd;
    }
    return new Ratio(nn, dd);
  }

  static fromBigInt(n: bigint): Ratio {
    return new Ratio(n, ONE);
  }

  static zero(): Ratio {
    return Ratio.fromBigInt(ZERO);
  }

  /**
   * Maximum permitted magnitude of the effective decimal scale (fractional
   * digits minus exponent) accepted by {@link Ratio.fromDecimal} /
   * {@link Ratio.parseDecimal}. Mirrors Rust `Ratio::MAX_DECIMAL_SCALE`
   * (rust/jlvm-core/src/ratio.rs) and Scala `NumericOps.MaxDecimalScale`.
   *
   * SECURITY: a Ratio materializes `10n ** |scale|` as a full bigint, so an
   * attacker-controlled exponent like "1e-2000000000" would eagerly allocate a
   * multi-GB integer (memory bomb). The bound is generous but safe (a
   * 10_000-digit power of ten is ~4 KB); anything beyond is rejected, so
   * programs like {"+":["1e-2000000000"]} error identically in all impls.
   */
  static readonly MAX_DECIMAL_SCALE = 10000n;

  /**
   * Exact conversion from a terminating decimal `unscaled * 10^(-scale)`.
   * Mirrors `Ratio.fromBigDecimal`: no precision loss. Returns null when
   * `|scale|` exceeds {@link Ratio.MAX_DECIMAL_SCALE} (see the bound's docs).
   */
  static fromDecimal(unscaled: bigint, scale: bigint): Ratio | null {
    const mag = scale < ZERO ? -scale : scale;
    if (mag > Ratio.MAX_DECIMAL_SCALE) {
      return null;
    }
    if (scale >= ZERO) {
      return Ratio.of(unscaled, TEN ** scale);
    }
    return Ratio.of(unscaled * TEN ** -scale, ONE);
  }

  /**
   * Parse a decimal string (possibly with a sign, fraction, and `e` exponent)
   * into an exact Ratio. Analogue of `Ratio.fromBigDecimal(BigDecimal(s))`,
   * used for string -> number coercion. Returns null on malformed input or
   * when the effective decimal scale exceeds {@link Ratio.MAX_DECIMAL_SCALE}
   * (callers surface that as a normal evaluation error).
   */
  static parseDecimal(input: string): Ratio | null {
    const s = input.trim();
    if (s.length === 0) return null;

    // Split optional exponent (first 'e' or 'E', matching the Rust port).
    let mantissa = s;
    let exp = ZERO;
    const eIdx = ((): number => {
      const a = s.indexOf('e');
      const b = s.indexOf('E');
      if (a === -1) return b;
      if (b === -1) return a;
      return Math.min(a, b);
    })();
    if (eIdx !== -1) {
      const expStr = s.slice(eIdx + 1);
      if (!/^[+-]?[0-9]+$/.test(expStr)) return null;
      exp = BigInt(expStr);
      mantissa = s.slice(0, eIdx);
    }
    if (mantissa.length === 0) return null;

    let sign = 1;
    let body = mantissa;
    if (body.startsWith('-')) {
      sign = -1;
      body = body.slice(1);
    } else if (body.startsWith('+')) {
      body = body.slice(1);
    }
    if (body.length === 0) return null;

    const dotIdx = body.indexOf('.');
    const intPart = dotIdx === -1 ? body : body.slice(0, dotIdx);
    const fracPart = dotIdx === -1 ? '' : body.slice(dotIdx + 1);
    if (intPart.length === 0 && fracPart.length === 0) return null;
    if (!/^[0-9]*$/.test(intPart) || !/^[0-9]*$/.test(fracPart)) return null;

    const digits = intPart + fracPart;
    let unscaled = digits.length === 0 ? ZERO : BigInt(digits);
    if (sign < 0) unscaled = -unscaled;

    // scale = number of fractional digits - exponent
    const scale = BigInt(fracPart.length) - exp;
    return Ratio.fromDecimal(unscaled, scale);
  }

  isInteger(): boolean {
    return this.denominator === ONE;
  }

  toBigIntExact(): bigint | null {
    return this.isInteger() ? this.numerator : null;
  }

  signum(): number {
    return this.numerator < ZERO ? -1 : this.numerator === ZERO ? 0 : 1;
  }

  isZero(): boolean {
    return this.numerator === ZERO;
  }

  abs(): Ratio {
    return new Ratio(bigAbs(this.numerator), this.denominator);
  }

  neg(): Ratio {
    return new Ratio(-this.numerator, this.denominator);
  }

  inverse(): Ratio {
    return Ratio.of(this.denominator, this.numerator);
  }

  add(that: Ratio): Ratio {
    return Ratio.of(
      this.numerator * that.denominator + that.numerator * this.denominator,
      this.denominator * that.denominator
    );
  }

  sub(that: Ratio): Ratio {
    return Ratio.of(
      this.numerator * that.denominator - that.numerator * this.denominator,
      this.denominator * that.denominator
    );
  }

  mul(that: Ratio): Ratio {
    return Ratio.of(this.numerator * that.numerator, this.denominator * that.denominator);
  }

  div(that: Ratio): Ratio {
    return Ratio.of(this.numerator * that.denominator, this.denominator * that.numerator);
  }

  /** Integer power for non-negative `n`. Mirrors `RatioOps.pow(n: Int)`. */
  pow(n: number): Ratio {
    if (!Number.isInteger(n) || n < 0) {
      throw new Error('Ratio.pow requires a non-negative integer exponent');
    }
    const e = BigInt(n);
    return Ratio.of(this.numerator ** e, this.denominator ** e);
  }

  /**
   * Exact comparison: -1, 0, or 1. Valid because both denominators are > 0
   * (the canonical-form invariant). Mirrors `RatioOps.compare`.
   */
  compare(that: Ratio): number {
    const l = this.numerator * that.denominator;
    const r = that.numerator * this.denominator;
    return l < r ? -1 : l === r ? 0 : 1;
  }

  equals(that: Ratio): boolean {
    // Both are always in canonical form, so component-wise comparison is exact.
    return this.numerator === that.numerator && this.denominator === that.denominator;
  }

  min(that: Ratio): Ratio {
    return this.compare(that) <= 0 ? this : that;
  }

  max(that: Ratio): Ratio {
    return this.compare(that) >= 0 ? this : that;
  }

  /** Largest integer <= x. Mirrors `RatioOps.floor`. */
  floor(): bigint {
    const q = this.numerator / this.denominator; // BigInt division truncates toward zero
    const r = this.numerator % this.denominator;
    if (r !== ZERO && this.numerator < ZERO) {
      return q - ONE;
    }
    return q;
  }

  /** Smallest integer >= x. Mirrors `RatioOps.ceil`. */
  ceil(): bigint {
    const q = this.numerator / this.denominator;
    const r = this.numerator % this.denominator;
    if (r !== ZERO && this.numerator > ZERO) {
      return q + ONE;
    }
    return q;
  }

  /** Round toward zero. Mirrors `RatioOps.truncate`. */
  truncate(): bigint {
    return this.numerator / this.denominator;
  }

  /**
   * Round half away from zero — matches BigDecimal RoundingMode.HALF_UP.
   * Mirrors `RatioOps.roundHalfUp`.
   */
  roundHalfUp(): bigint {
    const n = bigAbs(this.numerator);
    const d = this.denominator;
    const mag = (n * 2n + d) / (d * 2n);
    return BigInt(this.signum()) * mag;
  }

  /** Truncated remainder: a - b * truncate(a / b). Mirrors `RatioOps.mod`. */
  rem(that: Ratio): Ratio {
    const t = this.div(that).truncate();
    return this.sub(that.mul(Ratio.fromBigInt(t)));
  }

  /**
   * Convert to an IEEE-754 double. This is the serialization boundary used by
   * the RFC 8785 canonicalizer. We render an exact decimal expansion to enough
   * digits (well beyond double precision) and let the engine's correctly-rounded
   * string->number conversion do the rounding — same approach as the Rust port.
   */
  toNumber(): number {
    if (this.isInteger()) {
      return Number(this.numerator);
    }
    return Number(this.toDecimalString(40));
  }

  /**
   * Plain-decimal string for string ops (cat / join / in). Integral values
   * render without a decimal point; non-integral values use the exact decimal
   * expansion with trailing zeros stripped. Mirrors `NumericOps.floatToPlainString`
   * / Rust `to_plain_string`.
   */
  toPlainString(): string {
    if (this.isInteger()) {
      return this.numerator.toString();
    }
    return stripTrailingZerosDecimal(this.toDecimalString(60));
  }

  /**
   * Render an exact decimal expansion with up to `fracDigits` digits after the
   * point (truncated, not rounded — used at the f64 boundary where the engine's
   * string->number parse then rounds). Always exact to the requested precision.
   */
  private toDecimalString(fracDigits: number): string {
    const neg = this.numerator < ZERO;
    const num = bigAbs(this.numerator);
    const den = this.denominator;
    const intPart = num / den;
    let rem = num % den;
    let frac = '';
    for (let i = 0; i < fracDigits; i++) {
      if (rem === ZERO) break;
      rem *= TEN;
      const digit = rem / den;
      frac += digit.toString();
      rem %= den;
    }
    let out = '';
    if (neg) out += '-';
    out += intPart.toString();
    if (frac.length > 0) {
      out += '.' + frac;
    }
    return out;
  }
}

const stripTrailingZerosDecimal = (s: string): string => {
  if (!s.includes('.')) return s;
  let t = s;
  while (t.endsWith('0')) t = t.slice(0, -1);
  if (t.endsWith('.')) t = t.slice(0, -1);
  return t;
};
