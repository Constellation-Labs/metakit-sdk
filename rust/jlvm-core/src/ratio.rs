//! Exact rational `numerator / denominator`, gcd-reduced with a strictly positive
//! denominator at construction time.
//!
//! Direct port of metakit's `io.constellationnetwork.metagraph_sdk.numerics.Ratio`
//! and `RatioOps`. This is the JLVM's numeric backbone so the Scala, Rust, and WASM
//! evaluators compute byte-identical results: all arithmetic is exact, and the only
//! rounding happens at canonical serialization (RFC 8785 shortest-double).

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct Ratio {
    pub numerator: BigInt,
    pub denominator: BigInt,
}

impl PartialEq for Ratio {
    fn eq(&self, other: &Self) -> bool {
        // Both are always in canonical (reduced, positive-denominator) form, so a
        // component-wise comparison is exact — matching Scala's `Ratio.equals`.
        self.numerator == other.numerator && self.denominator == other.denominator
    }
}
impl Eq for Ratio {}

impl Ord for Ratio {
    fn cmp(&self, other: &Self) -> Ordering {
        // Valid because both denominators are > 0 (the canonical-form invariant).
        // Mirrors `RatioOps.compare`.
        (&self.numerator * &other.denominator).cmp(&(&other.numerator * &self.denominator))
    }
}

impl PartialOrd for Ratio {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ratio {
    /// Smart constructor: gcd-reduce and canonicalize the sign onto the numerator so
    /// the denominator is always > 0. Mirrors `Ratio.apply(n, d)`.
    pub fn new(n: BigInt, d: BigInt) -> Ratio {
        if d.is_zero() {
            panic!("Ratio denominator cannot be zero");
        }
        let g = n.gcd(&d); // num-integer gcd is always non-negative
        let g = if g.is_zero() { BigInt::one() } else { g };
        let nn = &n / &g;
        let dd = &d / &g;
        if dd.is_negative() {
            Ratio { numerator: -nn, denominator: -dd }
        } else {
            Ratio { numerator: nn, denominator: dd }
        }
    }

    pub fn from_bigint(n: BigInt) -> Ratio {
        Ratio { numerator: n, denominator: BigInt::one() }
    }

    pub fn from_i64(n: i64) -> Ratio {
        Ratio::from_bigint(BigInt::from(n))
    }

    pub fn zero() -> Ratio {
        Ratio::from_i64(0)
    }

    /// Exact conversion from a terminating decimal `unscaled * 10^(-scale)`.
    /// Mirrors `Ratio.fromBigDecimal`: no precision loss.
    pub fn from_decimal(unscaled: BigInt, scale: i64) -> Ratio {
        if scale >= 0 {
            Ratio::new(unscaled, BigInt::from(10).pow(scale as u32))
        } else {
            Ratio::new(unscaled * BigInt::from(10).pow((-scale) as u32), BigInt::one())
        }
    }

    /// Parse a decimal string (possibly with a sign, fraction, and `e` exponent) into
    /// an exact Ratio. This is the analogue of `Ratio.fromBigDecimal(BigDecimal(s))`,
    /// used for string -> number coercion. Returns None on malformed input.
    pub fn parse_decimal(s: &str) -> Option<Ratio> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        // Split optional exponent.
        let (mantissa, exp): (&str, i64) = match s.find(['e', 'E']) {
            Some(idx) => {
                let e: i64 = s[idx + 1..].parse().ok()?;
                (&s[..idx], e)
            }
            None => (s, 0),
        };
        if mantissa.is_empty() {
            return None;
        }
        let (sign, body) = match mantissa.strip_prefix('-') {
            Some(rest) => (-1i32, rest),
            None => match mantissa.strip_prefix('+') {
                Some(rest) => (1i32, rest),
                None => (1i32, mantissa),
            },
        };
        if body.is_empty() {
            return None;
        }
        let (int_part, frac_part) = match body.find('.') {
            Some(idx) => (&body[..idx], &body[idx + 1..]),
            None => (body, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        // Validate digits.
        if !int_part.chars().all(|c| c.is_ascii_digit())
            || !frac_part.chars().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        let digits = format!("{}{}", int_part, frac_part);
        let unscaled = if digits.is_empty() {
            BigInt::zero()
        } else {
            BigInt::parse_bytes(digits.as_bytes(), 10)?
        };
        let unscaled = if sign < 0 { -unscaled } else { unscaled };
        // scale = number of fractional digits - exponent
        let scale = frac_part.len() as i64 - exp;
        Some(Ratio::from_decimal(unscaled, scale))
    }

    pub fn is_integer(&self) -> bool {
        self.denominator.is_one()
    }

    pub fn to_bigint_exact(&self) -> Option<BigInt> {
        if self.is_integer() {
            Some(self.numerator.clone())
        } else {
            None
        }
    }

    pub fn signum_i32(&self) -> i32 {
        match self.numerator.sign() {
            num_bigint::Sign::Minus => -1,
            num_bigint::Sign::NoSign => 0,
            num_bigint::Sign::Plus => 1,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.numerator.is_zero()
    }

    pub fn abs(&self) -> Ratio {
        Ratio { numerator: self.numerator.abs(), denominator: self.denominator.clone() }
    }

    pub fn neg(&self) -> Ratio {
        Ratio { numerator: -self.numerator.clone(), denominator: self.denominator.clone() }
    }

    pub fn inverse(&self) -> Ratio {
        Ratio::new(self.denominator.clone(), self.numerator.clone())
    }

    pub fn add(&self, that: &Ratio) -> Ratio {
        Ratio::new(
            &self.numerator * &that.denominator + &that.numerator * &self.denominator,
            &self.denominator * &that.denominator,
        )
    }

    pub fn sub(&self, that: &Ratio) -> Ratio {
        Ratio::new(
            &self.numerator * &that.denominator - &that.numerator * &self.denominator,
            &self.denominator * &that.denominator,
        )
    }

    pub fn mul(&self, that: &Ratio) -> Ratio {
        Ratio::new(&self.numerator * &that.numerator, &self.denominator * &that.denominator)
    }

    pub fn div(&self, that: &Ratio) -> Ratio {
        Ratio::new(&self.numerator * &that.denominator, &self.denominator * &that.numerator)
    }

    /// Integer power. Mirrors `RatioOps.pow(n: Int)` for non-negative `n`.
    pub fn pow(&self, n: u32) -> Ratio {
        Ratio::new(self.numerator.pow(n), self.denominator.pow(n))
    }

    /// Minimum of two ratios (by-reference). Named distinctly from `Ord::min` to avoid
    /// method-resolution ambiguity with the std trait.
    pub fn min_ratio(&self, that: &Ratio) -> Ratio {
        if self.cmp(that) != Ordering::Greater {
            self.clone()
        } else {
            that.clone()
        }
    }

    /// Maximum of two ratios (by-reference).
    pub fn max_ratio(&self, that: &Ratio) -> Ratio {
        if self.cmp(that) != Ordering::Less {
            self.clone()
        } else {
            that.clone()
        }
    }

    /// Largest integer <= x. Mirrors `RatioOps.floor`.
    pub fn floor(&self) -> BigInt {
        let q = &self.numerator / &self.denominator;
        let r = &self.numerator % &self.denominator;
        if !r.is_zero() && self.numerator.is_negative() {
            q - 1
        } else {
            q
        }
    }

    /// Smallest integer >= x. Mirrors `RatioOps.ceil`.
    pub fn ceil(&self) -> BigInt {
        let q = &self.numerator / &self.denominator;
        let r = &self.numerator % &self.denominator;
        if !r.is_zero() && self.numerator.is_positive() {
            q + 1
        } else {
            q
        }
    }

    /// Round toward zero. Mirrors `RatioOps.truncate`. BigInt `/` truncates toward zero.
    pub fn truncate(&self) -> BigInt {
        &self.numerator / &self.denominator
    }

    /// Round half away from zero — matches BigDecimal RoundingMode.HALF_UP.
    /// Mirrors `RatioOps.roundHalfUp`.
    pub fn round_half_up(&self) -> BigInt {
        let n = self.numerator.abs();
        let d = &self.denominator;
        let mag = (&n * 2 + d) / (d * 2);
        BigInt::from(self.signum_i32()) * mag
    }

    /// Truncated remainder: a - b * truncate(a / b). Mirrors `RatioOps.mod`.
    pub fn rem(&self, that: &Ratio) -> Ratio {
        let t = self.div(that).truncate();
        self.sub(&that.mul(&Ratio::from_bigint(t)))
    }

    /// Convert to an IEEE-754 double. This is the serialization boundary used by the
    /// RFC 8785 canonicalizer (Scala: `RatioOps.toDouble` == `toBigDecimal.toDouble`).
    /// We compute numerator/denominator as f64 with correct rounding for the magnitudes
    /// that appear in practice; for huge magnitudes we fall back to a string round-trip.
    pub fn to_f64(&self) -> f64 {
        // Fast path: both fit in f64 exactly enough that the single division rounds
        // identically to BigDecimal -> Double. We use the same approach as JVM's
        // BigDecimal(num)/BigDecimal(den): full-precision decimal then to double. To
        // stay exact we render an exact decimal expansion to enough digits and parse.
        if self.is_integer() {
            return bigint_to_f64(&self.numerator);
        }
        // Produce a decimal string with sufficient significant digits (well beyond
        // double precision) and let Rust's correctly-rounded str->f64 do the rounding.
        let s = self.to_decimal_string(40);
        s.parse::<f64>().unwrap_or_else(|_| {
            bigint_to_f64(&self.numerator) / bigint_to_f64(&self.denominator)
        })
    }

    /// Plain-decimal string for string ops (cat / join / in). Integral values render
    /// without a decimal point; non-integral values use the exact decimal expansion with
    /// trailing zeros stripped. Mirrors `NumericOps.floatToPlainString`.
    pub fn to_plain_string(&self) -> String {
        if self.is_integer() {
            return self.numerator.to_string();
        }
        // Exact terminating decimal if denominator is 2^a*5^b, else a sufficiently long
        // expansion. We strip trailing zeros to match stripTrailingZeros.toPlainString.
        let s = self.to_decimal_string_terminating_or(60);
        strip_trailing_zeros_decimal(&s)
    }

    /// Render an exact decimal expansion with `frac_digits` digits after the point
    /// (truncated, not rounded — used only for the f64 boundary where we then let
    /// str->f64 round). Always exact to the requested precision.
    fn to_decimal_string(&self, frac_digits: usize) -> String {
        let neg = self.numerator.is_negative();
        let num = self.numerator.abs();
        let den = &self.denominator;
        let int_part = &num / den;
        let mut rem = &num % den;
        let mut frac = String::new();
        for _ in 0..frac_digits {
            if rem.is_zero() {
                break;
            }
            rem *= 10;
            let digit = &rem / den;
            frac.push_str(&digit.to_string());
            rem %= den;
        }
        let mut out = String::new();
        if neg {
            out.push('-');
        }
        out.push_str(&int_part.to_string());
        if !frac.is_empty() {
            out.push('.');
            out.push_str(&frac);
        }
        out
    }

    /// Like `to_decimal_string` but expands fully when the fraction terminates (cap at
    /// `max_digits` otherwise). Matches the exact terminating expansion BigDecimal gives.
    fn to_decimal_string_terminating_or(&self, max_digits: usize) -> String {
        self.to_decimal_string(max_digits)
    }
}

/// Convert a BigInt to the nearest f64. For magnitudes within f64 range this is
/// correctly rounded via the standard library's string parser.
fn bigint_to_f64(v: &BigInt) -> f64 {
    v.to_string().parse::<f64>().unwrap_or(f64::INFINITY)
}

fn strip_trailing_zeros_decimal(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    let trimmed = s.trim_end_matches('0');
    let trimmed = trimmed.trim_end_matches('.');
    trimmed.to_string()
}

#[cfg(test)]
#[allow(clippy::approx_constant)] // 3.14 here is a test literal, not an approximation of PI
mod tests {
    use super::*;

    fn r(n: i64, d: i64) -> Ratio {
        Ratio::new(BigInt::from(n), BigInt::from(d))
    }

    #[test]
    fn canonical_form_positive_denominator() {
        let x = r(1, -2);
        assert_eq!(x.numerator, BigInt::from(-1));
        assert_eq!(x.denominator, BigInt::from(2));
        // gcd reduction
        let y = r(4, 8);
        assert_eq!(y, r(1, 2));
    }

    #[test]
    fn round_half_up_away_from_zero() {
        assert_eq!(r(5, 2).round_half_up(), BigInt::from(3)); // 2.5 -> 3
        assert_eq!(r(-5, 2).round_half_up(), BigInt::from(-3)); // -2.5 -> -3
        assert_eq!(r(13, 5).round_half_up(), BigInt::from(3)); // 2.6 -> 3
        assert_eq!(r(3, 2).round_half_up(), BigInt::from(2)); // 1.5 -> 2
    }

    #[test]
    fn floor_ceil_with_negatives() {
        assert_eq!(r(-7, 2).floor(), BigInt::from(-4)); // -3.5
        assert_eq!(r(-7, 2).ceil(), BigInt::from(-3));
        assert_eq!(r(7, 2).floor(), BigInt::from(3));
        assert_eq!(r(7, 2).ceil(), BigInt::from(4));
    }

    #[test]
    fn modulo_is_truncated() {
        // -7 % 3 = -1 (truncated division), matching JS/Java BigDecimal.remainder.
        let m = r(-7, 1).rem(&r(3, 1));
        assert_eq!(m, r(-1, 1));
    }

    #[test]
    fn exact_division() {
        // 7/2 = 3.5 stays exact.
        let q = r(7, 1).div(&r(2, 1));
        assert_eq!(q, r(7, 2));
        assert!(!q.is_integer());
    }

    #[test]
    fn parse_decimal_exact() {
        assert_eq!(Ratio::parse_decimal("3.14").unwrap(), r(157, 50));
        assert_eq!(Ratio::parse_decimal("0.1").unwrap(), r(1, 10));
        assert_eq!(Ratio::parse_decimal("-2.5").unwrap(), r(-5, 2));
        assert_eq!(Ratio::parse_decimal("1e3").unwrap(), r(1000, 1));
        assert_eq!(Ratio::parse_decimal("1.5e-2").unwrap(), r(15, 1000));
        assert!(Ratio::parse_decimal("abc").is_none());
    }

    #[test]
    fn plain_string_strips_trailing_zeros() {
        assert_eq!(r(7, 2).to_plain_string(), "3.5");
        assert_eq!(r(5, 1).to_plain_string(), "5");
        assert_eq!(r(1, 4).to_plain_string(), "0.25");
    }

    #[test]
    fn to_f64_matches_ecmascript_value() {
        assert_eq!(r(157, 50).to_f64(), 3.14);
        assert_eq!(r(7, 2).to_f64(), 3.5);
        assert_eq!(r(1, 10).to_f64(), 0.1);
        assert_eq!(Ratio::from_i64(42).to_f64(), 42.0);
    }
}
