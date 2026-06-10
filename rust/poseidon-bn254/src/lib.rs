//! Poseidon hash over the BN254 / alt_bn128 scalar field (Fr) and a fixed-depth
//! sparse Poseidon Merkle tree, BYTE-COMPATIBLE with metakit's Scala
//! implementation (`io.constellationnetwork.metagraph_sdk.crypto.zk.poseidon.Poseidon`
//! and `...crypto.zk.merkle.PoseidonMerkleTree`).
//!
//! This is the Rust analogue of metakit's circomlib-compatible Poseidon, written
//! to interoperate exactly with the JVM side (just as `jlvm-core` is byte-compatible
//! with the Scala JLVM). All arithmetic is done over `BigUint` reduced modulo the
//! BN254 scalar field modulus [`R`], mirroring Scala's `BigInt mod R` — this avoids
//! any Montgomery-representation subtleties and guarantees identical outputs.
//!
//! Construction (identical to circomlib's `poseidon([...])`):
//!   - S-box `x^5`, RF = 8 full rounds, RP partial rounds (per width t, see [`constants`]);
//!   - state initialised as `[0, in_0, ..., in_{n-1}]` (capacity element = 0), width `t = n + 1`;
//!   - the permutation runs once and `state[0]` is returned.
//!
//! HARD ACCEPTANCE VECTOR (circomlibjs):
//!   `poseidon([1, 2]) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a`.

pub mod constants;
pub mod merkle;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::sync::OnceLock;

/// The BN254 (alt_bn128) scalar field modulus `R`. Fr arithmetic is `BigUint`
/// reduced modulo `R`. Identical to `Poseidon.R` on the Scala side.
pub fn modulus() -> &'static BigUint {
    static R: OnceLock<BigUint> = OnceLock::new();
    R.get_or_init(|| {
        BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .expect("valid BN254 Fr modulus")
    })
}

/// True iff `x` is already a canonical field element, i.e. `0 <= x < R`.
/// (`BigUint` is always non-negative, so only the upper bound is checked.)
pub fn is_canonical(x: &BigUint) -> bool {
    x < modulus()
}

/// Reduce any `BigUint` into `[0, R)`.
pub fn reduce(x: &BigUint) -> BigUint {
    x % modulus()
}

/// Reject a non-canonical element, naming the role for a useful panic message.
fn require_canonical(x: &BigUint, role: &str) {
    assert!(
        is_canonical(x),
        "{role} is not a canonical BN254 field element (must be in [0, R)): {x}"
    );
}

/// Parse a decimal string constant into an Fr element (already canonical by construction).
fn fr(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).expect("valid decimal Fr constant")
}

/// Per-width Poseidon parameters (round constants + MDS), lazily materialised from
/// the bundled decimal-string tables into `BigUint`s.
struct Params {
    /// Flat round-constant vector of length `t * (RF + RP[t])`.
    c: Vec<BigUint>,
    /// `t x t` MDS matrix.
    m: Vec<Vec<BigUint>>,
    rf: usize,
    rp: usize,
    t: usize,
}

fn params(t: usize) -> &'static Params {
    // One cache slot per supported width (MIN_WIDTH..=MAX_WIDTH).
    static CACHE: OnceLock<Vec<OnceLock<Params>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        (0..=constants::MAX_WIDTH)
            .map(|_| OnceLock::new())
            .collect()
    });
    assert!(
        (constants::MIN_WIDTH..=constants::MAX_WIDTH).contains(&t),
        "Poseidon width t={t} unsupported (bundled t in {}..={})",
        constants::MIN_WIDTH,
        constants::MAX_WIDTH
    );
    cache[t].get_or_init(|| {
        let c: Vec<BigUint> = constants::round_constants_str(t)
            .iter()
            .map(|s| fr(s))
            .collect();
        let m: Vec<Vec<BigUint>> = constants::mds_matrix_str(t)
            .iter()
            .map(|row| row.iter().map(|s| fr(s)).collect())
            .collect();
        let rp = constants::PARTIAL_ROUNDS[t];
        Params {
            c,
            m,
            rf: constants::FULL_ROUNDS,
            rp,
            t,
        }
    })
}

/// `x^5 mod R`, the Poseidon S-box.
fn pow5(a: &BigUint, r: &BigUint) -> BigUint {
    let a2 = (a * a) % r;
    let a4 = (&a2 * &a2) % r;
    (&a4 * a) % r
}

/// Maximum number of inputs supported (width `t = n + 1`).
pub const MAX_INPUTS: usize = constants::MAX_WIDTH - 1;

/// Hash a slice of field elements with circomlib semantics.
///
/// Panics if `inputs` is empty, longer than [`MAX_INPUTS`], or contains a
/// non-canonical element (mirroring Scala's `require`s, which reject `>= R`).
pub fn hash(inputs: &[BigUint]) -> BigUint {
    assert!(
        !inputs.is_empty(),
        "Poseidon hash requires at least one input"
    );
    let t = inputs.len() + 1;
    assert!(
        t <= constants::MAX_WIDTH,
        "Poseidon hash supports at most {} inputs (width t <= {}); got {}",
        MAX_INPUTS,
        constants::MAX_WIDTH,
        inputs.len()
    );
    for (i, x) in inputs.iter().enumerate() {
        require_canonical(x, &format!("Poseidon input[{i}]"));
    }

    let r = modulus();
    // State is [capacity=0, in_0, in_1, ...]; circomlib initialises the capacity to 0.
    let mut state: Vec<BigUint> = Vec::with_capacity(t);
    state.push(BigUint::zero());
    state.extend(inputs.iter().cloned());

    permute(state, params(t), r)
}

/// Convenience 2-to-1 compression for use as a binary Merkle node hash.
/// Equivalent to `hash(&[left, right])` (width `t = 3`).
pub fn compress(left: &BigUint, right: &BigUint) -> BigUint {
    hash(&[left.clone(), right.clone()])
}

/// Run the full Poseidon permutation on `state` and return `state[0]`.
fn permute(state: Vec<BigUint>, p: &Params, r: &BigUint) -> BigUint {
    let t = p.t;
    let total_rounds = p.rf + p.rp;
    let half_rf = p.rf / 2;

    let mut s = state;
    for round in 0..total_rounds {
        // ARK: add round constants.
        let mut after_ark: Vec<BigUint> =
            (0..t).map(|i| (&s[i] + &p.c[round * t + i]) % r).collect();

        // S-box: full rounds apply x^5 to every element; partial rounds only to state[0].
        let is_full_round = round < half_rf || round >= half_rf + p.rp;
        if is_full_round {
            for x in after_ark.iter_mut() {
                *x = pow5(x, r);
            }
        } else {
            after_ark[0] = pow5(&after_ark[0], r);
        }

        // Mix: state[i] = sum_j M[i][j] * state[j].
        let mixed: Vec<BigUint> = (0..t)
            .map(|i| {
                let row = &p.m[i];
                let mut acc = BigUint::zero();
                for j in 0..t {
                    acc = (acc + &row[j] * &after_ark[j]) % r;
                }
                acc
            })
            .collect();

        s = mixed;
    }

    s.into_iter().next().expect("non-empty state")
}

/// The additive identity / canonical "empty leaf".
pub fn zero() -> BigUint {
    BigUint::zero()
}

/// The multiplicative identity, occasionally handy for callers.
pub fn one() -> BigUint {
    BigUint::one()
}
