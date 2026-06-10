//! Acceptance + cross-check vectors for the Rust Poseidon, taken verbatim from
//! metakit's Scala `PoseidonSuite` (circomlibjs reference vectors). If these pass,
//! the Rust hash is byte-for-byte interoperable with the Scala/JVM Poseidon.

use num_bigint::BigUint;
use poseidon_bn254::{compress, hash, is_canonical, modulus};

fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}
fn hexf(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
}
fn to_hex(x: &BigUint) -> String {
    format!("0x{:064x}", x)
}

#[test]
fn hard_acceptance_gate_poseidon_1_2() {
    // poseidon([1, 2]) MUST equal this; otherwise the params are wrong.
    let expected = hexf("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
    let got = hash(&[BigUint::from(1u8), BigUint::from(2u8)]);
    println!("poseidon([1,2]) = {}", to_hex(&got));
    assert_eq!(
        got, expected,
        "HARD ACCEPTANCE GATE FAILED: poseidon([1,2]) mismatch"
    );
}

#[test]
fn vector_poseidon_1() {
    let expected =
        dec("18586133768512220936620570745912940619677854269274689475585506675881198879027");
    assert_eq!(hash(&[BigUint::from(1u8)]), expected);
}

#[test]
fn vector_poseidon_1_2_3_4() {
    let expected = hexf("299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465");
    let got = hash(&[
        BigUint::from(1u8),
        BigUint::from(2u8),
        BigUint::from(3u8),
        BigUint::from(4u8),
    ]);
    assert_eq!(got, expected);
}

#[test]
fn vector_poseidon_3_4_5() {
    let expected =
        dec("16070431878087339506657234884858910435593423055199073760739081656581316900759");
    let got = hash(&[BigUint::from(3u8), BigUint::from(4u8), BigUint::from(5u8)]);
    assert_eq!(got, expected);
}

#[test]
fn vector_poseidon_r_minus_1() {
    let r_minus_1 = modulus() - 1u32;
    let expected =
        dec("3366645945435192953002076803303112651887535928162668198103357554665518664470");
    assert_eq!(hash(&[r_minus_1]), expected);
}

#[test]
fn compress_equals_hash_pair() {
    let a = dec("12345678901234567890");
    let b = dec("98765432109876543210");
    assert_eq!(compress(&a, &b), hash(&[a.clone(), b.clone()]));
}

#[test]
fn compress_matches_1_2_vector() {
    let expected = hexf("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
    assert_eq!(compress(&BigUint::from(1u8), &BigUint::from(2u8)), expected);
}

#[test]
fn output_is_canonical() {
    let h = hash(&[BigUint::from(1u8), BigUint::from(2u8)]);
    assert!(is_canonical(&h));
}

#[test]
#[should_panic]
fn rejects_input_ge_r() {
    let _ = hash(&[modulus().clone()]); // exactly R is out of range
}

#[test]
fn order_matters() {
    let h1 = hash(&[BigUint::from(1u8), BigUint::from(2u8)]);
    let h2 = hash(&[BigUint::from(2u8), BigUint::from(1u8)]);
    assert_ne!(h1, h2);
}

/// Emit a few sample hashes so they can be diffed against the Scala side.
#[test]
fn emit_sample_hashes() {
    println!("--- Poseidon sample hashes (hex) for cross-check vs Scala ---");
    println!(
        "poseidon([1])       = {}",
        to_hex(&hash(&[BigUint::from(1u8)]))
    );
    println!(
        "poseidon([7])       = {}",
        to_hex(&hash(&[BigUint::from(7u8)]))
    );
    println!(
        "poseidon([1,2])     = {}",
        to_hex(&hash(&[BigUint::from(1u8), BigUint::from(2u8)]))
    );
    println!(
        "poseidon([3,4,5])   = {}",
        to_hex(&hash(&[
            BigUint::from(3u8),
            BigUint::from(4u8),
            BigUint::from(5u8)
        ]))
    );
    println!(
        "poseidon([1,2,3,4]) = {}",
        to_hex(&hash(&[
            BigUint::from(1u8),
            BigUint::from(2u8),
            BigUint::from(3u8),
            BigUint::from(4u8)
        ]))
    );
}
