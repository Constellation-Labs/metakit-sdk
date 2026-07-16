//! secp256r1 (NIST P-256) signing module.
//!
//! Mirrors the layout of the secp256k1 (K1) functions at the crate
//! root — `sign`, `verify`, `wallet`, `signed_object` — but uses the
//! P-256 curve. This is the curve that TPM 2.0 hardware natively
//! supports; a typical use-case is a TPM-backed device signer
//! producing R1 proofs that flow into a wider K1-signed pipeline.
//!
//! ## Cargo feature
//!
//! This module is gated behind the `r1` cargo feature so consumers
//! who only need K1 signing don't pull in the `p256` / `ecdsa`
//! dependency tree:
//!
//! ```toml
//! [dependencies]
//! constellation-metagraph-sdk-core = { version = "1.8", features = ["r1"] }
//! ```
//!
//! Without the feature, importing `constellation_sdk_core::r1` is a
//! compile error — the K1 functions at the crate root continue to
//! work unchanged.
//!
//! ## TS / Python parity (status)
//!
//! As of this writing R1 exists only in the Rust SDK. Cross-language
//! interop with TS or Python R1 verifiers is therefore not yet
//! possible. K1 (the crate root) is fully cross-language compatible.

pub mod sign;
pub mod signed_object;
pub mod verify;
pub mod wallet;
