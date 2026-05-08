//! Deprecated module path — use [`crate::r1::verify`] instead.
//!
//! Compat shim. See `src/sign_r1.rs` for the rationale.

#![allow(deprecated)]

pub use crate::r1::verify::verify as verify_r1;
pub use crate::r1::verify::verify_hash as verify_hash_r1;
pub use crate::r1::verify::verify_signature as verify_signature_r1;
