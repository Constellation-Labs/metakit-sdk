//! Deprecated module path — use [`crate::r1::signed_object`] instead.
//!
//! Compat shim. See `src/sign_r1.rs` for the rationale.

#![allow(deprecated)]

pub use crate::r1::signed_object::add_signature as add_signature_r1;
pub use crate::r1::signed_object::batch_sign as batch_sign_r1;
pub use crate::r1::signed_object::create_signed_object as create_signed_object_r1;
