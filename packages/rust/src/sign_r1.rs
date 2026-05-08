//! Deprecated module path — use [`crate::r1::sign`] instead.
//!
//! This file used to host the R1 signing implementation. The
//! implementation has moved into the `r1/` submodule alongside the
//! parallel `r1::verify` / `r1::wallet` / `r1::signed_object`
//! modules; this file remains as a thin re-export shim so existing
//! imports of the form
//!
//! ```ignore
//! use constellation_sdk::sign_r1::sign_hash_r1;
//! ```
//!
//! keep working unchanged. New code should prefer
//! `constellation_sdk::r1::sign::sign_hash`.

#![allow(deprecated)]

pub use crate::r1::sign::sign as sign_r1;
pub use crate::r1::sign::sign_data_update as sign_data_update_r1;
pub use crate::r1::sign::sign_hash as sign_hash_r1;
