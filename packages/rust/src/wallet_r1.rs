//! Deprecated module path — use [`crate::r1::wallet`] instead.
//!
//! Compat shim. See `src/sign_r1.rs` for the rationale.

#![allow(deprecated)]

pub use crate::r1::wallet::generate_key_pair as generate_key_pair_r1;
pub use crate::r1::wallet::get_address as get_address_r1;
pub use crate::r1::wallet::get_public_key_hex as get_public_key_hex_r1;
pub use crate::r1::wallet::get_public_key_id as get_public_key_id_r1;
pub use crate::r1::wallet::id_to_public_key as id_to_public_key_r1;
pub use crate::r1::wallet::is_valid_private_key as is_valid_private_key_r1;
pub use crate::r1::wallet::key_pair_from_private_key as key_pair_from_private_key_r1;
pub use crate::r1::wallet::normalize_public_key as normalize_public_key_r1;
pub use crate::r1::wallet::normalize_public_key_to_id as normalize_public_key_to_id_r1;
