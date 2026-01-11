//! Network operations for L1 node interactions
//!
//! This module provides HTTP clients for interacting with Constellation Network L1 nodes.
//!
//! # Features
//!
//! This module requires the `network` feature to be enabled:
//!
//! ```toml
//! [dependencies]
//! constellation-metagraph-sdk = { version = "0.1", features = ["network"] }
//! ```
//!
//! # Example
//!
//! ```ignore
//! use constellation_sdk::network::{CurrencyL1Client, NetworkConfig};
//!
//! let config = NetworkConfig {
//!     l1_url: Some("http://localhost:9010".to_string()),
//!     ..Default::default()
//! };
//!
//! let client = CurrencyL1Client::new(config)?;
//!
//! // Get last reference for an address
//! let last_ref = client.get_last_reference("DAG...").await?;
//!
//! // Submit a transaction
//! let result = client.post_transaction(&signed_tx).await?;
//! ```

mod client;
mod currency_l1_client;
mod data_l1_client;
mod types;

pub use client::HttpClient;
pub use currency_l1_client::CurrencyL1Client;
pub use data_l1_client::DataL1Client;
pub use types::*;
