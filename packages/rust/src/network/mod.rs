//! Network operations for Metagraph L1 node interactions
//!
//! This module provides clients for interacting with Constellation Network
//! metagraph nodes at various layers:
//!
//! - **ML0** (Metagraph L0): State channel operations
//! - **CL1** (Currency L1): Currency transactions
//! - **DL1** (Data L1): Data/update submissions
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
//! use constellation_sdk::network::{MetagraphClient, LayerType, create_metagraph_client};
//!
//! // Generic client for any layer
//! let dl1 = create_metagraph_client("http://localhost:9400", LayerType::DL1)?;
//! let result = dl1.post_data(&signed_data).await?;
//!
//! // Or use convenience clients
//! use constellation_sdk::network::{CurrencyL1Client, NetworkConfig};
//!
//! let config = NetworkConfig {
//!     l1_url: Some("http://localhost:9010".to_string()),
//!     ..Default::default()
//! };
//!
//! let client = CurrencyL1Client::new(config)?;
//! let last_ref = client.get_last_reference("DAG...").await?;
//! ```

mod client;
mod currency_l1_client;
mod data_l1_client;
mod metagraph_client;
mod types;

// Generic metagraph client
pub use metagraph_client::{
    create_metagraph_client, ClusterInfo, LayerType, MetagraphClient, MetagraphClientConfig,
};

// Convenience clients (backwards compatible)
pub use currency_l1_client::CurrencyL1Client;
pub use data_l1_client::DataL1Client;

// HTTP client (for custom implementations)
pub use client::HttpClient;

// Types and errors
pub use types::*;
