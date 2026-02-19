//! Network operations for Metagraph L1 node interactions
//!
//! This module provides a unified client for interacting with Constellation Network
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
//! // Currency L1 client
//! let cl1 = create_metagraph_client("http://localhost:9300", LayerType::CL1)?;
//! let last_ref = cl1.get_last_reference("DAG...").await?;
//! cl1.post_transaction(&signed_tx).await?;
//!
//! // Data L1 client
//! let dl1 = create_metagraph_client("http://localhost:9400", LayerType::DL1)?;
//! let fee = dl1.estimate_fee(&signed_data).await?;
//! dl1.post_data(&signed_data).await?;
//!
//! // Metagraph L0 client
//! let ml0 = create_metagraph_client("http://localhost:9200", LayerType::ML0)?;
//! let info = ml0.get_cluster_info().await?;
//! ```

mod client;
mod metagraph_client;
mod types;

// Generic metagraph client
pub use metagraph_client::{
    create_metagraph_client, ClusterInfo, LayerType, MetagraphClient, MetagraphClientConfig,
};

// HTTP client (for custom implementations)
pub use client::HttpClient;

// Types and errors
pub use types::{
    EstimateFeeResponse, NetworkError, PendingTransaction, PostDataResponse,
    PostTransactionResponse, RequestOptions, TransactionStatus,
};
