//! Generic Metagraph Client for any L1 layer type
//!
//! Works with ML0 (Metagraph L0), CL1 (Currency L1), and DL1 (Data L1) nodes.
//!
//! # Example
//!
//! ```ignore
//! use constellation_sdk::network::{MetagraphClient, LayerType};
//!
//! // Connect to a Currency L1 node
//! let cl1 = MetagraphClient::new("http://localhost:9300", LayerType::CL1)?;
//!
//! // Connect to a Data L1 node
//! let dl1 = MetagraphClient::new("http://localhost:9400", LayerType::DL1)?;
//!
//! // Connect to a Metagraph L0 node
//! let ml0 = MetagraphClient::new("http://localhost:9200", LayerType::ML0)?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::client::HttpClient;
use super::types::{
    EstimateFeeResponse, NetworkError, NetworkResult, PendingTransaction, PostDataResponse,
    PostTransactionResponse,
};
use crate::currency_types::{CurrencyTransaction, TransactionReference};
use crate::types::Signed;

/// Supported L1 layer types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LayerType {
    /// Metagraph L0 - state channel operations
    ML0,
    /// Currency L1 - currency transactions
    CL1,
    /// Data L1 - data/update submissions
    DL1,
}

impl LayerType {
    /// Get the string representation of the layer type
    pub fn as_str(&self) -> &'static str {
        match self {
            LayerType::ML0 => "ML0",
            LayerType::CL1 => "CL1",
            LayerType::DL1 => "DL1",
        }
    }
}

impl std::fmt::Display for LayerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cluster information from any L1 node
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInfo {
    /// Cluster node count
    #[serde(default)]
    pub size: Option<u32>,
    /// Cluster ID
    #[serde(default)]
    pub cluster_id: Option<String>,
    /// Additional fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Configuration for MetagraphClient
#[derive(Debug, Clone)]
pub struct MetagraphClientConfig {
    /// Base URL of the L1 node (e.g., "http://localhost:9200")
    pub base_url: String,
    /// Layer type for API path selection
    pub layer: LayerType,
    /// Request timeout in milliseconds (default: 30000)
    pub timeout: Option<u64>,
}

/// Generic client for interacting with any Metagraph L1 layer
///
/// This client provides a unified interface for ML0, CL1, and DL1 nodes,
/// automatically selecting the correct API paths based on layer type.
///
/// # Example
///
/// ```ignore
/// use constellation_sdk::network::{MetagraphClient, LayerType};
///
/// // Connect to a Currency L1 node
/// let cl1 = MetagraphClient::new("http://localhost:9300", LayerType::CL1)?;
/// let last_ref = cl1.get_last_reference("DAG...").await?;
///
/// // Connect to a Data L1 node
/// let dl1 = MetagraphClient::new("http://localhost:9400", LayerType::DL1)?;
/// let result = dl1.post_data(&signed_data).await?;
/// ```
pub struct MetagraphClient {
    client: HttpClient,
    layer: LayerType,
}

impl MetagraphClient {
    /// Create a new MetagraphClient
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL of the L1 node
    /// * `layer` - Layer type (ML0, CL1, or DL1)
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be initialized
    pub fn new(base_url: impl Into<String>, layer: LayerType) -> NetworkResult<Self> {
        let client = HttpClient::new(base_url, None)?;
        Ok(Self { client, layer })
    }

    /// Create a new MetagraphClient with full configuration
    pub fn with_config(config: MetagraphClientConfig) -> NetworkResult<Self> {
        let client = HttpClient::new(config.base_url, config.timeout)?;
        Ok(Self {
            client,
            layer: config.layer,
        })
    }

    /// Get the layer type of this client
    pub fn layer(&self) -> LayerType {
        self.layer
    }

    // ============================================
    // Common operations (all layers)
    // ============================================

    /// Check the health/availability of the node
    pub async fn check_health(&self) -> bool {
        self.client
            .get::<serde_json::Value>("/cluster/info")
            .await
            .is_ok()
    }

    /// Get cluster information
    pub async fn get_cluster_info(&self) -> NetworkResult<ClusterInfo> {
        self.client.get("/cluster/info").await
    }

    // ============================================
    // Currency operations (CL1 and ML0)
    // ============================================

    /// Get the last accepted transaction reference for an address
    ///
    /// This is needed to create a new transaction that chains from
    /// the address's most recent transaction.
    ///
    /// Available on: CL1, ML0 (if currency enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if called on an unsupported layer
    pub async fn get_last_reference(&self, address: &str) -> NetworkResult<TransactionReference> {
        self.assert_layer(&[LayerType::CL1, LayerType::ML0], "get_last_reference")?;
        self.client
            .get(&format!("/transactions/last-reference/{}", address))
            .await
    }

    /// Submit a signed currency transaction
    ///
    /// Available on: CL1
    ///
    /// # Errors
    ///
    /// Returns an error if called on an unsupported layer
    pub async fn post_transaction(
        &self,
        transaction: &CurrencyTransaction,
    ) -> NetworkResult<PostTransactionResponse> {
        self.assert_layer(&[LayerType::CL1], "post_transaction")?;
        self.client.post("/transactions", transaction).await
    }

    /// Get a pending transaction by hash
    ///
    /// Available on: CL1
    ///
    /// # Errors
    ///
    /// Returns an error if called on an unsupported layer
    pub async fn get_pending_transaction(
        &self,
        hash: &str,
    ) -> NetworkResult<Option<PendingTransaction>> {
        self.assert_layer(&[LayerType::CL1], "get_pending_transaction")?;
        match self.client.get(&format!("/transactions/{}", hash)).await {
            Ok(tx) => Ok(Some(tx)),
            Err(NetworkError::HttpError {
                status_code: Some(404),
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ============================================
    // Data operations (DL1)
    // ============================================

    /// Estimate the fee for submitting data
    ///
    /// Available on: DL1
    ///
    /// # Errors
    ///
    /// Returns an error if called on an unsupported layer
    pub async fn estimate_fee<T: Serialize>(
        &self,
        data: &Signed<T>,
    ) -> NetworkResult<EstimateFeeResponse> {
        self.assert_layer(&[LayerType::DL1], "estimate_fee")?;
        self.client.post("/data/estimate-fee", data).await
    }

    /// Submit signed data to the Data L1 node
    ///
    /// Available on: DL1
    ///
    /// # Errors
    ///
    /// Returns an error if called on an unsupported layer
    pub async fn post_data<T: Serialize>(
        &self,
        data: &Signed<T>,
    ) -> NetworkResult<PostDataResponse> {
        self.assert_layer(&[LayerType::DL1], "post_data")?;
        self.client.post("/data", data).await
    }

    // ============================================
    // Raw HTTP access
    // ============================================

    /// Make a raw GET request to the node
    pub async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> NetworkResult<T> {
        self.client.get(path).await
    }

    /// Make a raw POST request to the node
    pub async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> NetworkResult<T> {
        self.client.post(path, body).await
    }

    // ============================================
    // Helpers
    // ============================================

    fn assert_layer(&self, allowed: &[LayerType], method: &str) -> NetworkResult<()> {
        if !allowed.contains(&self.layer) {
            let allowed_str: Vec<&str> = allowed.iter().map(|l| l.as_str()).collect();
            return Err(NetworkError::ConfigError(format!(
                "{}() is not available on {} layer. Available on: {}",
                method,
                self.layer,
                allowed_str.join(", ")
            )));
        }
        Ok(())
    }
}

/// Create a MetagraphClient for a specific layer
///
/// # Arguments
///
/// * `base_url` - Node URL
/// * `layer` - Layer type
///
/// # Example
///
/// ```ignore
/// use constellation_sdk::network::{create_metagraph_client, LayerType};
///
/// let client = create_metagraph_client("http://localhost:9400", LayerType::DL1)?;
/// ```
pub fn create_metagraph_client(
    base_url: impl Into<String>,
    layer: LayerType,
) -> NetworkResult<MetagraphClient> {
    MetagraphClient::new(base_url, layer)
}
