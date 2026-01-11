//! Currency L1 client for submitting and querying transactions

use super::client::HttpClient;
use super::types::{
    NetworkConfig, NetworkError, NetworkResult, PendingTransaction, PostTransactionResponse,
};
use crate::currency_types::{CurrencyTransaction, TransactionReference};

/// Client for interacting with Currency L1 nodes
///
/// # Example
///
/// ```ignore
/// use constellation_sdk::network::{CurrencyL1Client, NetworkConfig};
///
/// let config = NetworkConfig {
///     l1_url: Some("http://localhost:9010".to_string()),
///     ..Default::default()
/// };
///
/// let client = CurrencyL1Client::new(config)?;
///
/// // Get last reference for an address
/// let last_ref = client.get_last_reference("DAG...").await?;
///
/// // Submit a transaction
/// let result = client.post_transaction(&signed_tx).await?;
///
/// // Check transaction status
/// if let Some(pending) = client.get_pending_transaction(&result.hash).await? {
///     println!("Status: {:?}", pending.status);
/// }
/// ```
pub struct CurrencyL1Client {
    client: HttpClient,
}

impl CurrencyL1Client {
    /// Create a new CurrencyL1Client
    ///
    /// # Errors
    ///
    /// Returns an error if l1_url is not provided in the config
    pub fn new(config: NetworkConfig) -> NetworkResult<Self> {
        let l1_url = config.l1_url.ok_or_else(|| {
            NetworkError::ConfigError("l1_url is required for CurrencyL1Client".into())
        })?;

        let client = HttpClient::new(l1_url, config.timeout)?;
        Ok(Self { client })
    }

    /// Get the last accepted transaction reference for an address
    ///
    /// This is needed to create a new transaction that chains from
    /// the address's most recent transaction.
    pub async fn get_last_reference(&self, address: &str) -> NetworkResult<TransactionReference> {
        self.client
            .get(&format!("/transactions/last-reference/{}", address))
            .await
    }

    /// Submit a signed currency transaction to the L1 network
    pub async fn post_transaction(
        &self,
        transaction: &CurrencyTransaction,
    ) -> NetworkResult<PostTransactionResponse> {
        self.client.post("/transactions", transaction).await
    }

    /// Get a pending transaction by hash
    ///
    /// Use this to poll for transaction status after submission.
    /// Returns None if the transaction is not found (already confirmed or invalid).
    pub async fn get_pending_transaction(
        &self,
        hash: &str,
    ) -> NetworkResult<Option<PendingTransaction>> {
        match self.client.get(&format!("/transactions/{}", hash)).await {
            Ok(tx) => Ok(Some(tx)),
            Err(NetworkError::HttpError {
                status_code: Some(404),
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Check the health/availability of the L1 node
    pub async fn check_health(&self) -> bool {
        self.client
            .get::<serde_json::Value>("/cluster/info")
            .await
            .is_ok()
    }
}
