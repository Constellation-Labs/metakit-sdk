//! Data L1 client for submitting data transactions to metagraphs

use serde::Serialize;

use super::client::HttpClient;
use super::types::{
    EstimateFeeResponse, NetworkConfig, NetworkError, NetworkResult, PostDataResponse,
};
use crate::types::Signed;

/// Client for interacting with Data L1 nodes (metagraphs)
///
/// # Example
///
/// ```ignore
/// use constellation_sdk::network::{DataL1Client, NetworkConfig};
///
/// let config = NetworkConfig {
///     data_l1_url: Some("http://localhost:8080".to_string()),
///     ..Default::default()
/// };
///
/// let client = DataL1Client::new(config)?;
///
/// // Estimate fee for data submission
/// let fee_info = client.estimate_fee(&signed_data).await?;
///
/// // Submit data
/// let result = client.post_data(&signed_data).await?;
/// ```
pub struct DataL1Client {
    client: HttpClient,
}

impl DataL1Client {
    /// Create a new DataL1Client
    ///
    /// # Errors
    ///
    /// Returns an error if data_l1_url is not provided in the config
    pub fn new(config: NetworkConfig) -> NetworkResult<Self> {
        let data_l1_url = config.data_l1_url.ok_or_else(|| {
            NetworkError::ConfigError("data_l1_url is required for DataL1Client".into())
        })?;

        let client = HttpClient::new(data_l1_url, config.timeout)?;
        Ok(Self { client })
    }

    /// Estimate the fee for submitting data
    ///
    /// Some metagraphs charge fees for data submissions.
    /// Call this before post_data to know the required fee.
    pub async fn estimate_fee<T: Serialize>(
        &self,
        data: &Signed<T>,
    ) -> NetworkResult<EstimateFeeResponse> {
        self.client.post("/data/estimate-fee", data).await
    }

    /// Submit signed data to the Data L1 node
    pub async fn post_data<T: Serialize>(
        &self,
        data: &Signed<T>,
    ) -> NetworkResult<PostDataResponse> {
        self.client.post("/data", data).await
    }

    /// Check the health/availability of the Data L1 node
    pub async fn check_health(&self) -> bool {
        self.client
            .get::<serde_json::Value>("/cluster/info")
            .await
            .is_ok()
    }
}
