//! Base HTTP client for network operations

use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

use super::types::{NetworkError, NetworkResult};

const DEFAULT_TIMEOUT: u64 = 30;

/// Simple HTTP client using reqwest
pub struct HttpClient {
    client: Client,
    base_url: String,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(base_url: impl Into<String>, timeout: Option<u64>) -> NetworkResult<Self> {
        let timeout_secs = timeout.unwrap_or(DEFAULT_TIMEOUT);
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| NetworkError::http(e.to_string(), None, None))?;

        let url = base_url.into();
        let base_url = url.trim_end_matches('/').to_string();

        Ok(Self { client, base_url })
    }

    /// Make a GET request
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> NetworkResult<T> {
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    NetworkError::Timeout
                } else {
                    NetworkError::http(e.to_string(), None, None)
                }
            })?;

        self.handle_response(response).await
    }

    /// Make a POST request
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> NetworkResult<T> {
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .post(&url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    NetworkError::Timeout
                } else {
                    NetworkError::http(e.to_string(), None, None)
                }
            })?;

        self.handle_response(response).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> NetworkResult<T> {
        let status = response.status();
        let status_code = status.as_u16();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(NetworkError::http(
                format!(
                    "HTTP {}: {}",
                    status_code,
                    status.canonical_reason().unwrap_or("Unknown")
                ),
                Some(status_code),
                Some(body),
            ));
        }

        response
            .json()
            .await
            .map_err(|e| NetworkError::SerializationError(e.to_string()))
    }
}
