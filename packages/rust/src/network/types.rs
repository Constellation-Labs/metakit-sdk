//! Network types for L1 client operations

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use crate::currency_types::CurrencyTransaction;

/// Network configuration for connecting to L1 nodes
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    /// Currency L1 endpoint URL (e.g., "http://localhost:9010")
    pub l1_url: Option<String>,
    /// Data L1 endpoint URL (e.g., "http://localhost:8080")
    pub data_l1_url: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout: Option<u64>,
}

/// Request options for individual requests
#[derive(Debug, Clone, Default)]
pub struct RequestOptions {
    /// Request timeout in seconds
    pub timeout: Option<u64>,
}

/// Transaction status in the network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    Waiting,
    InProgress,
    Accepted,
}

impl fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionStatus::Waiting => write!(f, "Waiting"),
            TransactionStatus::InProgress => write!(f, "InProgress"),
            TransactionStatus::Accepted => write!(f, "Accepted"),
        }
    }
}

/// Pending transaction response from L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    /// Transaction hash
    pub hash: String,
    /// Current status
    pub status: TransactionStatus,
    /// The transaction
    pub transaction: CurrencyTransaction,
}

/// Response from posting a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostTransactionResponse {
    /// Transaction hash
    pub hash: String,
}

/// Response from estimating data transaction fee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimateFeeResponse {
    /// Estimated fee in smallest units
    pub fee: i64,
    /// Fee destination address
    pub address: String,
}

/// Response from posting data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostDataResponse {
    /// Data hash
    pub hash: String,
}

/// Network error with status code and response details
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("HTTP error: {message}")]
    HttpError {
        message: String,
        status_code: Option<u16>,
        response: Option<String>,
    },

    #[error("Request timeout")]
    Timeout,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl NetworkError {
    pub fn http(
        message: impl Into<String>,
        status_code: Option<u16>,
        response: Option<String>,
    ) -> Self {
        NetworkError::HttpError {
            message: message.into(),
            status_code,
            response,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match self {
            NetworkError::HttpError { status_code, .. } => *status_code,
            _ => None,
        }
    }
}

/// Result type for network operations
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;
