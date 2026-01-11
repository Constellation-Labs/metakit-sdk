//! Tests for network operations

#[cfg(feature = "network")]
mod network_tests {
    use constellation_sdk::network::{CurrencyL1Client, DataL1Client, NetworkConfig, NetworkError};

    mod currency_l1_client {
        use super::*;

        #[test]
        fn requires_l1_url_in_config() {
            let config = NetworkConfig::default();
            let result = CurrencyL1Client::new(config);
            assert!(result.is_err());
            match result {
                Err(NetworkError::ConfigError(msg)) => {
                    assert!(msg.contains("l1_url is required"));
                }
                _ => panic!("Expected ConfigError"),
            }
        }

        #[test]
        fn creates_client_with_valid_config() {
            let config = NetworkConfig {
                l1_url: Some("http://localhost:9010".to_string()),
                ..Default::default()
            };
            let result = CurrencyL1Client::new(config);
            assert!(result.is_ok());
        }

        #[test]
        fn accepts_optional_timeout() {
            let config = NetworkConfig {
                l1_url: Some("http://localhost:9010".to_string()),
                timeout: Some(5),
                ..Default::default()
            };
            let result = CurrencyL1Client::new(config);
            assert!(result.is_ok());
        }
    }

    mod data_l1_client {
        use super::*;

        #[test]
        fn requires_data_l1_url_in_config() {
            let config = NetworkConfig::default();
            let result = DataL1Client::new(config);
            assert!(result.is_err());
            match result {
                Err(NetworkError::ConfigError(msg)) => {
                    assert!(msg.contains("data_l1_url is required"));
                }
                _ => panic!("Expected ConfigError"),
            }
        }

        #[test]
        fn creates_client_with_valid_config() {
            let config = NetworkConfig {
                data_l1_url: Some("http://localhost:8080".to_string()),
                ..Default::default()
            };
            let result = DataL1Client::new(config);
            assert!(result.is_ok());
        }

        #[test]
        fn accepts_optional_timeout() {
            let config = NetworkConfig {
                data_l1_url: Some("http://localhost:8080".to_string()),
                timeout: Some(10),
                ..Default::default()
            };
            let result = DataL1Client::new(config);
            assert!(result.is_ok());
        }
    }

    mod network_error {
        use super::*;

        #[test]
        fn creates_error_with_message_only() {
            let error = NetworkError::http("Connection failed", None, None);
            assert!(error.to_string().contains("Connection failed"));
            assert_eq!(error.status_code(), None);
        }

        #[test]
        fn creates_error_with_status_code() {
            let error = NetworkError::http("Not found", Some(404), None);
            assert!(error.to_string().contains("Not found"));
            assert_eq!(error.status_code(), Some(404));
        }

        #[test]
        fn creates_error_with_response_body() {
            let error = NetworkError::http(
                "Bad request",
                Some(400),
                Some(r#"{"error":"invalid"}"#.to_string()),
            );
            assert_eq!(error.status_code(), Some(400));
        }
    }

    mod combined_config {
        use super::*;

        #[test]
        fn allows_both_urls_in_same_config() {
            let config = NetworkConfig {
                l1_url: Some("http://localhost:9010".to_string()),
                data_l1_url: Some("http://localhost:8080".to_string()),
                timeout: Some(30),
            };

            let l1_client = CurrencyL1Client::new(config.clone());
            let data_client = DataL1Client::new(config);

            assert!(l1_client.is_ok());
            assert!(data_client.is_ok());
        }
    }
}
