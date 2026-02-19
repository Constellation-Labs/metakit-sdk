//! Tests for network operations

#[cfg(feature = "network")]
mod network_tests {
    use constellation_sdk::network::{
        create_metagraph_client, LayerType, MetagraphClient, MetagraphClientConfig, NetworkError,
    };

    mod metagraph_client {
        use super::*;

        #[test]
        fn requires_base_url() {
            let result = MetagraphClient::new("", LayerType::DL1);
            assert!(result.is_err());
        }

        #[test]
        fn creates_client_for_dl1() {
            let client = MetagraphClient::new("http://localhost:9400", LayerType::DL1).unwrap();
            assert_eq!(client.layer(), LayerType::DL1);
        }

        #[test]
        fn creates_client_for_cl1() {
            let client = MetagraphClient::new("http://localhost:9300", LayerType::CL1).unwrap();
            assert_eq!(client.layer(), LayerType::CL1);
        }

        #[test]
        fn creates_client_for_ml0() {
            let client = MetagraphClient::new("http://localhost:9200", LayerType::ML0).unwrap();
            assert_eq!(client.layer(), LayerType::ML0);
        }

        #[test]
        fn accepts_config_with_timeout() {
            let config = MetagraphClientConfig {
                base_url: "http://localhost:9400".to_string(),
                layer: LayerType::DL1,
                timeout: Some(5000),
            };
            let client = MetagraphClient::with_config(config).unwrap();
            assert_eq!(client.layer(), LayerType::DL1);
        }
    }

    mod create_metagraph_client_helper {
        use super::*;

        #[test]
        fn creates_client_with_convenience_function() {
            let client = create_metagraph_client("http://localhost:9400", LayerType::DL1).unwrap();
            assert_eq!(client.layer(), LayerType::DL1);
        }
    }

    mod layer_type {
        use super::*;

        #[test]
        fn has_correct_string_representation() {
            assert_eq!(LayerType::ML0.as_str(), "ML0");
            assert_eq!(LayerType::CL1.as_str(), "CL1");
            assert_eq!(LayerType::DL1.as_str(), "DL1");
        }

        #[test]
        fn implements_display() {
            assert_eq!(format!("{}", LayerType::ML0), "ML0");
            assert_eq!(format!("{}", LayerType::CL1), "CL1");
            assert_eq!(format!("{}", LayerType::DL1), "DL1");
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

    mod combined_usage {
        use super::*;

        #[test]
        fn creates_multiple_clients_for_different_layers() {
            let cl1 = create_metagraph_client("http://localhost:9300", LayerType::CL1).unwrap();
            let dl1 = create_metagraph_client("http://localhost:9400", LayerType::DL1).unwrap();
            let ml0 = create_metagraph_client("http://localhost:9200", LayerType::ML0).unwrap();

            assert_eq!(cl1.layer(), LayerType::CL1);
            assert_eq!(dl1.layer(), LayerType::DL1);
            assert_eq!(ml0.layer(), LayerType::ML0);
        }
    }
}
