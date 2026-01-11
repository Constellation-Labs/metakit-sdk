//! Tests for currency transaction functionality

use constellation_sdk::{
    create_currency_transaction, create_currency_transaction_batch, encode_currency_transaction,
    generate_key_pair, get_transaction_reference, hash_currency_transaction, is_valid_dag_address,
    sign_currency_transaction, token_to_units, units_to_token, verify_currency_transaction,
    SignatureProof, TransactionReference, TransferParams, TOKEN_DECIMALS,
};

#[cfg(test)]
mod utility_functions {
    use super::*;

    #[test]
    fn test_token_to_units_converts_correctly() {
        assert_eq!(token_to_units(100.5), 10050000000);
        assert_eq!(token_to_units(0.00000001), 1);
        assert_eq!(token_to_units(1.0), 100000000);
    }

    #[test]
    fn test_units_to_token_converts_correctly() {
        assert_eq!(units_to_token(10050000000), 100.5);
        assert_eq!(units_to_token(1), 0.00000001);
        assert_eq!(units_to_token(100000000), 1.0);
    }

    #[test]
    fn test_token_decimals_constant() {
        assert_eq!(TOKEN_DECIMALS, 1e-8);
    }

    #[test]
    fn test_is_valid_dag_address_validates_addresses() {
        let key_pair = generate_key_pair();
        assert!(is_valid_dag_address(&key_pair.address));
        assert!(!is_valid_dag_address("invalid"));
        assert!(!is_valid_dag_address(""));
        assert!(!is_valid_dag_address("DAG"));
    }
}

#[cfg(test)]
mod transaction_creation {
    use super::*;

    #[test]
    fn test_create_currency_transaction_creates_valid_transaction() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();

        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let tx = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 100.5,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref.clone(),
        )
        .unwrap();

        assert_eq!(tx.value.source, key_pair.address);
        assert_eq!(tx.value.destination, key_pair2.address);
        assert_eq!(tx.value.amount, 10050000000); // 100.5 * 1e8
        assert_eq!(tx.value.fee, 0);
        assert_eq!(tx.value.parent, last_ref);
        assert_eq!(tx.proofs.len(), 1);
        assert!(!tx.proofs[0].id.is_empty());
        assert!(!tx.proofs[0].signature.is_empty());
    }

    #[test]
    fn test_create_currency_transaction_throws_on_invalid_destination() {
        let key_pair = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let result = create_currency_transaction(
            TransferParams {
                destination: "invalid".to_string(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid destination address"));
    }

    #[test]
    fn test_create_currency_transaction_throws_on_same_address() {
        let key_pair = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let result = create_currency_transaction(
            TransferParams {
                destination: key_pair.address.clone(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Source and destination addresses cannot be the same"));
    }

    #[test]
    fn test_create_currency_transaction_throws_on_amount_too_small() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let result = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 0.000000001, // Less than 1e-8
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Transfer amount must be greater than 1e-8"));
    }

    #[test]
    fn test_create_currency_transaction_throws_on_negative_fee() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let result = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 100.0,
                fee: -1.0,
            },
            &key_pair.private_key,
            last_ref,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Fee must be greater than or equal to zero"));
    }
}

#[cfg(test)]
mod batch_transactions {
    use super::*;

    #[test]
    fn test_create_currency_transaction_batch_creates_multiple() {
        let key_pair = generate_key_pair();
        let recipient1 = generate_key_pair();
        let recipient2 = generate_key_pair();
        let recipient3 = generate_key_pair();

        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 5,
        };

        let transfers = vec![
            TransferParams {
                destination: recipient1.address.clone(),
                amount: 10.0,
                fee: 0.0,
            },
            TransferParams {
                destination: recipient2.address.clone(),
                amount: 20.0,
                fee: 0.0,
            },
            TransferParams {
                destination: recipient3.address.clone(),
                amount: 30.0,
                fee: 0.0,
            },
        ];

        let txns =
            create_currency_transaction_batch(transfers, &key_pair.private_key, last_ref).unwrap();

        assert_eq!(txns.len(), 3);
        assert_eq!(txns[0].value.amount, 1000000000); // 10 * 1e8
        assert_eq!(txns[1].value.amount, 2000000000); // 20 * 1e8
        assert_eq!(txns[2].value.amount, 3000000000); // 30 * 1e8

        // Check parent references are chained
        assert_eq!(txns[0].value.parent.ordinal, 5);
        assert_eq!(txns[1].value.parent.ordinal, 6);
        assert_eq!(txns[2].value.parent.ordinal, 7);
    }
}

#[cfg(test)]
mod transaction_verification {
    use super::*;

    #[test]
    fn test_verify_currency_transaction_validates_correct_signatures() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let tx = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        )
        .unwrap();

        let result = verify_currency_transaction(&tx);

        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 1);
        assert_eq!(result.invalid_proofs.len(), 0);
    }

    #[test]
    fn test_verify_currency_transaction_detects_invalid_signatures() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let mut tx = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        )
        .unwrap();

        // Replace with invalid proof
        tx.proofs[0] = SignatureProof {
            id: tx.proofs[0].id.clone(),
            signature: "invalid_signature".to_string(),
        };

        let result = verify_currency_transaction(&tx);

        assert!(!result.is_valid);
        assert_eq!(result.valid_proofs.len(), 0);
        assert_eq!(result.invalid_proofs.len(), 1);
    }
}

#[cfg(test)]
mod multi_signature_support {
    use super::*;

    #[test]
    fn test_sign_currency_transaction_adds_additional_signature() {
        let key_pair1 = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let recipient = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        // Create transaction with first signature
        let tx = create_currency_transaction(
            TransferParams {
                destination: recipient.address.clone(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair1.private_key,
            last_ref,
        )
        .unwrap();

        assert_eq!(tx.proofs.len(), 1);

        // Add second signature
        let tx = sign_currency_transaction(&tx, &key_pair2.private_key).unwrap();

        assert_eq!(tx.proofs.len(), 2);

        // Verify both signatures
        let result = verify_currency_transaction(&tx);

        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 2);
        assert_eq!(result.invalid_proofs.len(), 0);
    }
}

#[cfg(test)]
mod transaction_hashing {
    use super::*;

    #[test]
    fn test_hash_currency_transaction_produces_consistent_hashes() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let tx = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        )
        .unwrap();

        let hash1 = hash_currency_transaction(&tx);
        let hash2 = hash_currency_transaction(&tx);

        assert_eq!(hash1.value, hash2.value);
        assert_eq!(hash1.value.len(), 64); // SHA-256 hex string
        assert_eq!(hash1.bytes.len(), 32); // 32 bytes
    }

    #[test]
    fn test_get_transaction_reference_creates_correct_reference() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let tx = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        )
        .unwrap();

        let ref_result = get_transaction_reference(&tx, 1);

        assert_eq!(ref_result.ordinal, 1);
        assert_eq!(ref_result.hash.len(), 64);
    }

    #[test]
    fn test_encode_currency_transaction_returns_string() {
        let key_pair = generate_key_pair();
        let key_pair2 = generate_key_pair();
        let last_ref = TransactionReference {
            hash: "a".repeat(64),
            ordinal: 0,
        };

        let tx = create_currency_transaction(
            TransferParams {
                destination: key_pair2.address.clone(),
                amount: 100.0,
                fee: 0.0,
            },
            &key_pair.private_key,
            last_ref,
        )
        .unwrap();

        let encoded = encode_currency_transaction(&tx);

        assert!(!encoded.is_empty());
    }
}
