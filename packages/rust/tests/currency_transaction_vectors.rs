//! Currency transaction test vector validation
//!
//! Validates Rust implementation against reference test vectors from tessellation

use constellation_sdk::currency_transaction::*;
use constellation_sdk::currency_types::{TransactionReference, TransferParams};
use constellation_sdk::types::{SignatureProof, Signed};
use constellation_sdk::wallet::get_address;
use secp256k1::{Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Deserialize, Serialize)]
struct TestVectors {
    #[serde(rename = "cryptoParams")]
    crypto_params: CryptoParams,
    #[serde(rename = "testVectors")]
    test_vectors: TestVectorSet,
}

#[derive(Debug, Deserialize, Serialize)]
struct CryptoParams {
    #[serde(rename = "kryoSetReferences")]
    kryo_set_references: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct TestVectorSet {
    #[serde(rename = "basicTransaction")]
    basic_transaction: BasicTransaction,
    #[serde(rename = "encodingBreakdown")]
    encoding_breakdown: EncodingBreakdown,
    #[serde(rename = "multiSignature")]
    multi_signature: MultiSignature,
    #[serde(rename = "transactionChaining")]
    transaction_chaining: TransactionChaining,
    #[serde(rename = "edgeCases")]
    edge_cases: EdgeCases,
}

#[derive(Debug, Deserialize, Serialize)]
struct BasicTransaction {
    #[serde(rename = "privateKeyHex")]
    private_key_hex: String,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: String,
    address: String,
    transaction: serde_json::Value,
    #[serde(rename = "encodedString")]
    encoded_string: String,
    #[serde(rename = "kryoBytesHex")]
    kryo_bytes_hex: String,
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
    signature: String,
    #[serde(rename = "signerId")]
    signer_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct EncodingBreakdown {
    components: EncodingComponents,
    #[serde(rename = "fullEncoded")]
    full_encoded: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct EncodingComponents {
    #[serde(rename = "versionPrefix")]
    version_prefix: String,
    source: ComponentValue,
    destination: ComponentValue,
    #[serde(rename = "amountHex")]
    amount_hex: ComponentValue,
    #[serde(rename = "parentHash")]
    parent_hash: ComponentValue,
}

#[derive(Debug, Deserialize, Serialize)]
struct ComponentValue {
    length: i32,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct MultiSignature {
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
    proofs: Vec<SignatureProof>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TransactionChaining {
    transactions: Vec<ChainTransaction>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChainTransaction {
    index: i32,
    hash: String,
    ordinal: i64,
    #[serde(rename = "parentHash")]
    parent_hash: String,
    #[serde(rename = "parentOrdinal")]
    parent_ordinal: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct EdgeCases {
    #[serde(rename = "minAmount")]
    min_amount: EdgeCaseTransaction,
    #[serde(rename = "maxAmount")]
    max_amount: EdgeCaseTransaction,
    #[serde(rename = "withFee")]
    with_fee: EdgeCaseWithFee,
}

#[derive(Debug, Deserialize, Serialize)]
struct EdgeCaseTransaction {
    amount: i64,
    hash: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct EdgeCaseWithFee {
    amount: i64,
    fee: i64,
    hash: String,
    signature: String,
}

fn load_test_vectors() -> TestVectors {
    let vectors_path = "../../shared/currency_transaction_vectors.json";
    let data = fs::read_to_string(vectors_path).expect("Failed to read test vectors");
    serde_json::from_str(&data).expect("Failed to parse test vectors")
}

#[test]
fn test_public_key_derivation() {
    let vectors = load_test_vectors();
    let basic = &vectors.test_vectors.basic_transaction;

    let secret_key = SecretKey::from_slice(&hex::decode(&basic.private_key_hex).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize_uncompressed());

    assert_eq!(public_key_hex, basic.public_key_hex);
}

#[test]
fn test_address_derivation() {
    let vectors = load_test_vectors();
    let basic = &vectors.test_vectors.basic_transaction;

    let secret_key = SecretKey::from_slice(&hex::decode(&basic.private_key_hex).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize_uncompressed());
    let address = get_address(&public_key_hex);

    assert_eq!(address, basic.address);
}

#[test]
fn test_encoding_format() {
    let vectors = load_test_vectors();
    let basic = &vectors.test_vectors.basic_transaction;
    let tx_data: HashMap<String, serde_json::Value> =
        serde_json::from_value(basic.transaction.clone()).unwrap();

    // Extract transaction details
    let destination = tx_data["destination"].as_str().unwrap();
    let amount = tx_data["amount"].as_i64().unwrap();
    let fee = tx_data["fee"].as_i64().unwrap();
    let parent = tx_data["parent"].as_object().unwrap();
    let parent_hash = parent["hash"].as_str().unwrap();
    let parent_ordinal = parent["ordinal"].as_i64().unwrap();

    // Create transaction
    let mut tx = create_currency_transaction(
        TransferParams {
            destination: destination.to_string(),
            amount: amount as f64 / 1e8,
            fee: fee as f64 / 1e8,
        },
        &basic.private_key_hex,
        TransactionReference {
            hash: parent_hash.to_string(),
            ordinal: parent_ordinal,
        },
    )
    .unwrap();

    // Override salt for deterministic test
    tx.value.salt = tx_data["salt"].as_i64().unwrap().to_string();
    tx.proofs = vec![];

    let encoded = encode_currency_transaction(&tx);
    assert_eq!(encoded, basic.encoded_string);
}

#[test]
fn test_encoding_breakdown() {
    let vectors = load_test_vectors();
    let breakdown = &vectors.test_vectors.encoding_breakdown;
    let components = &breakdown.components;

    // Verify version prefix
    assert_eq!(components.version_prefix, "2");

    // Verify components are present in full encoding
    let full_encoded = &breakdown.full_encoded;
    assert!(full_encoded.starts_with("2"));
    assert!(full_encoded.contains(&components.source.value));
    assert!(full_encoded.contains(&components.destination.value));
    assert!(full_encoded.contains(&components.amount_hex.value));
    assert!(full_encoded.contains(&components.parent_hash.value));
}

#[test]
fn test_transaction_hash() {
    let vectors = load_test_vectors();
    let basic = &vectors.test_vectors.basic_transaction;
    let tx_data: HashMap<String, serde_json::Value> =
        serde_json::from_value(basic.transaction.clone()).unwrap();

    // Extract transaction details
    let destination = tx_data["destination"].as_str().unwrap();
    let amount = tx_data["amount"].as_i64().unwrap();
    let fee = tx_data["fee"].as_i64().unwrap();
    let parent = tx_data["parent"].as_object().unwrap();
    let parent_hash = parent["hash"].as_str().unwrap();
    let parent_ordinal = parent["ordinal"].as_i64().unwrap();

    // Create transaction
    let mut tx = create_currency_transaction(
        TransferParams {
            destination: destination.to_string(),
            amount: amount as f64 / 1e8,
            fee: fee as f64 / 1e8,
        },
        &basic.private_key_hex,
        TransactionReference {
            hash: parent_hash.to_string(),
            ordinal: parent_ordinal,
        },
    )
    .unwrap();

    // Override salt for exact match
    tx.value.salt = tx_data["salt"].as_i64().unwrap().to_string();
    tx.proofs = vec![];

    let hash = hash_currency_transaction(&tx);
    assert_eq!(hash.value, basic.transaction_hash);
}

#[test]
fn test_reference_signature() {
    let vectors = load_test_vectors();
    let basic = &vectors.test_vectors.basic_transaction;
    let tx_value: serde_json::Value = basic.transaction.clone();

    // Reconstruct transaction from test vector
    let tx = Signed {
        value: serde_json::from_value(tx_value).unwrap(),
        proofs: vec![SignatureProof {
            id: basic.signer_id.clone(),
            signature: basic.signature.clone(),
        }],
    };

    let result = verify_currency_transaction(&tx);
    assert!(result.is_valid);
    assert_eq!(result.valid_proofs.len(), 1);
    assert_eq!(result.invalid_proofs.len(), 0);
}

#[test]
fn test_multi_signature() {
    let vectors = load_test_vectors();
    let basic = &vectors.test_vectors.basic_transaction;
    let multi_sig = &vectors.test_vectors.multi_signature;
    let tx_value: serde_json::Value = basic.transaction.clone();

    // Reconstruct transaction with multiple proofs
    let tx = Signed {
        value: serde_json::from_value(tx_value).unwrap(),
        proofs: multi_sig.proofs.clone(),
    };

    let result = verify_currency_transaction(&tx);

    assert!(result.is_valid, "Multi-sig transaction should be valid");
    assert_eq!(result.valid_proofs.len(), 2, "Should have 2 valid proofs");
    assert_eq!(
        result.invalid_proofs.len(),
        0,
        "Should have 0 invalid proofs"
    );
}

#[test]
fn test_chain_parent_references() {
    let vectors = load_test_vectors();
    let chain = &vectors.test_vectors.transaction_chaining.transactions;

    // Verify first transaction parent
    assert_eq!(
        chain[0].parent_hash,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(chain[0].parent_ordinal, 5);
    assert_eq!(chain[0].ordinal, 6);

    // Verify second transaction chains to first
    assert_eq!(chain[1].parent_hash, chain[0].hash);
    assert_eq!(chain[1].parent_ordinal, chain[0].ordinal);
    assert_eq!(chain[1].ordinal, 7);

    // Verify third transaction chains to second
    assert_eq!(chain[2].parent_hash, chain[1].hash);
    assert_eq!(chain[2].parent_ordinal, chain[1].ordinal);
    assert_eq!(chain[2].ordinal, 8);
}

#[test]
fn test_minimum_amount() {
    let vectors = load_test_vectors();
    let min_amount = &vectors.test_vectors.edge_cases.min_amount;

    assert_eq!(min_amount.amount, 1);
    assert!(!min_amount.hash.is_empty());
    assert!(!min_amount.signature.is_empty());
}

#[test]
fn test_maximum_amount() {
    let vectors = load_test_vectors();
    let max_amount = &vectors.test_vectors.edge_cases.max_amount;

    assert_eq!(max_amount.amount, 9223372036854775807);
    assert!(!max_amount.hash.is_empty());
    assert!(!max_amount.signature.is_empty());
}

#[test]
fn test_non_zero_fee() {
    let vectors = load_test_vectors();
    let with_fee = &vectors.test_vectors.edge_cases.with_fee;

    assert_eq!(with_fee.amount, 10000000000);
    assert_eq!(with_fee.fee, 100000);
    assert!(!with_fee.hash.is_empty());
    assert!(!with_fee.signature.is_empty());
}

#[test]
fn test_kryo_set_references_flag() {
    let vectors = load_test_vectors();
    // v2 transactions use setReferences=false
    assert!(!vectors.crypto_params.kryo_set_references);
}

#[test]
fn test_kryo_header() {
    let vectors = load_test_vectors();
    let basic = &vectors.test_vectors.basic_transaction;
    let kryo_hex = &basic.kryo_bytes_hex;

    // Should start with 0x03 (string type) followed by length, no 0x01 reference flag for v2
    assert!(kryo_hex.starts_with("03"));
    assert!(!kryo_hex.starts_with("0301")); // No reference flag for v2
}
