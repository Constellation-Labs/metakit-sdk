//! Integration tests for the Constellation Metagraph SDK

use constellation_sdk::{
    add_signature, batch_sign, canonicalize, create_signed_object, decode_data_update,
    encode_data_update, generate_key_pair, hash_data, key_pair_from_private_key, sign,
    sign_data_update, to_bytes, verify, verify_signature, Signed,
};
use serde_json::json;

mod key_generation {
    use super::*;

    #[test]
    fn generates_valid_key_pair() {
        let key_pair = generate_key_pair();

        assert_eq!(key_pair.private_key.len(), 64, "Private key should be 64 hex chars");
        assert_eq!(key_pair.public_key.len(), 130, "Public key should be 130 hex chars");
        assert!(
            key_pair.address.starts_with("DAG"),
            "Address should start with DAG"
        );
    }

    #[test]
    fn derives_consistent_key_pair() {
        let original = generate_key_pair();
        let derived = key_pair_from_private_key(&original.private_key).unwrap();

        assert_eq!(derived.public_key, original.public_key);
        assert_eq!(derived.address, original.address);
    }

    #[test]
    fn generates_unique_key_pairs() {
        let key1 = generate_key_pair();
        let key2 = generate_key_pair();

        assert_ne!(key1.private_key, key2.private_key);
        assert_ne!(key1.public_key, key2.public_key);
        assert_ne!(key1.address, key2.address);
    }
}

mod regular_signing {
    use super::*;

    #[test]
    fn signs_and_verifies_data() {
        let key_pair = generate_key_pair();
        let data = json!({
            "action": "test",
            "value": 42
        });

        let signed = create_signed_object(&data, &key_pair.private_key, false).unwrap();
        let result = verify(&signed, false);

        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 1);
        assert!(result.invalid_proofs.is_empty());
    }

    #[test]
    fn produces_consistent_signatures() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});

        let proof1 = sign(&data, &key_pair.private_key).unwrap();
        let proof2 = sign(&data, &key_pair.private_key).unwrap();

        // Same public key
        assert_eq!(proof1.id, proof2.id);
        // Both should verify
        assert!(verify_signature(&data, &proof1, false).unwrap());
        assert!(verify_signature(&data, &proof2, false).unwrap());
    }

    #[test]
    fn signature_contains_public_key_id() {
        let key_pair = generate_key_pair();
        let data = json!({"test": true});

        let proof = sign(&data, &key_pair.private_key).unwrap();

        // ID should be public key without 04 prefix
        assert_eq!(proof.id.len(), 128);
        assert_eq!(proof.id, key_pair.public_key[2..]); // Skip 04 prefix
    }
}

mod data_update_signing {
    use super::*;

    #[test]
    fn signs_and_verifies_data_update() {
        let key_pair = generate_key_pair();
        let data = json!({
            "id": "update-001",
            "value": 123
        });

        let signed = create_signed_object(&data, &key_pair.private_key, true).unwrap();
        let result = verify(&signed, true);

        assert!(result.is_valid);
    }

    #[test]
    fn data_update_verification_fails_with_wrong_mode() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});

        // Sign as DataUpdate
        let signed = create_signed_object(&data, &key_pair.private_key, true).unwrap();

        // Verify as regular (should fail)
        let result = verify(&signed, false);
        assert!(!result.is_valid);
    }

    #[test]
    fn produces_different_signatures_than_regular() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});

        let regular_proof = sign(&data, &key_pair.private_key).unwrap();
        let update_proof = sign_data_update(&data, &key_pair.private_key).unwrap();

        // Same key
        assert_eq!(regular_proof.id, update_proof.id);
        // Different signatures
        assert_ne!(regular_proof.signature, update_proof.signature);
    }
}

mod multi_signature {
    use super::*;

    #[test]
    fn adds_signature_to_existing_object() {
        let key1 = generate_key_pair();
        let key2 = generate_key_pair();
        let data = json!({"action": "multi-sig"});

        let signed = create_signed_object(&data, &key1.private_key, false).unwrap();
        let signed = add_signature(signed, &key2.private_key, false).unwrap();

        assert_eq!(signed.proofs.len(), 2);

        let result = verify(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 2);
    }

    #[test]
    fn batch_signs_with_multiple_keys() {
        let key1 = generate_key_pair();
        let key2 = generate_key_pair();
        let key3 = generate_key_pair();
        let data = json!({"action": "batch"});

        let signed = batch_sign(
            &data,
            &[&key1.private_key, &key2.private_key, &key3.private_key],
            false,
        )
        .unwrap();

        assert_eq!(signed.proofs.len(), 3);

        let result = verify(&signed, false);
        assert!(result.is_valid);
        assert_eq!(result.valid_proofs.len(), 3);
    }

    #[test]
    fn all_signatures_are_unique() {
        let key1 = generate_key_pair();
        let key2 = generate_key_pair();
        let data = json!({"id": "test"});

        let signed = batch_sign(&data, &[&key1.private_key, &key2.private_key], false).unwrap();

        assert_ne!(signed.proofs[0].id, signed.proofs[1].id);
        assert_ne!(signed.proofs[0].signature, signed.proofs[1].signature);
    }
}

mod tamper_detection {
    use super::*;

    #[test]
    fn detects_modified_value() {
        let key_pair = generate_key_pair();
        let original = json!({"amount": 100});

        let proof = sign(&original, &key_pair.private_key).unwrap();

        // Create signed object with tampered value
        let tampered = json!({"amount": 999});
        let signed = Signed {
            value: tampered,
            proofs: vec![proof],
        };

        let result = verify(&signed, false);
        assert!(!result.is_valid);
        assert!(result.valid_proofs.is_empty());
        assert_eq!(result.invalid_proofs.len(), 1);
    }

    #[test]
    fn detects_modified_signature() {
        let key_pair = generate_key_pair();
        let data = json!({"id": "test"});

        let mut proof = sign(&data, &key_pair.private_key).unwrap();
        // Tamper with signature
        proof.signature = proof.signature.replace("0", "1");

        let signed = Signed {
            value: data,
            proofs: vec![proof],
        };

        let result = verify(&signed, false);
        assert!(!result.is_valid);
    }

    #[test]
    fn partial_validity_with_mixed_proofs() {
        let key1 = generate_key_pair();
        let key2 = generate_key_pair();
        let data = json!({"id": "test"});

        let valid_proof = sign(&data, &key1.private_key).unwrap();
        let mut invalid_proof = sign(&data, &key2.private_key).unwrap();
        invalid_proof.signature = invalid_proof.signature.replace("0", "1");

        let signed = Signed {
            value: data,
            proofs: vec![valid_proof, invalid_proof],
        };

        let result = verify(&signed, false);
        assert!(!result.is_valid); // Not fully valid
        assert_eq!(result.valid_proofs.len(), 1);
        assert_eq!(result.invalid_proofs.len(), 1);
    }
}

mod codec_operations {
    use super::*;

    #[test]
    fn encodes_and_decodes_data_update() {
        let data = json!({
            "id": "test",
            "nested": {"key": "value"},
            "array": [1, 2, 3]
        });

        let encoded = encode_data_update(&data).unwrap();
        let decoded: serde_json::Value = decode_data_update(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn canonicalizes_json_consistently() {
        let data = json!({
            "z": 26,
            "a": 1,
            "m": 13
        });

        let canonical = canonicalize(&data).unwrap();
        assert_eq!(canonical, r#"{"a":1,"m":13,"z":26}"#);
    }

    #[test]
    fn to_bytes_produces_different_output_for_data_update() {
        let data = json!({"id": "test"});

        let regular = to_bytes(&data, false).unwrap();
        let update = to_bytes(&data, true).unwrap();

        assert_ne!(regular, update);

        let update_str = String::from_utf8(update).unwrap();
        assert!(update_str.contains("Constellation Signed Data"));
    }
}

mod hashing {
    use super::*;

    #[test]
    fn produces_consistent_hashes() {
        let data = json!({"id": "test", "value": 42});

        let hash1 = hash_data(&data, false).unwrap();
        let hash2 = hash_data(&data, false).unwrap();

        assert_eq!(hash1.value, hash2.value);
        assert_eq!(hash1.bytes, hash2.bytes);
    }

    #[test]
    fn hash_is_32_bytes() {
        let data = json!({"test": true});
        let hash = hash_data(&data, false).unwrap();

        assert_eq!(hash.bytes.len(), 32);
        assert_eq!(hash.value.len(), 64);
    }

    #[test]
    fn different_data_produces_different_hash() {
        let data1 = json!({"value": 1});
        let data2 = json!({"value": 2});

        let hash1 = hash_data(&data1, false).unwrap();
        let hash2 = hash_data(&data2, false).unwrap();

        assert_ne!(hash1.value, hash2.value);
    }
}

mod error_handling {
    use super::*;
    use constellation_sdk::SdkError;

    #[test]
    fn rejects_invalid_private_key() {
        let result = key_pair_from_private_key("invalid");
        assert!(matches!(result, Err(SdkError::InvalidPrivateKey(_))));
    }

    #[test]
    fn batch_sign_requires_at_least_one_key() {
        let data = json!({"test": true});
        let result = batch_sign::<serde_json::Value>(&data, &[], false);
        assert!(matches!(result, Err(SdkError::NoPrivateKeys)));
    }
}
