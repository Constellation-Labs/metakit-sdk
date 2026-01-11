//! Currency transaction operations for metagraph token transfers

use num_bigint::BigUint;
use rand::Rng;
use regex::Regex;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};

use crate::currency_types::{
    CurrencyTransaction, CurrencyTransactionValue, TransactionReference, TransferParams,
    TOKEN_DECIMALS,
};
use crate::types::{Hash, Result, SdkError, SignatureProof, Signed, VerificationResult};
use crate::wallet::get_address;

/// Minimum salt complexity (from dag4.js)
const MIN_SALT: u64 = (1u64 << 53) - (1u64 << 48);

/// Convert token amount to smallest units
pub fn token_to_units(amount: f64) -> i64 {
    (amount * 1e8).floor() as i64
}

/// Convert smallest units to token amount
pub fn units_to_token(units: i64) -> f64 {
    units as f64 * TOKEN_DECIMALS
}

/// Validate DAG address format
pub fn is_valid_dag_address(address: &str) -> bool {
    // DAG addresses: DAG + parity digit (0-8) + 36 base58 chars = 40 chars total
    if !address.starts_with("DAG") {
        return false;
    }
    // Exact length check
    if address.len() != 40 {
        return false;
    }
    // Position 3 (after DAG) must be parity digit 0-8
    let parity_char = address.chars().nth(3).unwrap();
    if !parity_char.is_ascii_digit() || parity_char > '8' {
        return false;
    }
    // Remaining 36 characters must be base58 (no 0, O, I, l)
    let re =
        Regex::new(r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{36}$").unwrap();
    re.is_match(&address[4..])
}

/// Generate a random salt for transaction uniqueness
fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 6] = rng.gen();
    let random_int = u64::from_be_bytes([
        0,
        0,
        random_bytes[0],
        random_bytes[1],
        random_bytes[2],
        random_bytes[3],
        random_bytes[4],
        random_bytes[5],
    ]);
    let salt = MIN_SALT + random_int;
    salt.to_string()
}

/// Encode a currency transaction for hashing
fn encode_transaction(tx: &CurrencyTransaction) -> String {
    let parent_count = "2"; // Always 2 parents for v2
    let source = &tx.value.source;
    let destination = &tx.value.destination;
    let amount_hex = format!("{:x}", tx.value.amount);
    let parent_hash = &tx.value.parent.hash;
    let ordinal = tx.value.parent.ordinal.to_string();
    let fee = tx.value.fee.to_string();

    // Convert salt to hex
    let salt_int = tx.value.salt.parse::<BigUint>().unwrap();
    let salt_hex = format!("{salt_int:x}");

    // Build encoded string (length-prefixed format)
    format!(
        "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
        parent_count,
        source.len(),
        source,
        destination.len(),
        destination,
        amount_hex.len(),
        amount_hex,
        parent_hash.len(),
        parent_hash,
        ordinal.len(),
        ordinal,
        fee.len(),
        fee,
        salt_hex.len(),
        salt_hex
    )
}

/// Kryo serialization for transaction encoding
fn kryo_serialize(msg: &str, set_references: bool) -> Vec<u8> {
    fn utf8_length(value: usize) -> Vec<u8> {
        if value >> 6 == 0 {
            vec![(value | 0x80) as u8]
        } else if value >> 13 == 0 {
            vec![(value | 0x40 | 0x80) as u8, (value >> 6) as u8]
        } else if value >> 20 == 0 {
            vec![
                (value | 0x40 | 0x80) as u8,
                ((value >> 6) | 0x80) as u8,
                (value >> 13) as u8,
            ]
        } else if value >> 27 == 0 {
            vec![
                (value | 0x40 | 0x80) as u8,
                ((value >> 6) | 0x80) as u8,
                ((value >> 13) | 0x80) as u8,
                (value >> 20) as u8,
            ]
        } else {
            vec![
                (value | 0x40 | 0x80) as u8,
                ((value >> 6) | 0x80) as u8,
                ((value >> 13) | 0x80) as u8,
                ((value >> 20) | 0x80) as u8,
                (value >> 27) as u8,
            ]
        }
    }

    let mut result = vec![0x03];
    if set_references {
        result.push(0x01);
    }

    let length = msg.len() + 1;
    result.extend(utf8_length(length));
    result.extend(msg.as_bytes());

    result
}

/// Sign a hash using Constellation signing protocol
fn sign_hash_internal(hash_hex: &str, private_key_hex: &str) -> Result<String> {
    // Hash hex as UTF-8 -> SHA-512 -> truncate 32 bytes
    let hash_utf8 = hash_hex.as_bytes();
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(hash_utf8);
    let sha512_hash = sha512_hasher.finalize();
    let digest = &sha512_hash[..32];

    // Sign with ECDSA
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&hex::decode(private_key_hex)?)?;
    let message = Message::from_digest_slice(digest)?;
    let signature = secp.sign_ecdsa(&message, &secret_key);

    Ok(hex::encode(signature.serialize_der()))
}

/// Verify a signature on a hash
fn verify_hash_internal(public_key_hex: &str, hash_hex: &str, signature_hex: &str) -> bool {
    // Hash hex as UTF-8 -> SHA-512 -> truncate 32 bytes
    let hash_utf8 = hash_hex.as_bytes();
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(hash_utf8);
    let sha512_hash = sha512_hasher.finalize();
    let digest = &sha512_hash[..32];

    // Parse public key and signature
    let public_key_bytes = match hex::decode(public_key_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let public_key = match secp256k1::PublicKey::from_slice(&public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let signature_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let mut signature = match secp256k1::ecdsa::Signature::from_der(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Normalize signature to low-S to accept high-S signatures (BIP 62 compatibility)
    // This ensures we accept signatures from other SDKs that may not normalize to low-S
    signature.normalize_s();

    let message = match Message::from_digest_slice(digest) {
        Ok(msg) => msg,
        Err(_) => return false,
    };

    let secp = Secp256k1::new();
    secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
}

/// Create a metagraph token transaction
pub fn create_currency_transaction(
    params: TransferParams,
    private_key: &str,
    last_ref: TransactionReference,
) -> Result<CurrencyTransaction> {
    // Get source address from private key
    let secret_key = SecretKey::from_slice(&hex::decode(private_key)?)?;
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize_uncompressed());
    let source = get_address(&public_key_hex);

    // Validate addresses
    if !is_valid_dag_address(&source) {
        return Err(SdkError::InvalidAddress(
            "Invalid source address".to_string(),
        ));
    }
    if !is_valid_dag_address(&params.destination) {
        return Err(SdkError::InvalidAddress(
            "Invalid destination address".to_string(),
        ));
    }
    if source == params.destination {
        return Err(SdkError::InvalidAddress(
            "Source and destination addresses cannot be the same".to_string(),
        ));
    }

    // Convert amounts to smallest units
    let amount = token_to_units(params.amount);
    let fee = token_to_units(params.fee);

    // Validate amounts
    if amount < 1 {
        return Err(SdkError::InvalidAmount(
            "Transfer amount must be greater than 1e-8".to_string(),
        ));
    }
    if fee < 0 {
        return Err(SdkError::InvalidAmount(
            "Fee must be greater than or equal to zero".to_string(),
        ));
    }

    // Generate salt
    let salt = generate_salt();

    // Create transaction value
    let tx_value = CurrencyTransactionValue {
        source,
        destination: params.destination,
        amount,
        fee,
        parent: last_ref,
        salt,
    };

    // Create signed transaction
    let mut tx = Signed {
        value: tx_value,
        proofs: vec![],
    };

    // Encode and hash
    let encoded = encode_transaction(&tx);
    let serialized = kryo_serialize(&encoded, false);
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);

    // Sign
    let signature = sign_hash_internal(&hash_hex, private_key)?;

    // Create proof
    let public_key_id = &public_key_hex[2..]; // Remove '04' prefix
    let proof = SignatureProof {
        id: public_key_id.to_string(),
        signature,
    };

    // Add proof to transaction
    tx.proofs.push(proof);

    Ok(tx)
}

/// Create multiple metagraph token transactions (batch)
pub fn create_currency_transaction_batch(
    transfers: Vec<TransferParams>,
    private_key: &str,
    last_ref: TransactionReference,
) -> Result<Vec<CurrencyTransaction>> {
    let mut transactions = Vec::new();
    let mut current_ref = last_ref;

    for transfer in transfers {
        let tx = create_currency_transaction(transfer, private_key, current_ref.clone())?;

        // Calculate hash for next transaction's parent reference
        let hash_result = hash_currency_transaction(&tx);

        // Update reference for next transaction
        current_ref = TransactionReference {
            hash: hash_result.value,
            ordinal: current_ref.ordinal + 1,
        };

        transactions.push(tx);
    }

    Ok(transactions)
}

/// Add a signature to an existing currency transaction (for multi-sig)
pub fn sign_currency_transaction(
    transaction: &CurrencyTransaction,
    private_key: &str,
) -> Result<CurrencyTransaction> {
    // Encode and hash
    let encoded = encode_transaction(transaction);
    let serialized = kryo_serialize(&encoded, false);
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);

    // Sign
    let signature = sign_hash_internal(&hash_hex, private_key)?;

    // Get public key
    let secret_key = SecretKey::from_slice(&hex::decode(private_key)?)?;
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize_uncompressed());

    // Verify signature
    if !verify_hash_internal(&public_key_hex, &hash_hex, &signature) {
        return Err(SdkError::InvalidSignature("Sign-Verify failed".to_string()));
    }

    // Create proof
    let public_key_id = &public_key_hex[2..]; // Remove '04' prefix
    let proof = SignatureProof {
        id: public_key_id.to_string(),
        signature,
    };

    // Create new signed transaction with updated proofs
    let mut new_proofs = transaction.proofs.clone();
    new_proofs.push(proof);

    Ok(Signed {
        value: transaction.value.clone(),
        proofs: new_proofs,
    })
}

/// Verify all signatures on a currency transaction
pub fn verify_currency_transaction(transaction: &CurrencyTransaction) -> VerificationResult {
    // Encode and hash
    let encoded = encode_transaction(transaction);
    let serialized = kryo_serialize(&encoded, false);
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);

    let mut valid_proofs = Vec::new();
    let mut invalid_proofs = Vec::new();

    // Verify each proof
    for proof in &transaction.proofs {
        let public_key = format!("04{}", proof.id); // Add back '04' prefix
        let is_valid = verify_hash_internal(&public_key, &hash_hex, &proof.signature);

        if is_valid {
            valid_proofs.push(proof.clone());
        } else {
            invalid_proofs.push(proof.clone());
        }
    }

    VerificationResult {
        is_valid: invalid_proofs.is_empty() && !valid_proofs.is_empty(),
        valid_proofs,
        invalid_proofs,
    }
}

/// Encode a currency transaction for hashing
pub fn encode_currency_transaction(transaction: &CurrencyTransaction) -> String {
    encode_transaction(transaction)
}

/// Hash a currency transaction
pub fn hash_currency_transaction(transaction: &CurrencyTransaction) -> Hash {
    let encoded = encode_transaction(transaction);
    let serialized = kryo_serialize(&encoded, false);
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    let hash_bytes = hasher.finalize();

    Hash {
        value: hex::encode(hash_bytes),
        bytes: hash_bytes.to_vec(),
    }
}

/// Get transaction reference from a currency transaction
pub fn get_transaction_reference(
    transaction: &CurrencyTransaction,
    ordinal: i64,
) -> TransactionReference {
    let hash_result = hash_currency_transaction(transaction);
    TransactionReference {
        hash: hash_result.value,
        ordinal,
    }
}
