"""
Currency transaction operations for metagraph token transfers.

Functions for creating, signing, and verifying metagraph token transactions (v2 format).
"""

import hashlib
import math
import os
import re
from typing import List

from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der

from .currency_types import (
    TOKEN_DECIMALS,
    CurrencyTransaction,
    CurrencyTransactionValue,
    TransactionReference,
    TransferParams,
)
from .types import Hash, SignatureProof, Signed, VerificationResult
from .wallet import get_address

# Minimum salt complexity (from dag4.js)
MIN_SALT = 2**53 - 2**48  # Number.MAX_SAFE_INTEGER - 2^48


def token_to_units(amount: float) -> int:
    """
    Convert token amount to smallest units.

    Args:
        amount: Amount in token units (e.g., 100.5)

    Returns:
        Amount in smallest units (1e-8)

    Example:
        >>> units = token_to_units(100.5)
        >>> print(units)  # 10050000000
    """
    return math.floor(amount * 1e8)


def units_to_token(units: int) -> float:
    """
    Convert smallest units to token amount.

    Args:
        units: Amount in smallest units

    Returns:
        Amount in token units

    Example:
        >>> tokens = units_to_token(10050000000)
        >>> print(tokens)  # 100.5
    """
    return units * TOKEN_DECIMALS


def is_valid_dag_address(address: str) -> bool:
    """
    Validate DAG address format.

    Args:
        address: DAG address to validate

    Returns:
        True if address is valid

    Example:
        >>> valid = is_valid_dag_address('DAG...')
    """
    # DAG addresses: DAG + parity digit (0-8) + 36 base58 chars = 40 chars total
    if not address.startswith("DAG"):
        return False
    # Exact length check
    if len(address) != 40:
        return False
    # Position 3 (after DAG) must be parity digit 0-8
    if not address[3].isdigit() or int(address[3]) > 8:
        return False
    # Remaining 36 characters must be base58 (no 0, O, I, l)
    base58_pattern = re.compile(
        r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{36}$"
    )
    return bool(base58_pattern.match(address[4:]))


def _generate_salt() -> str:
    """Generate a random salt for transaction uniqueness."""
    # Generate 6 random bytes (48 bits)
    random_bytes = os.urandom(6)
    random_int = int.from_bytes(random_bytes, byteorder="big")
    salt = MIN_SALT + random_int
    return str(salt)


def _encode_transaction(tx: CurrencyTransaction) -> str:
    """
    Encode a currency transaction for hashing.

    Matches the TransactionV2.getEncoded() method from dag4.js.

    Args:
        tx: Transaction to encode

    Returns:
        Encoded transaction string
    """
    parent_count = "2"  # Always 2 parents for v2
    source = tx.value.source
    destination = tx.value.destination
    amount_hex = hex(tx.value.amount)[2:]  # Remove '0x' prefix
    parent_hash = tx.value.parent.hash
    ordinal = str(tx.value.parent.ordinal)
    fee = str(tx.value.fee)

    # Convert salt to hex (handle negative numbers if needed)
    salt_int = int(tx.value.salt)
    if salt_int < 0:
        salt_hex = hex((1 << 64) + salt_int)[2:]
    else:
        salt_hex = hex(salt_int)[2:]

    # Build encoded string (length-prefixed format)
    parts = [
        parent_count,
        str(len(source)),
        source,
        str(len(destination)),
        destination,
        str(len(amount_hex)),
        amount_hex,
        str(len(parent_hash)),
        parent_hash,
        str(len(ordinal)),
        ordinal,
        str(len(fee)),
        fee,
        str(len(salt_hex)),
        salt_hex,
    ]

    return "".join(parts)


def _kryo_serialize(msg: str, set_references: bool = True) -> bytes:
    """
    Kryo serialization for transaction encoding.

    Matches the txEncode.kryoSerialize() method from dag4.js.

    Args:
        msg: Message to serialize
        set_references: Whether to set references (True for v1, False for v2)

    Returns:
        Serialized bytes
    """

    # UTF-8 length encoding
    def utf8_length(value: int) -> bytes:
        """Encode length as variable-length integer."""
        if value >> 6 == 0:
            return bytes([value | 0x80])
        elif value >> 13 == 0:
            return bytes([value | 0x40 | 0x80, value >> 6])
        elif value >> 20 == 0:
            return bytes([value | 0x40 | 0x80, (value >> 6) | 0x80, value >> 13])
        elif value >> 27 == 0:
            return bytes(
                [
                    value | 0x40 | 0x80,
                    (value >> 6) | 0x80,
                    (value >> 13) | 0x80,
                    value >> 20,
                ]
            )
        else:
            return bytes(
                [
                    value | 0x40 | 0x80,
                    (value >> 6) | 0x80,
                    (value >> 13) | 0x80,
                    (value >> 20) | 0x80,
                    value >> 27,
                ]
            )

    # Build serialized message
    prefix_bytes = bytes([0x03])
    if set_references:
        prefix_bytes += bytes([0x01])

    length = len(msg) + 1
    prefix_bytes += utf8_length(length)

    msg_bytes = msg.encode("utf-8")

    return prefix_bytes + msg_bytes


def create_currency_transaction(
    params: TransferParams,
    private_key: str,
    last_ref: TransactionReference,
) -> CurrencyTransaction:
    """
    Create a metagraph token transaction.

    Args:
        params: Transfer parameters
        private_key: Private key to sign with (hex string)
        last_ref: Reference to last accepted transaction

    Returns:
        Signed currency transaction

    Raises:
        ValueError: If addresses are invalid or amounts are invalid

    Example:
        >>> tx = create_currency_transaction(
        ...     TransferParams(destination='DAG...', amount=100.5, fee=0),
        ...     private_key,
        ...     TransactionReference(hash='abc123...', ordinal=5)
        ... )
    """
    # Get source address from private key
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    vk = sk.verifying_key
    public_key = "04" + vk.to_string().hex()
    source = get_address(public_key)

    # Validate addresses
    if not is_valid_dag_address(source):
        raise ValueError("Invalid source address")
    if not is_valid_dag_address(params.destination):
        raise ValueError("Invalid destination address")
    if source == params.destination:
        raise ValueError("Source and destination addresses cannot be the same")

    # Convert amounts to smallest units
    amount = token_to_units(params.amount)
    fee = token_to_units(params.fee)

    # Validate amounts
    if amount < 1:
        raise ValueError("Transfer amount must be greater than 1e-8")
    if fee < 0:
        raise ValueError("Fee must be greater than or equal to zero")

    # Generate salt
    salt = _generate_salt()

    # Create transaction value
    tx_value = CurrencyTransactionValue(
        source=source,
        destination=params.destination,
        amount=amount,
        fee=fee,
        parent=last_ref,
        salt=salt,
    )

    # Create signed transaction
    tx = Signed(value=tx_value, proofs=[])

    # Encode and hash
    encoded = _encode_transaction(tx)
    serialized = _kryo_serialize(encoded, set_references=False)
    hash_bytes = hashlib.sha256(serialized).digest()
    hash_hex = hash_bytes.hex()

    # Sign
    signature = _sign_hash(hash_hex, private_key)

    # Create proof
    public_key_id = public_key[2:]  # Remove '04' prefix
    proof = SignatureProof(id=public_key_id, signature=signature)

    # Add proof to transaction
    tx.proofs.append(proof)

    return tx


def create_currency_transaction_batch(
    transfers: List[TransferParams],
    private_key: str,
    last_ref: TransactionReference,
) -> List[CurrencyTransaction]:
    """
    Create multiple metagraph token transactions (batch).

    Args:
        transfers: Array of transfer parameters
        private_key: Private key to sign with
        last_ref: Reference to last accepted transaction

    Returns:
        Array of signed currency transactions

    Raises:
        ValueError: If any address is invalid or amount is invalid

    Example:
        >>> txns = create_currency_transaction_batch(
        ...     [
        ...         TransferParams(destination='DAG...1', amount=10),
        ...         TransferParams(destination='DAG...2', amount=20),
        ...     ],
        ...     private_key,
        ...     TransactionReference(hash='abc123...', ordinal=5)
        ... )
    """
    transactions: List[CurrencyTransaction] = []
    current_ref = TransactionReference(hash=last_ref.hash, ordinal=last_ref.ordinal)

    for transfer in transfers:
        tx = create_currency_transaction(transfer, private_key, current_ref)

        # Calculate hash for next transaction's parent reference
        hash_result = hash_currency_transaction(tx)

        # Update reference for next transaction
        current_ref = TransactionReference(hash=hash_result.value, ordinal=current_ref.ordinal + 1)

        transactions.append(tx)

    return transactions


def sign_currency_transaction(
    transaction: CurrencyTransaction,
    private_key: str,
) -> CurrencyTransaction:
    """
    Add a signature to an existing currency transaction (for multi-sig).

    Args:
        transaction: Transaction to sign
        private_key: Private key to sign with

    Returns:
        Transaction with additional signature

    Raises:
        ValueError: If sign-verify fails

    Example:
        >>> signed_tx = sign_currency_transaction(tx, private_key2)
    """
    # Encode and hash
    encoded = _encode_transaction(transaction)
    serialized = _kryo_serialize(encoded, set_references=False)
    hash_bytes = hashlib.sha256(serialized).digest()
    hash_hex = hash_bytes.hex()

    # Sign
    signature = _sign_hash(hash_hex, private_key)

    # Get public key
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    vk = sk.verifying_key
    public_key = "04" + vk.to_string().hex()

    # Verify signature
    if not _verify_hash(public_key, hash_hex, signature):
        raise ValueError("Sign-Verify failed")

    # Create proof
    public_key_id = public_key[2:]  # Remove '04' prefix
    proof = SignatureProof(id=public_key_id, signature=signature)

    # Add proof (create new signed transaction with updated proofs)
    new_proofs = [*transaction.proofs, proof]
    return Signed(value=transaction.value, proofs=new_proofs)


def verify_currency_transaction(transaction: CurrencyTransaction) -> VerificationResult:
    """
    Verify all signatures on a currency transaction.

    Args:
        transaction: Transaction to verify

    Returns:
        Verification result with valid/invalid proofs

    Example:
        >>> result = verify_currency_transaction(tx)
        >>> print('Valid:', result.is_valid)
    """
    # Encode and hash
    encoded = _encode_transaction(transaction)
    serialized = _kryo_serialize(encoded, set_references=False)
    hash_bytes = hashlib.sha256(serialized).digest()
    hash_hex = hash_bytes.hex()

    valid_proofs: List[SignatureProof] = []
    invalid_proofs: List[SignatureProof] = []

    # Verify each proof
    for proof in transaction.proofs:
        public_key = "04" + proof.id  # Add back '04' prefix
        is_valid = _verify_hash(public_key, hash_hex, proof.signature)

        if is_valid:
            valid_proofs.append(proof)
        else:
            invalid_proofs.append(proof)

    return VerificationResult(
        is_valid=len(invalid_proofs) == 0 and len(valid_proofs) > 0,
        valid_proofs=valid_proofs,
        invalid_proofs=invalid_proofs,
    )


def encode_currency_transaction(transaction: CurrencyTransaction) -> str:
    """
    Encode a currency transaction for hashing.

    Args:
        transaction: Transaction to encode

    Returns:
        Hex-encoded string

    Example:
        >>> encoded = encode_currency_transaction(tx)
    """
    return _encode_transaction(transaction)


def hash_currency_transaction(transaction: CurrencyTransaction) -> Hash:
    """
    Hash a currency transaction.

    Args:
        transaction: Transaction to hash

    Returns:
        Hash object with value and bytes

    Example:
        >>> hash_result = hash_currency_transaction(tx)
        >>> print('Hash:', hash_result.value)
    """
    encoded = _encode_transaction(transaction)
    serialized = _kryo_serialize(encoded, set_references=False)
    hash_bytes = hashlib.sha256(serialized).digest()

    return Hash(value=hash_bytes.hex(), bytes=hash_bytes)


def get_transaction_reference(
    transaction: CurrencyTransaction, ordinal: int
) -> TransactionReference:
    """
    Get transaction reference from a currency transaction.

    Useful for chaining transactions.

    Args:
        transaction: Transaction to extract reference from
        ordinal: Ordinal number for this transaction

    Returns:
        Transaction reference

    Example:
        >>> ref = get_transaction_reference(tx, 6)
        >>> # Use ref as last_ref for next transaction
    """
    hash_result = hash_currency_transaction(transaction)
    return TransactionReference(hash=hash_result.value, ordinal=ordinal)


def _sign_hash(hash_hex: str, private_key: str) -> str:
    """
    Sign a hash using Constellation signing protocol.

    Protocol:
    1. Treat hash hex as UTF-8 string
    2. SHA-512 hash the string
    3. Truncate to first 32 bytes
    4. Sign with ECDSA secp256k1

    Args:
        hash_hex: Hash in hex format (64 characters)
        private_key: Private key in hex format

    Returns:
        DER-encoded signature in hex format
    """
    # Hash hex as UTF-8 -> SHA-512 -> truncate 32 bytes
    hash_utf8 = hash_hex.encode("utf-8")
    sha512_hash = hashlib.sha512(hash_utf8).digest()
    digest = sha512_hash[:32]

    # Sign with ECDSA
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    signature_bytes: bytes = sk.sign_digest(digest, sigencode=sigencode_der)

    return signature_bytes.hex()


def _verify_hash(public_key: str, hash_hex: str, signature: str) -> bool:
    """
    Verify a signature on a hash.

    Args:
        public_key: Public key in hex format (with 04 prefix)
        hash_hex: Hash in hex format
        signature: DER-encoded signature in hex format

    Returns:
        True if signature is valid
    """
    try:
        # Hash hex as UTF-8 -> SHA-512 -> truncate 32 bytes
        hash_utf8 = hash_hex.encode("utf-8")
        sha512_hash = hashlib.sha512(hash_utf8).digest()
        digest = sha512_hash[:32]

        # Get verifying key
        public_key_bytes = bytes.fromhex(public_key)
        # Remove '04' prefix if present
        if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
            public_key_bytes = public_key_bytes[1:]

        vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)

        # Verify signature
        signature_bytes = bytes.fromhex(signature)
        vk.verify_digest(signature_bytes, digest, sigdecode=sigdecode_der)

        return True
    except Exception:
        return False
