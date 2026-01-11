"""
Constellation Metagraph SDK.

Python SDK for standard operations on Constellation Network metagraphs built using the metakit framework.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("constellation-metagraph-sdk")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"  # Fallback for development

# Binary encoding
from .binary import encode_data_update, to_bytes

# Canonicalization
from .canonicalize import canonicalize, canonicalize_bytes

# Codec utilities
from .codec import decode_data_update

# Currency transaction operations
from .currency_transaction import (
    create_currency_transaction,
    create_currency_transaction_batch,
    encode_currency_transaction,
    get_transaction_reference,
    hash_currency_transaction,
    is_valid_dag_address,
    sign_currency_transaction,
    token_to_units,
    units_to_token,
    verify_currency_transaction,
)

# Currency transaction types
from .currency_types import (
    TOKEN_DECIMALS,
    CurrencyTransaction,
    CurrencyTransactionValue,
    TransactionReference,
    TransferParams,
)

# Hashing
from .hash import compute_digest, hash_bytes, hash_data

# Signing
from .sign import sign, sign_data_update, sign_hash

# High-level API
from .signed_object import add_signature, batch_sign, create_signed_object

# Core types
from .types import (
    ALGORITHM,
    CONSTELLATION_PREFIX,
    Hash,
    KeyPair,
    SignatureProof,
    Signed,
    VerificationResult,
)

# Verification
from .verify import verify, verify_hash, verify_signature

# Wallet utilities
from .wallet import (
    generate_key_pair,
    get_address,
    get_public_key_hex,
    get_public_key_id,
    is_valid_private_key,
    is_valid_public_key,
    key_pair_from_private_key,
)

__all__ = [
    # Version
    "__version__",
    # Types
    "SignatureProof",
    "Signed",
    "KeyPair",
    "Hash",
    "VerificationResult",
    # Constants
    "ALGORITHM",
    "CONSTELLATION_PREFIX",
    # Canonicalization
    "canonicalize",
    "canonicalize_bytes",
    # Binary
    "to_bytes",
    "encode_data_update",
    # Hash
    "hash_data",
    "hash_bytes",
    "compute_digest",
    # Codec
    "decode_data_update",
    # Sign
    "sign",
    "sign_data_update",
    "sign_hash",
    # Verify
    "verify",
    "verify_hash",
    "verify_signature",
    # High-level
    "create_signed_object",
    "add_signature",
    "batch_sign",
    # Wallet
    "generate_key_pair",
    "key_pair_from_private_key",
    "get_public_key_hex",
    "get_public_key_id",
    "get_address",
    "is_valid_private_key",
    "is_valid_public_key",
    # Currency transaction types
    "TransactionReference",
    "CurrencyTransactionValue",
    "CurrencyTransaction",
    "TransferParams",
    "TOKEN_DECIMALS",
    # Currency transactions
    "create_currency_transaction",
    "create_currency_transaction_batch",
    "sign_currency_transaction",
    "verify_currency_transaction",
    "encode_currency_transaction",
    "hash_currency_transaction",
    "get_transaction_reference",
    "is_valid_dag_address",
    "token_to_units",
    "units_to_token",
]
