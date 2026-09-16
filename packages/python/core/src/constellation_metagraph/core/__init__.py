"""
Constellation Metagraph SDK — core tier.

The fully-offline kernel: canonicalization, binary encoding, hashing, codecs,
signing, verification, and wallet/key-pair utilities. No network access and no
currency-transaction helpers live here (those are in the ``std`` tier).

This distribution ships the ``constellation_metagraph.core`` namespace package.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("constellation-metagraph-sdk-core")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"  # Fallback for development

# Binary encoding
from constellation_metagraph.core.binary import encode_data_update, to_bytes

# Canonicalization
from constellation_metagraph.core.canonicalize import (
    canonicalize,
    canonicalize_bytes,
    drop_null_fields,
)

# Codec utilities
from constellation_metagraph.core.codec import decode_data_update

# Hashing
from constellation_metagraph.core.hash import compute_digest, hash_bytes, hash_data

# Signing
from constellation_metagraph.core.sign import sign, sign_data_update, sign_hash

# High-level signing API
from constellation_metagraph.core.signed_object import (
    add_signature,
    batch_sign,
    create_signed_object,
)

# Core types
from constellation_metagraph.core.types import (
    ALGORITHM,
    CONSTELLATION_PREFIX,
    Hash,
    KeyPair,
    SignatureProof,
    Signed,
    VerificationResult,
)

# Verification
from constellation_metagraph.core.verify import verify, verify_hash, verify_signature

# Wallet utilities
from constellation_metagraph.core.wallet import (
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
    "drop_null_fields",
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
]
