"""
Hashing Utilities.

SHA-256 and SHA-512 hashing for the Constellation signature protocol.
"""

import hashlib
from typing import Any

from constellation_metagraph.core.binary import to_bytes
from constellation_metagraph.core.types import Hash


def hash_data(data: Any, is_data_update: bool = False) -> Hash:
    """
    Compute SHA-256 hash of canonical JSON data.

    Args:
        data: Any JSON-serializable object
        is_data_update: Whether to apply DataUpdate encoding

    Returns:
        Hash object with hex string and raw bytes

    Example:
        >>> result = hash_data({"action": "test"})
        >>> print(result.value)  # 64-char hex string
    """
    data_bytes = to_bytes(data, is_data_update)
    return hash_bytes(data_bytes)


def hash_bytes(data: bytes) -> Hash:
    """
    Compute SHA-256 hash of raw bytes.

    Args:
        data: Input bytes

    Returns:
        Hash object with hex string and raw bytes
    """
    digest = hashlib.sha256(data).digest()
    hex_value = digest.hex()
    return Hash(value=hex_value, bytes=digest)


def compute_digest(data: Any, is_data_update: bool = False) -> bytes:
    """
    Compute the full signing digest according to Constellation protocol.

    Protocol:
    1. Serialize data to binary (with optional DataUpdate prefix)
    2. Compute SHA-256 hash
    3. Convert hash to hex string
    4. Treat hex string as UTF-8 bytes (NOT hex decode)
    5. Compute SHA-512 of those bytes
    6. Truncate to 32 bytes for secp256k1 signing

    Args:
        data: Any JSON-serializable object
        is_data_update: Whether to apply DataUpdate encoding

    Returns:
        32-byte digest ready for ECDSA signing
    """
    # Step 1: Serialize to binary
    data_bytes = to_bytes(data, is_data_update)

    # Step 2: SHA-256 hash
    sha256_hash = hash_bytes(data_bytes)

    # Step 3-4: Hex string as UTF-8 bytes (critical: NOT hex decode)
    hex_as_utf8 = sha256_hash.value.encode("utf-8")

    # Step 5: SHA-512
    sha512_hash = hashlib.sha512(hex_as_utf8).digest()

    # Step 6: Truncate to 32 bytes
    return sha512_hash[:32]
