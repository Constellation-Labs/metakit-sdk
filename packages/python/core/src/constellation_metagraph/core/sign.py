"""
Signing Functions.

ECDSA signing using secp256k1 curve.
Implements the Constellation signature protocol.
"""

import hashlib
from typing import Any

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der

from constellation_metagraph.core.binary import to_bytes
from constellation_metagraph.core.hash import hash_bytes
from constellation_metagraph.core.types import SignatureProof


def sign(data: Any, private_key: str) -> SignatureProof:
    """
    Sign data using the regular Constellation protocol (non-DataUpdate).

    Protocol:
    1. Canonicalize JSON
    2. UTF-8 encode
    3. SHA-256 hash
    4. Hash hex as UTF-8 -> SHA-512 -> truncate -> ECDSA sign

    Args:
        data: Any JSON-serializable object
        private_key: Private key in hex format

    Returns:
        SignatureProof with public key ID and signature

    Example:
        >>> proof = sign({"action": "test"}, private_key_hex)
        >>> print(proof.id)        # public key (128 chars)
        >>> print(proof.signature) # DER signature
    """
    # Serialize and hash
    data_bytes = to_bytes(data, is_data_update=False)
    hash_result = hash_bytes(data_bytes)

    # Sign the hash
    signature = sign_hash(hash_result.value, private_key)

    # Get public key ID
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    public_key_id = _get_public_key_id(sk)

    return SignatureProof(id=public_key_id, signature=signature)


def sign_data_update(data: Any, private_key: str) -> SignatureProof:
    """
    Sign data as a DataUpdate (with Constellation prefix).

    Args:
        data: Any JSON-serializable object
        private_key: Private key in hex format

    Returns:
        SignatureProof
    """
    # Serialize with DataUpdate encoding
    data_bytes = to_bytes(data, is_data_update=True)
    hash_result = hash_bytes(data_bytes)

    # Sign the hash
    signature = sign_hash(hash_result.value, private_key)

    # Get public key ID
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    public_key_id = _get_public_key_id(sk)

    return SignatureProof(id=public_key_id, signature=signature)


def sign_hash(hash_hex: str, private_key: str) -> str:
    """
    Sign a pre-computed SHA-256 hash.

    Protocol:
    1. Treat hash hex as UTF-8 bytes (NOT hex decode)
    2. SHA-512 hash
    3. Truncate to 32 bytes
    4. Sign with ECDSA

    Args:
        hash_hex: SHA-256 hash as 64-character hex string
        private_key: Private key in hex format

    Returns:
        DER-encoded signature in hex format
    """
    # Step 1-2: Hash hex as UTF-8, then SHA-512
    hex_as_utf8 = hash_hex.encode("utf-8")
    sha512_hash = hashlib.sha512(hex_as_utf8).digest()

    # Step 3: Truncate to 32 bytes
    truncated_hash = sha512_hash[:32]

    # Step 4: Sign with ECDSA
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    signature: bytes = sk.sign_digest(truncated_hash, sigencode=sigencode_der)

    return signature.hex()


def _get_public_key_id(signing_key: SigningKey) -> str:
    """Get public key ID (without 04 prefix) from signing key."""
    verifying_key = signing_key.verifying_key
    x_coord = verifying_key.pubkey.point.x()
    y_coord = verifying_key.pubkey.point.y()
    # Return without 04 prefix (128 chars)
    return f"{x_coord:064x}{y_coord:064x}"
