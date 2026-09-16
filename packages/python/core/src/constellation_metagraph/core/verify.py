"""
Signature Verification.

Verify ECDSA signatures using secp256k1 curve.
"""

import hashlib
from typing import Any, TypeVar

from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

from constellation_metagraph.core.binary import to_bytes
from constellation_metagraph.core.hash import hash_bytes
from constellation_metagraph.core.types import SignatureProof, Signed, VerificationResult

T = TypeVar("T")


def verify(signed: Signed[T], is_data_update: bool = False) -> VerificationResult:
    """
    Verify a signed object.

    Args:
        signed: Signed object with value and proofs
        is_data_update: Whether the value was signed as a DataUpdate

    Returns:
        VerificationResult with valid/invalid proof lists

    Example:
        >>> result = verify(signed_object)
        >>> if result.is_valid:
        ...     print("All signatures valid")
    """
    # Compute the hash that should have been signed
    data_bytes = to_bytes(signed.value, is_data_update)
    hash_result = hash_bytes(data_bytes)

    valid_proofs: list[SignatureProof] = []
    invalid_proofs: list[SignatureProof] = []

    for proof in signed.proofs:
        try:
            is_valid = verify_hash(hash_result.value, proof.signature, proof.id)
            if is_valid:
                valid_proofs.append(proof)
            else:
                invalid_proofs.append(proof)
        except Exception:
            # Verification error = invalid
            invalid_proofs.append(proof)

    return VerificationResult(
        is_valid=len(invalid_proofs) == 0 and len(valid_proofs) > 0,
        valid_proofs=valid_proofs,
        invalid_proofs=invalid_proofs,
    )


def verify_hash(hash_hex: str, signature: str, public_key_id: str) -> bool:
    """
    Verify a signature against a SHA-256 hash.

    Protocol:
    1. Treat hash hex as UTF-8 bytes (NOT hex decode)
    2. SHA-512 hash
    3. Truncate to 32 bytes
    4. Verify ECDSA signature

    Args:
        hash_hex: SHA-256 hash as 64-character hex string
        signature: DER-encoded signature in hex format
        public_key_id: Public key in hex (with or without 04 prefix)

    Returns:
        True if signature is valid
    """
    try:
        # Step 1-2: Hash hex as UTF-8, then SHA-512
        hex_as_utf8 = hash_hex.encode("utf-8")
        sha512_hash = hashlib.sha512(hex_as_utf8).digest()

        # Step 3: Truncate to 32 bytes
        truncated_hash = sha512_hash[:32]

        # Normalize public key (add 04 prefix if needed)
        full_public_key = _normalize_public_key(public_key_id)

        # Step 4: Verify with ecdsa
        vk = VerifyingKey.from_string(bytes.fromhex(full_public_key), curve=SECP256k1)
        result: bool = vk.verify_digest(
            bytes.fromhex(signature), truncated_hash, sigdecode=sigdecode_der
        )
        return result
    except Exception:
        return False


def verify_signature(data: Any, proof: SignatureProof, is_data_update: bool = False) -> bool:
    """
    Verify a single signature proof against data.

    Args:
        data: The original data that was signed
        proof: The signature proof to verify
        is_data_update: Whether data was signed as DataUpdate

    Returns:
        True if signature is valid
    """
    data_bytes = to_bytes(data, is_data_update)
    hash_result = hash_bytes(data_bytes)
    return verify_hash(hash_result.value, proof.signature, proof.id)


def _normalize_public_key(public_key: str) -> str:
    """Normalize public key to full format (without 04 prefix for ecdsa library)."""
    # ecdsa library expects uncompressed key without 04 prefix
    if public_key.startswith("04") and len(public_key) == 130:
        return public_key[2:]
    if len(public_key) == 128:
        return public_key
    return public_key
