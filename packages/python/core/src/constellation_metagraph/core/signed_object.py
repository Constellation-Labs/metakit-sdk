"""
High-Level Signed Object API.

Convenience functions for creating and managing signed objects.
"""

from typing import List, TypeVar

from constellation_metagraph.core.sign import sign, sign_data_update
from constellation_metagraph.core.types import SignatureProof, Signed

T = TypeVar("T")


def create_signed_object(value: T, private_key: str, is_data_update: bool = False) -> Signed[T]:
    """
    Create a signed object with a single signature.

    Args:
        value: Any JSON-serializable object
        private_key: Private key in hex format
        is_data_update: Whether to sign as DataUpdate

    Returns:
        Signed object ready for submission

    Example:
        >>> # Sign a regular data object
        >>> signed = create_signed_object(my_data, private_key)

        >>> # Sign as DataUpdate for L1 submission
        >>> signed_update = create_signed_object(my_data, private_key, is_data_update=True)
    """
    proof = sign_data_update(value, private_key) if is_data_update else sign(value, private_key)
    return Signed(value=value, proofs=[proof])


def add_signature(signed: Signed[T], private_key: str, is_data_update: bool = False) -> Signed[T]:
    """
    Add an additional signature to an existing signed object.

    This allows building multi-signature objects where multiple parties
    need to sign the same data.

    Args:
        signed: Existing signed object
        private_key: Private key in hex format
        is_data_update: Whether to sign as DataUpdate (must match original)

    Returns:
        New signed object with additional proof

    Example:
        >>> # First party signs
        >>> signed = create_signed_object(data, party1_key)

        >>> # Second party adds signature
        >>> signed = add_signature(signed, party2_key)

        >>> # Now has 2 proofs
        >>> len(signed.proofs)  # 2
    """
    proof = (
        sign_data_update(signed.value, private_key)
        if is_data_update
        else sign(signed.value, private_key)
    )
    return Signed(value=signed.value, proofs=[*signed.proofs, proof])


def batch_sign(value: T, private_keys: List[str], is_data_update: bool = False) -> Signed[T]:
    """
    Create a signed object with multiple signatures at once.

    Useful when you have access to multiple private keys and want
    to create a multi-sig object in one operation.

    Args:
        value: Any JSON-serializable object
        private_keys: List of private keys in hex format
        is_data_update: Whether to sign as DataUpdate

    Returns:
        Signed object with multiple proofs

    Raises:
        ValueError: If no private keys provided

    Example:
        >>> signed = batch_sign(data, [key1, key2, key3])
        >>> len(signed.proofs)  # 3
    """
    if not private_keys:
        raise ValueError("At least one private key is required")

    proofs: List[SignatureProof] = []
    for key in private_keys:
        proof = sign_data_update(value, key) if is_data_update else sign(value, key)
        proofs.append(proof)

    return Signed(value=value, proofs=proofs)
