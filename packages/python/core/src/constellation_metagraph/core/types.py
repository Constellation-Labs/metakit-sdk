"""
Core type definitions for the Constellation Metagraph SDK.
"""

from dataclasses import dataclass, field
from typing import Generic, List, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class SignatureProof:
    """A signature proof containing the signer's public key ID and signature."""

    id: str
    """Public key hex (uncompressed, without 04 prefix) - 128 characters."""

    signature: str
    """DER-encoded ECDSA signature in hex format."""


@dataclass
class Signed(Generic[T]):
    """A signed object wrapping a value with one or more signature proofs."""

    value: T
    """The signed value."""

    proofs: List[SignatureProof] = field(default_factory=list)
    """List of signature proofs."""

    def add_proof(self, proof: SignatureProof) -> "Signed[T]":
        """Return a new Signed object with an additional proof."""
        return Signed(value=self.value, proofs=[*self.proofs, proof])


@dataclass(frozen=True)
class KeyPair:
    """A key pair for signing operations."""

    private_key: str
    """Private key in hex format."""

    public_key: str
    """Public key in hex format (uncompressed, with 04 prefix)."""

    address: str
    """DAG address derived from the public key."""


@dataclass(frozen=True)
class Hash:
    """A hash result containing both hex string and raw bytes."""

    value: str
    """SHA-256 hash as 64-character hex string."""

    bytes: bytes
    """Raw 32-byte hash."""


@dataclass
class VerificationResult:
    """Result of signature verification."""

    is_valid: bool
    """Whether all signatures are valid."""

    valid_proofs: List[SignatureProof] = field(default_factory=list)
    """Proofs that passed verification."""

    invalid_proofs: List[SignatureProof] = field(default_factory=list)
    """Proofs that failed verification."""


# Constants
ALGORITHM = "SECP256K1_RFC8785_V1"
"""Supported signature algorithm."""

CONSTELLATION_PREFIX = "\x19Constellation Signed Data:\n"
"""Constellation prefix for DataUpdate signing."""
