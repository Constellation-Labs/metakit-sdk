"""
Currency transaction types for metagraph token transfers.

Type definitions for v2 currency transactions.
"""

from dataclasses import dataclass
from typing import TypeAlias

from constellation_metagraph.core.types import Signed

# Token decimals constant (1e-8) - same as DAG_DECIMALS from dag4.js
TOKEN_DECIMALS = 1e-8
"""Token decimals constant (1e-8)."""


@dataclass(frozen=True)
class TransactionReference:
    """Reference to a previous transaction for chaining."""

    hash: str
    """Transaction hash (64-character hex string)."""

    ordinal: int
    """Transaction ordinal number."""


@dataclass
class CurrencyTransactionValue:
    """
    Currency transaction value structure (v2).

    Contains the actual transaction data before signing.
    Used for metagraph token transfers.
    """

    source: str
    """Source DAG address."""

    destination: str
    """Destination DAG address."""

    amount: int
    """Amount in smallest units (1e-8)."""

    fee: int
    """Fee in smallest units (1e-8)."""

    parent: TransactionReference
    """Reference to parent transaction."""

    salt: str
    """Random salt for uniqueness (as string)."""


# Currency transaction is a signed currency transaction value
CurrencyTransaction: TypeAlias = Signed[CurrencyTransactionValue]
"""
Currency transaction structure (v2).

A signed currency transaction value.
Used for metagraph token transfers.
"""


@dataclass(frozen=True)
class TransferParams:
    """Parameters for creating a token transfer."""

    destination: str
    """Destination DAG address."""

    amount: float
    """Amount in token units (e.g., 100.5 tokens)."""

    fee: float = 0.0
    """Fee in token units (defaults to 0)."""
