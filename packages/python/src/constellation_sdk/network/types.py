"""
Network types for L1 client operations.
"""

from dataclasses import dataclass, field
from typing import Dict, Literal, Optional

from ..currency_types import CurrencyTransaction


@dataclass
class NetworkConfig:
    """Network configuration for connecting to L1 nodes."""

    l1_url: Optional[str] = None
    """Currency L1 endpoint URL (e.g., 'http://localhost:9010')."""

    data_l1_url: Optional[str] = None
    """Data L1 endpoint URL (e.g., 'http://localhost:8080')."""

    timeout: float = 30.0
    """Request timeout in seconds (default: 30)."""


@dataclass
class RequestOptions:
    """HTTP request options."""

    timeout: Optional[float] = None
    """Request timeout in seconds."""

    headers: Dict[str, str] = field(default_factory=dict)
    """Additional headers."""


TransactionStatus = Literal["Waiting", "InProgress", "Accepted"]
"""Transaction status in the network."""


@dataclass
class PendingTransaction:
    """Pending transaction response from L1."""

    hash: str
    """Transaction hash."""

    status: TransactionStatus
    """Current status."""

    transaction: CurrencyTransaction
    """The transaction value."""


@dataclass
class PostTransactionResponse:
    """Response from posting a transaction."""

    hash: str
    """Transaction hash."""


@dataclass
class EstimateFeeResponse:
    """Response from estimating data transaction fee."""

    fee: int
    """Estimated fee in smallest units."""

    address: str
    """Fee destination address."""


@dataclass
class PostDataResponse:
    """Response from posting data."""

    hash: str
    """Data hash."""


class NetworkError(Exception):
    """Network error with status code and response details."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response: Optional[str] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response = response

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status_code is not None:
            parts.append(f"(status: {self.status_code})")
        return " ".join(parts)
