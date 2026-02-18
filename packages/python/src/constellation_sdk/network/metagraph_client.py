"""
Generic Metagraph Client for any L1 layer type.

Works with ML0 (Metagraph L0), CL1 (Currency L1), and DL1 (Data L1) nodes.
"""

from enum import Enum
from typing import Any, Optional, TypeVar

from ..currency_types import TransactionReference
from ..types import Signed
from .client import HttpClient
from .types import (
    EstimateFeeResponse,
    NetworkError,
    PendingTransaction,
    PostDataResponse,
    PostTransactionResponse,
    RequestOptions,
)

T = TypeVar("T")


class LayerType(str, Enum):
    """Supported L1 layer types."""

    ML0 = "ml0"
    CL1 = "cl1"
    DL1 = "dl1"


class ClusterInfo:
    """Cluster information from any L1 node."""

    def __init__(self, **kwargs: Any):
        self.size: Optional[int] = kwargs.get("size")
        self.cluster_id: Optional[str] = kwargs.get("clusterId")
        self._data = kwargs

    def __getitem__(self, key: str) -> Any:
        return self._data.get(key)


class MetagraphClientConfig:
    """Configuration for MetagraphClient."""

    def __init__(
        self,
        base_url: str,
        layer: LayerType,
        timeout: Optional[int] = None,
    ):
        """
        Create client configuration.

        Args:
            base_url: Base URL of the L1 node (e.g., 'http://localhost:9200')
            layer: Layer type for API path selection
            timeout: Request timeout in milliseconds (default: 30000)
        """
        self.base_url = base_url
        self.layer = layer
        self.timeout = timeout


class MetagraphClient:
    """
    Generic client for interacting with any Metagraph L1 layer.

    This client provides a unified interface for ML0, CL1, and DL1 nodes,
    automatically selecting the correct API paths based on layer type.

    Example::

        # Connect to a Currency L1 node
        cl1 = MetagraphClient(MetagraphClientConfig(
            base_url='http://localhost:9300',
            layer=LayerType.CL1
        ))

        # Connect to a Data L1 node
        dl1 = MetagraphClient(MetagraphClientConfig(
            base_url='http://localhost:9400',
            layer=LayerType.DL1
        ))

        # Connect to a Metagraph L0 node
        ml0 = MetagraphClient(MetagraphClientConfig(
            base_url='http://localhost:9200',
            layer=LayerType.ML0
        ))
    """

    def __init__(self, config: MetagraphClientConfig):
        """
        Create a new MetagraphClient.

        Args:
            config: Client configuration

        Raises:
            ValueError: If base_url or layer is not provided
        """
        if not config.base_url:
            raise ValueError("base_url is required for MetagraphClient")
        if not config.layer:
            raise ValueError("layer is required for MetagraphClient")
        self._client = HttpClient(config.base_url, config.timeout)
        self._layer = config.layer

    @property
    def layer(self) -> LayerType:
        """Get the layer type of this client."""
        return self._layer

    # ============================================
    # Common operations (all layers)
    # ============================================

    def check_health(self, options: Optional[RequestOptions] = None) -> bool:
        """
        Check the health/availability of the node.

        Args:
            options: Request options

        Returns:
            True if the node is healthy
        """
        try:
            self._client.get("/cluster/info", options)
            return True
        except Exception:
            return False

    def get_cluster_info(
        self, options: Optional[RequestOptions] = None
    ) -> ClusterInfo:
        """
        Get cluster information.

        Args:
            options: Request options

        Returns:
            Cluster information
        """
        data = self._client.get("/cluster/info", options)
        return ClusterInfo(**data)

    # ============================================
    # Currency operations (CL1 and ML0)
    # ============================================

    def get_last_reference(
        self,
        address: str,
        options: Optional[RequestOptions] = None,
    ) -> TransactionReference:
        """
        Get the last accepted transaction reference for an address.

        This is needed to create a new transaction that chains from
        the address's most recent transaction.

        Available on: CL1, ML0 (if currency enabled)

        Args:
            address: DAG address to query
            options: Request options

        Returns:
            Transaction reference with hash and ordinal

        Raises:
            ValueError: If called on unsupported layer
        """
        self._assert_layer([LayerType.CL1, LayerType.ML0], "get_last_reference")
        data = self._client.get(f"/transactions/last-reference/{address}", options)
        return TransactionReference(hash=data["hash"], ordinal=data["ordinal"])

    def post_transaction(
        self,
        transaction: Any,
        options: Optional[RequestOptions] = None,
    ) -> PostTransactionResponse:
        """
        Submit a signed currency transaction.

        Available on: CL1

        Args:
            transaction: Signed currency transaction
            options: Request options

        Returns:
            Response containing the transaction hash

        Raises:
            ValueError: If called on unsupported layer
        """
        self._assert_layer([LayerType.CL1], "post_transaction")
        tx_dict = self._transaction_to_dict(transaction)
        data = self._client.post("/transactions", tx_dict, options)
        return PostTransactionResponse(hash=data["hash"])

    def get_pending_transaction(
        self,
        hash: str,
        options: Optional[RequestOptions] = None,
    ) -> Optional[PendingTransaction]:
        """
        Get a pending transaction by hash.

        Available on: CL1

        Args:
            hash: Transaction hash
            options: Request options

        Returns:
            Pending transaction details or None if not found

        Raises:
            ValueError: If called on unsupported layer
        """
        self._assert_layer([LayerType.CL1], "get_pending_transaction")
        try:
            data = self._client.get(f"/transactions/{hash}", options)
            return PendingTransaction(
                hash=data["hash"],
                status=data["status"],
                transaction=data["transaction"],
            )
        except NetworkError as e:
            if e.status_code == 404:
                return None
            raise

    # ============================================
    # Data operations (DL1)
    # ============================================

    def estimate_fee(
        self,
        data: Signed[T],
        options: Optional[RequestOptions] = None,
    ) -> EstimateFeeResponse:
        """
        Estimate the fee for submitting data.

        Available on: DL1

        Args:
            data: Signed data object to estimate fee for
            options: Request options

        Returns:
            Fee estimate with amount and destination address

        Raises:
            ValueError: If called on unsupported layer
        """
        self._assert_layer([LayerType.DL1], "estimate_fee")
        data_dict = self._signed_to_dict(data)
        result = self._client.post("/data/estimate-fee", data_dict, options)
        return EstimateFeeResponse(fee=result["fee"], address=result["address"])

    def post_data(
        self,
        data: Signed[T],
        options: Optional[RequestOptions] = None,
    ) -> PostDataResponse:
        """
        Submit signed data to the Data L1 node.

        Available on: DL1

        Args:
            data: Signed data object to submit
            options: Request options

        Returns:
            Response containing the data hash

        Raises:
            ValueError: If called on unsupported layer
        """
        self._assert_layer([LayerType.DL1], "post_data")
        data_dict = self._signed_to_dict(data)
        result = self._client.post("/data", data_dict, options)
        return PostDataResponse(hash=result["hash"])

    # ============================================
    # Raw HTTP access
    # ============================================

    def get(self, path: str, options: Optional[RequestOptions] = None) -> Any:
        """
        Make a raw GET request to the node.

        Args:
            path: API path
            options: Request options

        Returns:
            Response data
        """
        return self._client.get(path, options)

    def post(
        self,
        path: str,
        body: Optional[Any] = None,
        options: Optional[RequestOptions] = None,
    ) -> Any:
        """
        Make a raw POST request to the node.

        Args:
            path: API path
            body: Request body
            options: Request options

        Returns:
            Response data
        """
        return self._client.post(path, body, options)

    # ============================================
    # Helpers
    # ============================================

    def _assert_layer(self, allowed: list[LayerType], method: str) -> None:
        if self._layer not in allowed:
            allowed_str = ", ".join(layer.value.upper() for layer in allowed)
            raise ValueError(
                f"{method}() is not available on {self._layer.value.upper()} layer. "
                f"Available on: {allowed_str}"
            )

    def _transaction_to_dict(self, tx: Any) -> dict[str, object]:
        """Convert a CurrencyTransaction to a dict for JSON serialization."""
        return {
            "value": {
                "source": tx.value.source,
                "destination": tx.value.destination,
                "amount": tx.value.amount,
                "fee": tx.value.fee,
                "parent": {
                    "hash": tx.value.parent.hash,
                    "ordinal": tx.value.parent.ordinal,
                },
                "salt": tx.value.salt,
            },
            "proofs": [{"id": p.id, "signature": p.signature} for p in tx.proofs],
        }

    def _signed_to_dict(self, signed: Signed[T]) -> dict[str, object]:
        """Convert a Signed object to a dict for JSON serialization."""
        value = signed.value
        value_dict: object
        if hasattr(value, "__dict__"):
            result: dict[str, object] = {}
            for k, v in value.__dict__.items():
                if not k.startswith("_"):
                    if hasattr(v, "__dict__"):
                        result[k] = {
                            kk: vv
                            for kk, vv in v.__dict__.items()
                            if not kk.startswith("_")
                        }
                    else:
                        result[k] = v
            value_dict = result
        else:
            value_dict = value

        return {
            "value": value_dict,
            "proofs": [{"id": p.id, "signature": p.signature} for p in signed.proofs],
        }


def create_metagraph_client(
    base_url: str,
    layer: LayerType,
    timeout: Optional[int] = None,
) -> MetagraphClient:
    """
    Create a MetagraphClient for a specific layer.

    Args:
        base_url: Node URL
        layer: Layer type
        timeout: Request timeout

    Returns:
        Configured MetagraphClient
    """
    return MetagraphClient(
        MetagraphClientConfig(base_url=base_url, layer=layer, timeout=timeout)
    )
