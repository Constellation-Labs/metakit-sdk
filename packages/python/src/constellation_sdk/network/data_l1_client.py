"""
Data L1 client for submitting data transactions to metagraphs.
"""

from typing import Optional, TypeVar

from ..types import Signed
from .client import HttpClient
from .types import (
    EstimateFeeResponse,
    NetworkConfig,
    PostDataResponse,
    RequestOptions,
)

T = TypeVar("T")


class DataL1Client:
    """
    Client for interacting with Data L1 nodes (metagraphs).

    Example::

        client = DataL1Client(NetworkConfig(data_l1_url='http://localhost:8080'))

        # Estimate fee for data submission
        fee_info = client.estimate_fee(signed_data)

        # Submit data
        result = client.post_data(signed_data)
    """

    def __init__(self, config: NetworkConfig):
        """
        Create a new DataL1Client.

        Args:
            config: Network configuration with data_l1_url

        Raises:
            ValueError: If data_l1_url is not provided
        """
        if not config.data_l1_url:
            raise ValueError("data_l1_url is required for DataL1Client")
        self._client = HttpClient(config.data_l1_url, config.timeout)

    def estimate_fee(
        self,
        data: Signed[T],
        options: Optional[RequestOptions] = None,
    ) -> EstimateFeeResponse:
        """
        Estimate the fee for submitting data.

        Some metagraphs charge fees for data submissions.
        Call this before post_data to know the required fee.

        Args:
            data: Signed data object to estimate fee for
            options: Request options

        Returns:
            Fee estimate with amount and destination address
        """
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

        Args:
            data: Signed data object to submit
            options: Request options

        Returns:
            Response containing the data hash
        """
        data_dict = self._signed_to_dict(data)
        result = self._client.post("/data", data_dict, options)
        return PostDataResponse(hash=result["hash"])

    def check_health(self, options: Optional[RequestOptions] = None) -> bool:
        """
        Check the health/availability of the Data L1 node.

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
                            kk: vv for kk, vv in v.__dict__.items() if not kk.startswith("_")
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
