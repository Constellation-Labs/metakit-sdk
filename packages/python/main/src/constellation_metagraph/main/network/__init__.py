"""
Network operations for Metagraph L1 node interactions.

This module provides a unified client for interacting with Constellation Network
metagraph nodes at various layers:

- **ML0** (Metagraph L0): State channel operations
- **CL1** (Currency L1): Currency transactions
- **DL1** (Data L1): Data/update submissions

Example::

    from constellation_sdk.network import MetagraphClient, LayerType, create_metagraph_client

    # Currency L1 client
    cl1 = create_metagraph_client('http://localhost:9300', LayerType.CL1)
    ref = cl1.get_last_reference(address)
    cl1.post_transaction(signed_tx)

    # Data L1 client
    dl1 = create_metagraph_client('http://localhost:9400', LayerType.DL1)
    fee = dl1.estimate_fee(signed_data)
    dl1.post_data(signed_data)

    # Metagraph L0 client
    ml0 = create_metagraph_client('http://localhost:9200', LayerType.ML0)
    info = ml0.get_cluster_info()
"""

from .metagraph_client import (
    ClusterInfo,
    LayerType,
    MetagraphClient,
    MetagraphClientConfig,
    create_metagraph_client,
)
from .types import (
    EstimateFeeResponse,
    NetworkError,
    PendingTransaction,
    PostDataResponse,
    PostTransactionResponse,
    RequestOptions,
    TransactionStatus,
)

__all__ = [
    # Client
    "MetagraphClient",
    "MetagraphClientConfig",
    "LayerType",
    "ClusterInfo",
    "create_metagraph_client",
    # Types
    "RequestOptions",
    "TransactionStatus",
    "PendingTransaction",
    "PostTransactionResponse",
    "EstimateFeeResponse",
    "PostDataResponse",
    "NetworkError",
]
