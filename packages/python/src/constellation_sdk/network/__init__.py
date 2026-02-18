"""
Network operations for Metagraph L1 node interactions.

This module provides clients for interacting with Constellation Network
metagraph nodes at various layers:

- **ML0** (Metagraph L0): State channel operations
- **CL1** (Currency L1): Currency transactions
- **DL1** (Data L1): Data/update submissions

Example::

    # Generic client for any layer
    from constellation_sdk.network import MetagraphClient, LayerType, create_metagraph_client

    dl1 = create_metagraph_client('http://localhost:9400', LayerType.DL1)
    await dl1.post_data(signed_data)

    # Or use convenience clients
    from constellation_sdk.network import CurrencyL1Client, DataL1Client

    currency_client = CurrencyL1Client(NetworkConfig(l1_url='http://localhost:9300'))
    data_client = DataL1Client(NetworkConfig(data_l1_url='http://localhost:9400'))
"""

# Generic metagraph client
from .metagraph_client import (
    ClusterInfo,
    LayerType,
    MetagraphClient,
    MetagraphClientConfig,
    create_metagraph_client,
)

# Convenience clients (backwards compatible)
from .currency_l1_client import CurrencyL1Client
from .data_l1_client import DataL1Client

# Types and errors
from .types import (
    EstimateFeeResponse,
    NetworkConfig,
    NetworkError,
    PendingTransaction,
    PostDataResponse,
    PostTransactionResponse,
    RequestOptions,
    TransactionStatus,
)

__all__ = [
    # Generic client
    "MetagraphClient",
    "MetagraphClientConfig",
    "LayerType",
    "ClusterInfo",
    "create_metagraph_client",
    # Convenience clients
    "CurrencyL1Client",
    "DataL1Client",
    # Types
    "NetworkConfig",
    "RequestOptions",
    "TransactionStatus",
    "PendingTransaction",
    "PostTransactionResponse",
    "EstimateFeeResponse",
    "PostDataResponse",
    "NetworkError",
]
