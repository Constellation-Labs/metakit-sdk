"""
Constellation Metagraph SDK — main (batteries-included) tier.

The batteries-included base library: re-exports the entire offline ``core`` kernel
(signing, verification, wallet, canonicalization, hashing, codecs) and adds currency
transaction helpers plus network clients for talking to ML0/CL1/DL1 nodes.

This distribution ships the ``constellation_metagraph.main`` namespace package and
depends on ``constellation-metagraph-sdk-core``.

For network operations, import from the network module:

    from constellation_metagraph.main.network import (
        MetagraphClient,
        create_metagraph_client,
        LayerType,
    )

    cl1 = create_metagraph_client('http://localhost:9300', LayerType.CL1)
    dl1 = create_metagraph_client('http://localhost:9400', LayerType.DL1)
"""

from importlib.metadata import PackageNotFoundError, version

# Re-export the full offline core kernel (signing, verification, wallet, ...).
from constellation_metagraph.core import *  # noqa: F401,F403
from constellation_metagraph.core import __all__ as _core_all

try:
    __version__ = version("constellation-metagraph-sdk")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"  # Fallback for development

# Currency transaction operations
from constellation_metagraph.main.currency_transaction import (
    create_currency_transaction,
    create_currency_transaction_batch,
    encode_currency_transaction,
    get_transaction_reference,
    hash_currency_transaction,
    is_valid_dag_address,
    sign_currency_transaction,
    token_to_units,
    units_to_token,
    verify_currency_transaction,
)

# Currency transaction types
from constellation_metagraph.main.currency_types import (
    TOKEN_DECIMALS,
    CurrencyTransaction,
    CurrencyTransactionValue,
    TransactionReference,
    TransferParams,
)

# Network types (for convenience - full network module has more)
from constellation_metagraph.main.network import (
    EstimateFeeResponse,
    NetworkError,
    PendingTransaction,
    PostDataResponse,
    PostTransactionResponse,
    RequestOptions,
    TransactionStatus,
)

_main_all = [
    # Currency transaction types
    "TransactionReference",
    "CurrencyTransactionValue",
    "CurrencyTransaction",
    "TransferParams",
    "TOKEN_DECIMALS",
    # Currency transactions
    "create_currency_transaction",
    "create_currency_transaction_batch",
    "sign_currency_transaction",
    "verify_currency_transaction",
    "encode_currency_transaction",
    "hash_currency_transaction",
    "get_transaction_reference",
    "is_valid_dag_address",
    "token_to_units",
    "units_to_token",
    # Network types (clients in network submodule)
    "NetworkError",
    "RequestOptions",
    "TransactionStatus",
    "PendingTransaction",
    "PostTransactionResponse",
    "EstimateFeeResponse",
    "PostDataResponse",
]

# main's public surface = everything core re-exports + the currency/network additions.
__all__ = list(dict.fromkeys([*_core_all, *_main_all]))
