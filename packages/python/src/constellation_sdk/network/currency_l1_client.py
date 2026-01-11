"""
Currency L1 client for submitting and querying transactions.
"""

from typing import Optional

from ..currency_types import CurrencyTransaction, TransactionReference
from .client import HttpClient
from .types import (
    NetworkConfig,
    NetworkError,
    PendingTransaction,
    PostTransactionResponse,
    RequestOptions,
)


class CurrencyL1Client:
    """
    Client for interacting with Currency L1 nodes.

    Example::

        client = CurrencyL1Client(NetworkConfig(l1_url='http://localhost:9010'))

        # Get last reference for an address
        last_ref = client.get_last_reference('DAG...')

        # Submit a transaction
        result = client.post_transaction(signed_tx)

        # Check transaction status
        pending = client.get_pending_transaction(result.hash)
    """

    def __init__(self, config: NetworkConfig):
        """
        Create a new CurrencyL1Client.

        Args:
            config: Network configuration with l1_url

        Raises:
            ValueError: If l1_url is not provided
        """
        if not config.l1_url:
            raise ValueError("l1_url is required for CurrencyL1Client")
        self._client = HttpClient(config.l1_url, config.timeout)

    def get_last_reference(
        self,
        address: str,
        options: Optional[RequestOptions] = None,
    ) -> TransactionReference:
        """
        Get the last accepted transaction reference for an address.

        This is needed to create a new transaction that chains from
        the address's most recent transaction.

        Args:
            address: DAG address to query
            options: Request options

        Returns:
            Transaction reference with hash and ordinal
        """
        data = self._client.get(f"/transactions/last-reference/{address}", options)
        return TransactionReference(hash=data["hash"], ordinal=data["ordinal"])

    def post_transaction(
        self,
        transaction: CurrencyTransaction,
        options: Optional[RequestOptions] = None,
    ) -> PostTransactionResponse:
        """
        Submit a signed currency transaction to the L1 network.

        Args:
            transaction: Signed currency transaction
            options: Request options

        Returns:
            Response containing the transaction hash
        """
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

        Use this to poll for transaction status after submission.
        Returns None if the transaction is not found (already confirmed or invalid).

        Args:
            hash: Transaction hash
            options: Request options

        Returns:
            Pending transaction details or None if not found
        """
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

    def check_health(self, options: Optional[RequestOptions] = None) -> bool:
        """
        Check the health/availability of the L1 node.

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

    def _transaction_to_dict(self, tx: CurrencyTransaction) -> dict[str, object]:
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
