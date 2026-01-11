package io.constellationnetwork.metagraph.sdk;

/**
 * Client for interacting with Currency L1 nodes.
 *
 * <p>Example usage:
 * <pre>{@code
 * NetworkConfig config = new NetworkConfig.Builder()
 *     .l1Url("http://localhost:9010")
 *     .build();
 *
 * CurrencyL1Client client = new CurrencyL1Client(config);
 *
 * // Get last reference for an address
 * TransactionReference lastRef = client.getLastReference("DAG...");
 *
 * // Submit a transaction
 * PostTransactionResponse result = client.postTransaction(signedTx);
 *
 * // Check transaction status
 * PendingTransaction pending = client.getPendingTransaction(result.getHash());
 * }</pre>
 */
public class CurrencyL1Client {

    private final HttpClient client;

    /**
     * Create a new CurrencyL1Client.
     *
     * @param config Network configuration with l1Url
     * @throws IllegalArgumentException if l1Url is not provided
     */
    public CurrencyL1Client(NetworkTypes.NetworkConfig config) {
        if (config.getL1Url() == null || config.getL1Url().isEmpty()) {
            throw new IllegalArgumentException("l1Url is required for CurrencyL1Client");
        }
        this.client = new HttpClient(config.getL1Url(), config.getTimeout());
    }

    /**
     * Get the last accepted transaction reference for an address.
     *
     * <p>This is needed to create a new transaction that chains from
     * the address's most recent transaction.
     *
     * @param address DAG address to query
     * @return Transaction reference with hash and ordinal
     */
    public CurrencyTypes.TransactionReference getLastReference(String address) {
        return client.get(
                "/transactions/last-reference/" + address,
                CurrencyTypes.TransactionReference.class
        );
    }

    /**
     * Submit a signed currency transaction to the L1 network.
     *
     * @param transaction Signed currency transaction
     * @return Response containing the transaction hash
     */
    public NetworkTypes.PostTransactionResponse postTransaction(CurrencyTypes.CurrencyTransaction transaction) {
        return client.post(
                "/transactions",
                transaction,
                NetworkTypes.PostTransactionResponse.class
        );
    }

    /**
     * Get a pending transaction by hash.
     *
     * <p>Use this to poll for transaction status after submission.
     * Returns null if the transaction is not found (already confirmed or invalid).
     *
     * @param hash Transaction hash
     * @return Pending transaction details or null if not found
     */
    public NetworkTypes.PendingTransaction getPendingTransaction(String hash) {
        try {
            return client.get(
                    "/transactions/" + hash,
                    NetworkTypes.PendingTransaction.class
            );
        } catch (NetworkTypes.NetworkException e) {
            if (e.getStatusCode() == 404) {
                return null;
            }
            throw e;
        }
    }

    /**
     * Check the health/availability of the L1 node.
     *
     * @return true if the node is healthy
     */
    public boolean checkHealth() {
        try {
            client.get("/cluster/info", Object.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
