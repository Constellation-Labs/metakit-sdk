package io.constellationnetwork.metagraph.sdk;

/**
 * Network types for L1 client operations.
 */
public final class NetworkTypes {

    private NetworkTypes() {
        // Utility class
    }

    /**
     * Transaction status in the network.
     */
    public enum TransactionStatus {
        Waiting,
        InProgress,
        Accepted
    }

    /**
     * Pending transaction response from L1.
     */
    public static class PendingTransaction {
        private final String hash;
        private final TransactionStatus status;
        private final CurrencyTypes.CurrencyTransaction transaction;

        public PendingTransaction(String hash, TransactionStatus status, CurrencyTypes.CurrencyTransaction transaction) {
            this.hash = hash;
            this.status = status;
            this.transaction = transaction;
        }

        public String getHash() {
            return hash;
        }

        public TransactionStatus getStatus() {
            return status;
        }

        public CurrencyTypes.CurrencyTransaction getTransaction() {
            return transaction;
        }
    }

    /**
     * Response from posting a transaction.
     */
    public static class PostTransactionResponse {
        private final String hash;

        public PostTransactionResponse(String hash) {
            this.hash = hash;
        }

        public String getHash() {
            return hash;
        }
    }

    /**
     * Response from estimating data transaction fee.
     */
    public static class EstimateFeeResponse {
        private final long fee;
        private final String address;

        public EstimateFeeResponse(long fee, String address) {
            this.fee = fee;
            this.address = address;
        }

        public long getFee() {
            return fee;
        }

        public String getAddress() {
            return address;
        }
    }

    /**
     * Response from posting data.
     */
    public static class PostDataResponse {
        private final String hash;

        public PostDataResponse(String hash) {
            this.hash = hash;
        }

        public String getHash() {
            return hash;
        }
    }

    /**
     * Network error with status code and response details.
     */
    public static class NetworkException extends RuntimeException {
        private final int statusCode;
        private final String response;

        public NetworkException(String message) {
            this(message, 0, null);
        }

        public NetworkException(String message, int statusCode, String response) {
            super(message);
            this.statusCode = statusCode;
            this.response = response;
        }

        public NetworkException(String message, Throwable cause) {
            super(message, cause);
            this.statusCode = 0;
            this.response = null;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getResponse() {
            return response;
        }

        @Override
        public String toString() {
            if (statusCode > 0) {
                return getMessage() + " (status: " + statusCode + ")";
            }
            return getMessage();
        }
    }
}
