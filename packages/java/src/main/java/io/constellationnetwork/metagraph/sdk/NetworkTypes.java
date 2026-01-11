package io.constellationnetwork.metagraph.sdk;

import java.util.List;
import java.util.Objects;

/**
 * Network types for L1 client operations.
 */
public final class NetworkTypes {

    private NetworkTypes() {
        // Utility class
    }

    /**
     * Network configuration for connecting to L1 nodes.
     */
    public static class NetworkConfig {
        private final String l1Url;
        private final String dataL1Url;
        private final int timeout;

        private NetworkConfig(Builder builder) {
            this.l1Url = builder.l1Url;
            this.dataL1Url = builder.dataL1Url;
            this.timeout = builder.timeout;
        }

        public String getL1Url() {
            return l1Url;
        }

        public String getDataL1Url() {
            return dataL1Url;
        }

        public int getTimeout() {
            return timeout;
        }

        public static class Builder {
            private String l1Url;
            private String dataL1Url;
            private int timeout = 30;

            public Builder l1Url(String l1Url) {
                this.l1Url = l1Url;
                return this;
            }

            public Builder dataL1Url(String dataL1Url) {
                this.dataL1Url = dataL1Url;
                return this;
            }

            public Builder timeout(int timeout) {
                this.timeout = timeout;
                return this;
            }

            public NetworkConfig build() {
                return new NetworkConfig(this);
            }
        }
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
