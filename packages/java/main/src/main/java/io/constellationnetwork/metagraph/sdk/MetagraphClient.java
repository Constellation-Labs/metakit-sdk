package io.constellationnetwork.metagraph.sdk;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Generic client for interacting with any Metagraph L1 layer.
 *
 * <p>This client provides a unified interface for ML0, CL1, and DL1 nodes,
 * automatically selecting the correct API paths based on layer type.
 *
 * <p>Example usage:
 * <pre>{@code
 * // Connect to a Currency L1 node
 * MetagraphClient cl1 = new MetagraphClient("http://localhost:9300", LayerType.CL1);
 *
 * // Connect to a Data L1 node
 * MetagraphClient dl1 = new MetagraphClient("http://localhost:9400", LayerType.DL1);
 *
 * // Connect to a Metagraph L0 node
 * MetagraphClient ml0 = new MetagraphClient("http://localhost:9200", LayerType.ML0);
 *
 * // Get last reference (CL1 and ML0)
 * TransactionReference ref = cl1.getLastReference("DAG...");
 *
 * // Post data (DL1 only)
 * PostDataResponse result = dl1.postData(signedData);
 * }</pre>
 */
public class MetagraphClient {

    /**
     * Supported L1 layer types.
     */
    public enum LayerType {
        /** Metagraph L0 - state channel operations */
        ML0("ml0"),
        /** Currency L1 - currency transactions */
        CL1("cl1"),
        /** Data L1 - data/update submissions */
        DL1("dl1");

        private final String value;

        LayerType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return name();
        }
    }

    /**
     * Cluster information from any L1 node.
     */
    public static class ClusterInfo {
        private Integer size;
        private String clusterId;
        private Map<String, Object> extra;

        public Integer getSize() {
            return size;
        }

        public void setSize(Integer size) {
            this.size = size;
        }

        public String getClusterId() {
            return clusterId;
        }

        public void setClusterId(String clusterId) {
            this.clusterId = clusterId;
        }

        public Map<String, Object> getExtra() {
            return extra;
        }

        public void setExtra(Map<String, Object> extra) {
            this.extra = extra;
        }
    }

    /**
     * Configuration for MetagraphClient.
     */
    public static class Config {
        private final String baseUrl;
        private final LayerType layer;
        private final Integer timeout;

        private Config(Builder builder) {
            this.baseUrl = builder.baseUrl;
            this.layer = builder.layer;
            this.timeout = builder.timeout;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public LayerType getLayer() {
            return layer;
        }

        public Integer getTimeout() {
            return timeout;
        }

        public static class Builder {
            private String baseUrl;
            private LayerType layer;
            private Integer timeout;

            public Builder baseUrl(String baseUrl) {
                this.baseUrl = baseUrl;
                return this;
            }

            public Builder layer(LayerType layer) {
                this.layer = layer;
                return this;
            }

            public Builder timeout(Integer timeout) {
                this.timeout = timeout;
                return this;
            }

            public Config build() {
                return new Config(this);
            }
        }
    }

    private final HttpClient client;
    private final LayerType layer;

    /**
     * Create a new MetagraphClient.
     *
     * @param baseUrl Base URL of the L1 node
     * @param layer Layer type (ML0, CL1, or DL1)
     * @throws IllegalArgumentException if baseUrl or layer is null
     */
    public MetagraphClient(String baseUrl, LayerType layer) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new IllegalArgumentException("baseUrl is required for MetagraphClient");
        }
        if (layer == null) {
            throw new IllegalArgumentException("layer is required for MetagraphClient");
        }
        this.client = new HttpClient(baseUrl, 30);
        this.layer = layer;
    }

    /**
     * Create a new MetagraphClient with full configuration.
     *
     * @param config Client configuration
     */
    public MetagraphClient(Config config) {
        if (config.getBaseUrl() == null || config.getBaseUrl().isEmpty()) {
            throw new IllegalArgumentException("baseUrl is required for MetagraphClient");
        }
        if (config.getLayer() == null) {
            throw new IllegalArgumentException("layer is required for MetagraphClient");
        }
        this.client = new HttpClient(config.getBaseUrl(), config.getTimeout());
        this.layer = config.getLayer();
    }

    /**
     * Get the layer type of this client.
     *
     * @return Layer type
     */
    public LayerType getLayer() {
        return layer;
    }

    // ============================================
    // Common operations (all layers)
    // ============================================

    /**
     * Check the health/availability of the node.
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

    /**
     * Get cluster information.
     *
     * @return Cluster information
     */
    public ClusterInfo getClusterInfo() {
        return client.get("/cluster/info", ClusterInfo.class);
    }

    // ============================================
    // Currency operations (CL1 and ML0)
    // ============================================

    /**
     * Get the last accepted transaction reference for an address.
     *
     * <p>This is needed to create a new transaction that chains from
     * the address's most recent transaction.
     *
     * <p>Available on: CL1, ML0 (if currency enabled)
     *
     * @param address DAG address to query
     * @return Transaction reference with hash and ordinal
     * @throws IllegalStateException if called on unsupported layer
     */
    public CurrencyTypes.TransactionReference getLastReference(String address) {
        assertLayer(Set.of(LayerType.CL1, LayerType.ML0), "getLastReference");
        return client.get(
                "/transactions/last-reference/" + address,
                CurrencyTypes.TransactionReference.class
        );
    }

    /**
     * Submit a signed currency transaction.
     *
     * <p>Available on: CL1
     *
     * @param transaction Signed currency transaction
     * @return Response containing the transaction hash
     * @throws IllegalStateException if called on unsupported layer
     */
    public NetworkTypes.PostTransactionResponse postTransaction(CurrencyTypes.CurrencyTransaction transaction) {
        assertLayer(Set.of(LayerType.CL1), "postTransaction");
        return client.post(
                "/transactions",
                transaction,
                NetworkTypes.PostTransactionResponse.class
        );
    }

    /**
     * Get a pending transaction by hash.
     *
     * <p>Available on: CL1
     *
     * @param hash Transaction hash
     * @return Pending transaction details or null if not found
     * @throws IllegalStateException if called on unsupported layer
     */
    public NetworkTypes.PendingTransaction getPendingTransaction(String hash) {
        assertLayer(Set.of(LayerType.CL1), "getPendingTransaction");
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

    // ============================================
    // Data operations (DL1)
    // ============================================

    /**
     * Estimate the fee for submitting data.
     *
     * <p>Available on: DL1
     *
     * @param data Signed data object to estimate fee for
     * @return Fee estimate with amount and destination address
     * @throws IllegalStateException if called on unsupported layer
     */
    public NetworkTypes.EstimateFeeResponse estimateFee(Object data) {
        assertLayer(Set.of(LayerType.DL1), "estimateFee");
        return client.post(
                "/data/estimate-fee",
                data,
                NetworkTypes.EstimateFeeResponse.class
        );
    }

    /**
     * Submit signed data to the Data L1 node.
     *
     * <p>Available on: DL1
     *
     * @param data Signed data object to submit
     * @return Response containing the data hash
     * @throws IllegalStateException if called on unsupported layer
     */
    public NetworkTypes.PostDataResponse postData(Object data) {
        assertLayer(Set.of(LayerType.DL1), "postData");
        return client.post(
                "/data",
                data,
                NetworkTypes.PostDataResponse.class
        );
    }

    // ============================================
    // Raw HTTP access
    // ============================================

    /**
     * Make a raw GET request to the node.
     *
     * @param path API path
     * @param responseType Response type class
     * @param <T> Response type
     * @return Response data
     */
    public <T> T get(String path, Class<T> responseType) {
        return client.get(path, responseType);
    }

    /**
     * Make a raw POST request to the node.
     *
     * @param path API path
     * @param body Request body
     * @param responseType Response type class
     * @param <T> Response type
     * @return Response data
     */
    public <T> T post(String path, Object body, Class<T> responseType) {
        return client.post(path, body, responseType);
    }

    // ============================================
    // Helpers
    // ============================================

    private void assertLayer(Set<LayerType> allowed, String method) {
        if (!allowed.contains(layer)) {
            String allowedStr = allowed.stream()
                    .map(LayerType::toString)
                    .collect(Collectors.joining(", "));
            throw new IllegalStateException(String.format(
                    "%s() is not available on %s layer. Available on: %s",
                    method, layer, allowedStr
            ));
        }
    }

    // ============================================
    // Factory method
    // ============================================

    /**
     * Create a MetagraphClient for a specific layer.
     *
     * @param baseUrl Node URL
     * @param layer Layer type
     * @return Configured MetagraphClient
     */
    public static MetagraphClient create(String baseUrl, LayerType layer) {
        return new MetagraphClient(baseUrl, layer);
    }
}
