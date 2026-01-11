package io.constellationnetwork.metagraph.sdk;

/**
 * Client for interacting with Data L1 nodes (metagraphs).
 *
 * <p>Example usage:
 * <pre>{@code
 * NetworkConfig config = new NetworkConfig.Builder()
 *     .dataL1Url("http://localhost:8080")
 *     .build();
 *
 * DataL1Client client = new DataL1Client(config);
 *
 * // Estimate fee for data submission
 * EstimateFeeResponse feeInfo = client.estimateFee(signedData);
 *
 * // Submit data
 * PostDataResponse result = client.postData(signedData);
 * }</pre>
 */
public class DataL1Client {

    private final HttpClient client;

    /**
     * Create a new DataL1Client.
     *
     * @param config Network configuration with dataL1Url
     * @throws IllegalArgumentException if dataL1Url is not provided
     */
    public DataL1Client(NetworkTypes.NetworkConfig config) {
        if (config.getDataL1Url() == null || config.getDataL1Url().isEmpty()) {
            throw new IllegalArgumentException("dataL1Url is required for DataL1Client");
        }
        this.client = new HttpClient(config.getDataL1Url(), config.getTimeout());
    }

    /**
     * Estimate the fee for submitting data.
     *
     * <p>Some metagraphs charge fees for data submissions.
     * Call this before postData to know the required fee.
     *
     * @param data Signed data object to estimate fee for
     * @return Fee estimate with amount and destination address
     */
    public <T> NetworkTypes.EstimateFeeResponse estimateFee(Types.Signed<T> data) {
        return client.post(
                "/data/estimate-fee",
                data,
                NetworkTypes.EstimateFeeResponse.class
        );
    }

    /**
     * Submit signed data to the Data L1 node.
     *
     * @param data Signed data object to submit
     * @return Response containing the data hash
     */
    public <T> NetworkTypes.PostDataResponse postData(Types.Signed<T> data) {
        return client.post(
                "/data",
                data,
                NetworkTypes.PostDataResponse.class
        );
    }

    /**
     * Check the health/availability of the Data L1 node.
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
