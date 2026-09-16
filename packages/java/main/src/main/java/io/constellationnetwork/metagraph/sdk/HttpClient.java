package io.constellationnetwork.metagraph.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Simple HTTP client for network operations using Java 11 HttpClient.
 */
public class HttpClient {

    private static final int DEFAULT_TIMEOUT = 30;
    private static final Gson gson = new Gson();

    private final java.net.http.HttpClient client;
    private final String baseUrl;
    private final int timeout;

    /**
     * Create a new HTTP client.
     *
     * @param baseUrl Base URL for requests
     * @param timeout Request timeout in seconds
     */
    public HttpClient(String baseUrl, int timeout) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.timeout = timeout > 0 ? timeout : DEFAULT_TIMEOUT;
        this.client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(this.timeout))
                .build();
    }

    /**
     * Make a GET request.
     *
     * @param path Request path
     * @param responseType Type of response to deserialize
     * @return Deserialized response
     */
    public <T> T get(String path, Class<T> responseType) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(timeout))
                    .GET()
                    .build();

            return executeRequest(request, responseType);
        } catch (NetworkTypes.NetworkException e) {
            throw e;
        } catch (Exception e) {
            throw new NetworkTypes.NetworkException("Request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Make a POST request.
     *
     * @param path Request path
     * @param body Request body to serialize as JSON
     * @param responseType Type of response to deserialize
     * @return Deserialized response
     */
    public <T> T post(String path, Object body, Class<T> responseType) {
        try {
            String jsonBody = gson.toJson(body);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(timeout))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            return executeRequest(request, responseType);
        } catch (NetworkTypes.NetworkException e) {
            throw e;
        } catch (Exception e) {
            throw new NetworkTypes.NetworkException("Request failed: " + e.getMessage(), e);
        }
    }

    private <T> T executeRequest(HttpRequest request, Class<T> responseType) throws Exception {
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        int statusCode = response.statusCode();
        String body = response.body();

        if (statusCode < 200 || statusCode >= 300) {
            throw new NetworkTypes.NetworkException(
                    "HTTP " + statusCode,
                    statusCode,
                    body
            );
        }

        if (body == null || body.isEmpty()) {
            return null;
        }

        return gson.fromJson(body, responseType);
    }
}
