package io.constellationnetwork.metagraph.sdk;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Network Operations")
class NetworkTest {

    @Nested
    @DisplayName("CurrencyL1Client")
    class CurrencyL1ClientTests {

        @Test
        @DisplayName("requires l1Url in config")
        void requiresL1UrlInConfig() {
            NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder().build();

            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> new CurrencyL1Client(config)
            );

            assertTrue(exception.getMessage().contains("l1Url is required"));
        }

        @Test
        @DisplayName("creates client with valid config")
        void createsClientWithValidConfig() {
            NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
                    .l1Url("http://localhost:9010")
                    .build();

            CurrencyL1Client client = new CurrencyL1Client(config);
            assertNotNull(client);
        }

        @Test
        @DisplayName("accepts optional timeout")
        void acceptsOptionalTimeout() {
            NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
                    .l1Url("http://localhost:9010")
                    .timeout(5)
                    .build();

            CurrencyL1Client client = new CurrencyL1Client(config);
            assertNotNull(client);
        }
    }

    @Nested
    @DisplayName("DataL1Client")
    class DataL1ClientTests {

        @Test
        @DisplayName("requires dataL1Url in config")
        void requiresDataL1UrlInConfig() {
            NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder().build();

            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> new DataL1Client(config)
            );

            assertTrue(exception.getMessage().contains("dataL1Url is required"));
        }

        @Test
        @DisplayName("creates client with valid config")
        void createsClientWithValidConfig() {
            NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
                    .dataL1Url("http://localhost:8080")
                    .build();

            DataL1Client client = new DataL1Client(config);
            assertNotNull(client);
        }

        @Test
        @DisplayName("accepts optional timeout")
        void acceptsOptionalTimeout() {
            NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
                    .dataL1Url("http://localhost:8080")
                    .timeout(10)
                    .build();

            DataL1Client client = new DataL1Client(config);
            assertNotNull(client);
        }
    }

    @Nested
    @DisplayName("NetworkException")
    class NetworkExceptionTests {

        @Test
        @DisplayName("creates error with message only")
        void createsErrorWithMessageOnly() {
            NetworkTypes.NetworkException error = new NetworkTypes.NetworkException("Connection failed");
            assertEquals("Connection failed", error.getMessage());
            assertEquals(0, error.getStatusCode());
            assertNull(error.getResponse());
        }

        @Test
        @DisplayName("creates error with status code")
        void createsErrorWithStatusCode() {
            NetworkTypes.NetworkException error = new NetworkTypes.NetworkException("Not found", 404, null);
            assertTrue(error.toString().contains("Not found"));
            assertTrue(error.toString().contains("404"));
            assertEquals(404, error.getStatusCode());
        }

        @Test
        @DisplayName("creates error with response body")
        void createsErrorWithResponseBody() {
            NetworkTypes.NetworkException error = new NetworkTypes.NetworkException(
                    "Bad request", 400, "{\"error\":\"invalid\"}"
            );
            assertEquals(400, error.getStatusCode());
            assertEquals("{\"error\":\"invalid\"}", error.getResponse());
        }

        @Test
        @DisplayName("is instance of RuntimeException")
        void isInstanceOfRuntimeException() {
            NetworkTypes.NetworkException error = new NetworkTypes.NetworkException("Test");
            assertInstanceOf(RuntimeException.class, error);
        }
    }

    @Nested
    @DisplayName("Combined config")
    class CombinedConfigTests {

        @Test
        @DisplayName("allows both URLs in same config")
        void allowsBothUrlsInSameConfig() {
            NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
                    .l1Url("http://localhost:9010")
                    .dataL1Url("http://localhost:8080")
                    .timeout(30)
                    .build();

            CurrencyL1Client l1Client = new CurrencyL1Client(config);
            DataL1Client dataClient = new DataL1Client(config);

            assertNotNull(l1Client);
            assertNotNull(dataClient);
        }
    }
}
