package io.constellationnetwork.metagraph.sdk;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Network Operations")
class NetworkTest {

    @Nested
    @DisplayName("MetagraphClient")
    class MetagraphClientTests {

        @Test
        @DisplayName("requires baseUrl in config")
        void requiresBaseUrlInConfig() {
            MetagraphClient.Config config = new MetagraphClient.Config.Builder()
                    .layer(MetagraphClient.LayerType.DL1)
                    .build();

            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> new MetagraphClient(config)
            );

            assertTrue(exception.getMessage().contains("baseUrl is required"));
        }

        @Test
        @DisplayName("requires layer in config")
        void requiresLayerInConfig() {
            MetagraphClient.Config config = new MetagraphClient.Config.Builder()
                    .baseUrl("http://localhost:9400")
                    .build();

            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> new MetagraphClient(config)
            );

            assertTrue(exception.getMessage().contains("layer is required"));
        }

        @Test
        @DisplayName("creates client for DL1")
        void createsClientForDL1() {
            MetagraphClient client = new MetagraphClient("http://localhost:9400", MetagraphClient.LayerType.DL1);
            assertNotNull(client);
            assertEquals(MetagraphClient.LayerType.DL1, client.getLayer());
        }

        @Test
        @DisplayName("creates client for CL1")
        void createsClientForCL1() {
            MetagraphClient client = new MetagraphClient("http://localhost:9300", MetagraphClient.LayerType.CL1);
            assertNotNull(client);
            assertEquals(MetagraphClient.LayerType.CL1, client.getLayer());
        }

        @Test
        @DisplayName("creates client for ML0")
        void createsClientForML0() {
            MetagraphClient client = new MetagraphClient("http://localhost:9200", MetagraphClient.LayerType.ML0);
            assertNotNull(client);
            assertEquals(MetagraphClient.LayerType.ML0, client.getLayer());
        }

        @Test
        @DisplayName("accepts optional timeout via config")
        void acceptsOptionalTimeout() {
            MetagraphClient.Config config = new MetagraphClient.Config.Builder()
                    .baseUrl("http://localhost:9400")
                    .layer(MetagraphClient.LayerType.DL1)
                    .timeout(5000)
                    .build();

            MetagraphClient client = new MetagraphClient(config);
            assertNotNull(client);
        }
    }

    @Nested
    @DisplayName("LayerType")
    class LayerTypeTests {

        @Test
        @DisplayName("has correct string representation")
        void hasCorrectStringRepresentation() {
            assertEquals("ML0", MetagraphClient.LayerType.ML0.toString());
            assertEquals("CL1", MetagraphClient.LayerType.CL1.toString());
            assertEquals("DL1", MetagraphClient.LayerType.DL1.toString());
        }

        @Test
        @DisplayName("has correct value")
        void hasCorrectValue() {
            assertEquals("ml0", MetagraphClient.LayerType.ML0.getValue());
            assertEquals("cl1", MetagraphClient.LayerType.CL1.getValue());
            assertEquals("dl1", MetagraphClient.LayerType.DL1.getValue());
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
    @DisplayName("Combined usage")
    class CombinedUsageTests {

        @Test
        @DisplayName("creates multiple clients for different layers")
        void createsMultipleClientsForDifferentLayers() {
            MetagraphClient cl1 = new MetagraphClient("http://localhost:9300", MetagraphClient.LayerType.CL1);
            MetagraphClient dl1 = new MetagraphClient("http://localhost:9400", MetagraphClient.LayerType.DL1);
            MetagraphClient ml0 = new MetagraphClient("http://localhost:9200", MetagraphClient.LayerType.ML0);

            assertNotNull(cl1);
            assertNotNull(dl1);
            assertNotNull(ml0);
            assertEquals(MetagraphClient.LayerType.CL1, cl1.getLayer());
            assertEquals(MetagraphClient.LayerType.DL1, dl1.getLayer());
            assertEquals(MetagraphClient.LayerType.ML0, ml0.getLayer());
        }
    }
}
