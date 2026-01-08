package io.constellationnetwork.metagraph.sdk;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class CrossLanguageTest {

    private static List<TestVector> testVectors;
    private static final Gson GSON = new Gson();

    static class TestVector {
        String source;
        String type;
        Map<String, Object> data;
        String canonical_json;
        String utf8_bytes_hex;
        String sha256_hash_hex;
        String signature_hex;
        String public_key_hex;
    }

    @BeforeAll
    static void loadTestVectors() throws IOException {
        Path vectorsPath = Paths.get(System.getProperty("user.dir"), "..", "..", "shared", "test_vectors.json");
        String content = Files.readString(vectorsPath);
        Type listType = new TypeToken<List<TestVector>>(){}.getType();
        testVectors = GSON.fromJson(content, listType);
    }

    @Nested
    @DisplayName("Canonicalization")
    class Canonicalization {

        @Test
        @DisplayName("matches all test vectors")
        void matchesAllVectors() {
            for (TestVector vector : testVectors) {
                String canonical = Canonicalize.canonicalize(vector.data);
                assertEquals(vector.canonical_json, canonical,
                    String.format("Canonicalization mismatch for %s %s", vector.source, vector.type));
            }
        }
    }

    @Nested
    @DisplayName("Binary encoding")
    class BinaryEncoding {

        @Test
        @DisplayName("matches all test vectors")
        void matchesAllVectors() {
            for (TestVector vector : testVectors) {
                boolean isDataUpdate = "TestDataUpdate".equals(vector.type);
                byte[] bytes = Binary.toBytes(vector.data, isDataUpdate);
                String bytesHex = Wallet.bytesToHex(bytes);
                assertEquals(vector.utf8_bytes_hex, bytesHex,
                    String.format("Binary encoding mismatch for %s %s", vector.source, vector.type));
            }
        }
    }

    @Nested
    @DisplayName("Hashing")
    class Hashing {

        @Test
        @DisplayName("matches all test vectors")
        void matchesAllVectors() {
            for (TestVector vector : testVectors) {
                boolean isDataUpdate = "TestDataUpdate".equals(vector.type);
                byte[] bytes = Binary.toBytes(vector.data, isDataUpdate);
                Types.Hash hash = Hash.hashBytes(bytes);
                assertEquals(vector.sha256_hash_hex, hash.getValue(),
                    String.format("Hash mismatch for %s %s", vector.source, vector.type));
            }
        }
    }

    @Nested
    @DisplayName("Signature verification")
    class SignatureVerification {

        @Test
        @DisplayName("verifies all test vectors")
        void verifiesAllVectors() {
            for (TestVector vector : testVectors) {
                boolean isValid = Verify.verifyHash(
                    vector.sha256_hash_hex,
                    vector.signature_hex,
                    vector.public_key_hex
                );
                assertTrue(isValid,
                    String.format("Failed to verify %s %s signature", vector.source, vector.type));
            }
        }

        @Test
        @DisplayName("rejects tampered signatures")
        void rejectsTamperedSignatures() {
            TestVector vector = testVectors.get(0);

            // Tamper with hash
            String tamperedHash = vector.sha256_hash_hex.replace("0", "1");
            boolean isValid = Verify.verifyHash(
                tamperedHash,
                vector.signature_hex,
                vector.public_key_hex
            );
            assertFalse(isValid, "Should reject signature with tampered hash");
        }
    }

    @Nested
    @DisplayName("By source language")
    class BySourceLanguage {

        @Test
        @DisplayName("verifies python vectors")
        void verifiesPythonVectors() {
            verifyLanguageVectors("python");
        }

        @Test
        @DisplayName("verifies javascript vectors")
        void verifiesJavascriptVectors() {
            verifyLanguageVectors("javascript");
        }

        @Test
        @DisplayName("verifies rust vectors")
        void verifiesRustVectors() {
            verifyLanguageVectors("rust");
        }

        @Test
        @DisplayName("verifies go vectors")
        void verifiesGoVectors() {
            verifyLanguageVectors("go");
        }

        private void verifyLanguageVectors(String language) {
            List<TestVector> langVectors = testVectors.stream()
                .filter(v -> language.equals(v.source))
                .collect(Collectors.toList());

            assertFalse(langVectors.isEmpty(), "No test vectors found for " + language);

            for (TestVector vector : langVectors) {
                // Verify hash computation
                boolean isDataUpdate = "TestDataUpdate".equals(vector.type);
                byte[] bytes = Binary.toBytes(vector.data, isDataUpdate);
                Types.Hash hash = Hash.hashBytes(bytes);
                assertEquals(vector.sha256_hash_hex, hash.getValue(),
                    String.format("%s %s hash mismatch", language, vector.type));

                // Verify signature
                boolean isValid = Verify.verifyHash(
                    vector.sha256_hash_hex,
                    vector.signature_hex,
                    vector.public_key_hex
                );
                assertTrue(isValid,
                    String.format("%s %s signature verification failed", language, vector.type));
            }
        }
    }
}
