package io.constellationnetwork.metagraph.sdk;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IntegrationTest {

    @Nested
    @DisplayName("Key generation")
    class KeyGeneration {

        @Test
        @DisplayName("generates valid key pair")
        void generatesValidKeyPair() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();

            assertEquals(64, keyPair.getPrivateKey().length());
            assertEquals(130, keyPair.getPublicKey().length());
            assertTrue(keyPair.getPublicKey().startsWith("04"));
            assertTrue(keyPair.getAddress().startsWith("DAG"));
        }

        @Test
        @DisplayName("derives consistent key pair")
        void derivesConsistentKeyPair() {
            Types.KeyPair original = Wallet.generateKeyPair();
            Types.KeyPair derived = Wallet.keyPairFromPrivateKey(original.getPrivateKey());

            assertEquals(original.getPublicKey(), derived.getPublicKey());
            assertEquals(original.getAddress(), derived.getAddress());
        }

        @Test
        @DisplayName("generates unique key pairs")
        void generatesUniqueKeyPairs() {
            Types.KeyPair keyPair1 = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();

            assertNotEquals(keyPair1.getPrivateKey(), keyPair2.getPrivateKey());
            assertNotEquals(keyPair1.getPublicKey(), keyPair2.getPublicKey());
        }
    }

    @Nested
    @DisplayName("Regular signing")
    class RegularSigning {

        @Test
        @DisplayName("signs and verifies data")
        void signsAndVerifiesData() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test-001");
            data.put("value", 42);

            Types.SignatureProof proof = Sign.sign(data, keyPair.getPrivateKey());

            assertNotNull(proof.getId());
            assertNotNull(proof.getSignature());
            assertEquals(128, proof.getId().length());

            boolean isValid = Verify.verifySignature(data, proof, false);
            assertTrue(isValid);
        }

        @Test
        @DisplayName("creates signed object")
        void createsSignedObject() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test-001");
            data.put("value", 42);

            Types.Signed<Map<String, Object>> signed = SignedObject.createSignedObject(
                data, keyPair.getPrivateKey(), false
            );

            assertEquals(1, signed.getProofs().size());

            Types.VerificationResult result = SignedObject.verify(signed, false);
            assertTrue(result.isValid());
            assertEquals(1, result.getValidProofs().size());
            assertTrue(result.getInvalidProofs().isEmpty());
        }
    }

    @Nested
    @DisplayName("DataUpdate signing")
    class DataUpdateSigning {

        @Test
        @DisplayName("signs and verifies DataUpdate")
        void signsAndVerifiesDataUpdate() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test-update-001");
            data.put("value", 123);

            Types.SignatureProof proof = Sign.signDataUpdate(data, keyPair.getPrivateKey());

            boolean isValid = Verify.verifySignature(data, proof, true);
            assertTrue(isValid);
        }

        @Test
        @DisplayName("verification fails with wrong mode")
        void verificationFailsWithWrongMode() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test");
            data.put("value", 42);

            // Sign as DataUpdate
            Types.SignatureProof proof = Sign.signDataUpdate(data, keyPair.getPrivateKey());

            // Verify as regular (should fail)
            boolean isValid = Verify.verifySignature(data, proof, false);
            assertFalse(isValid);
        }

        @Test
        @DisplayName("produces different signatures than regular")
        void producesDifferentSignaturesThanRegular() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test");
            data.put("value", 42);

            Types.SignatureProof regularProof = Sign.sign(data, keyPair.getPrivateKey());
            Types.SignatureProof dataUpdateProof = Sign.signDataUpdate(data, keyPair.getPrivateKey());

            assertNotEquals(regularProof.getSignature(), dataUpdateProof.getSignature());
        }
    }

    @Nested
    @DisplayName("Multi-signature")
    class MultiSignature {

        @Test
        @DisplayName("adds signature to existing object")
        void addsSignatureToExistingObject() {
            Types.KeyPair keyPair1 = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            Map<String, Object> data = new HashMap<>();
            data.put("id", "multi-sign-test");
            data.put("value", 100);

            Types.Signed<Map<String, Object>> signed = SignedObject.createSignedObject(
                data, keyPair1.getPrivateKey(), false
            );
            Types.Signed<Map<String, Object>> multiSigned = SignedObject.addSignature(
                signed, keyPair2.getPrivateKey(), false
            );

            assertEquals(2, multiSigned.getProofs().size());

            Types.VerificationResult result = SignedObject.verify(multiSigned, false);
            assertTrue(result.isValid());
            assertEquals(2, result.getValidProofs().size());
        }

        @Test
        @DisplayName("batch signs with multiple keys")
        void batchSignsWithMultipleKeys() {
            Types.KeyPair keyPair1 = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            Types.KeyPair keyPair3 = Wallet.generateKeyPair();
            Map<String, Object> data = new HashMap<>();
            data.put("id", "batch-sign-test");

            Types.Signed<Map<String, Object>> signed = SignedObject.batchSign(
                data,
                Arrays.asList(keyPair1.getPrivateKey(), keyPair2.getPrivateKey(), keyPair3.getPrivateKey()),
                false
            );

            assertEquals(3, signed.getProofs().size());

            Types.VerificationResult result = SignedObject.verify(signed, false);
            assertTrue(result.isValid());
            assertEquals(3, result.getValidProofs().size());
        }
    }

    @Nested
    @DisplayName("Tamper detection")
    class TamperDetection {

        @Test
        @DisplayName("detects modified value")
        void detectsModifiedValue() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Map<String, Object> originalData = new HashMap<>();
            originalData.put("id", "test");
            originalData.put("value", 42);

            Types.SignatureProof proof = Sign.sign(originalData, keyPair.getPrivateKey());

            // Tamper with data
            Map<String, Object> tamperedData = new HashMap<>();
            tamperedData.put("id", "test");
            tamperedData.put("value", 999);

            Types.Signed<Map<String, Object>> signed = new Types.Signed<>(
                tamperedData, Arrays.asList(proof)
            );

            Types.VerificationResult result = Verify.verify(signed, false);
            assertFalse(result.isValid());
            assertEquals(1, result.getInvalidProofs().size());
        }
    }

    @Nested
    @DisplayName("Hashing")
    class HashingTests {

        @Test
        @DisplayName("produces consistent hashes")
        void producesConsistentHashes() {
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test");
            data.put("value", 42);

            Types.Hash hash1 = Hash.hash(data);
            Types.Hash hash2 = Hash.hash(data);

            assertEquals(hash1.getValue(), hash2.getValue());
        }

        @Test
        @DisplayName("hash is 32 bytes")
        void hashIs32Bytes() {
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test");

            Types.Hash hash = Hash.hash(data);

            assertEquals(64, hash.getValue().length()); // 32 bytes = 64 hex chars
            assertEquals(32, hash.getBytes().length);
        }

        @Test
        @DisplayName("different data produces different hash")
        void differentDataProducesDifferentHash() {
            Map<String, Object> data1 = new HashMap<>();
            data1.put("id", "test1");

            Map<String, Object> data2 = new HashMap<>();
            data2.put("id", "test2");

            Types.Hash hash1 = Hash.hash(data1);
            Types.Hash hash2 = Hash.hash(data2);

            assertNotEquals(hash1.getValue(), hash2.getValue());
        }
    }

    @Nested
    @DisplayName("Error handling")
    class ErrorHandling {

        @Test
        @DisplayName("rejects invalid private key")
        void rejectsInvalidPrivateKey() {
            assertFalse(Wallet.isValidPrivateKey("invalid"));
            assertFalse(Wallet.isValidPrivateKey("abc123")); // Too short
            assertFalse(Wallet.isValidPrivateKey("zz" + "a".repeat(62))); // Invalid chars

            assertThrows(Types.SdkException.class, () ->
                Wallet.keyPairFromPrivateKey("invalid")
            );
        }

        @Test
        @DisplayName("batch sign requires at least one key")
        void batchSignRequiresAtLeastOneKey() {
            Map<String, Object> data = new HashMap<>();
            data.put("id", "test");

            assertThrows(Types.SdkException.class, () ->
                SignedObject.batchSign(data, Arrays.asList(), false)
            );
        }
    }
}
