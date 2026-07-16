package io.constellationnetwork.metagraph.sdk;

import io.constellationnetwork.metagraph.sdk.core.Types;
import io.constellationnetwork.metagraph.sdk.core.Wallet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CurrencyTransactionTest {

    @Nested
    @DisplayName("Utility functions")
    class UtilityFunctions {

        @Test
        @DisplayName("tokenToUnits converts correctly")
        void tokenToUnitsConvertsCorrectly() {
            assertEquals(10050000000L, CurrencyTransaction.tokenToUnits(100.5));
            assertEquals(1L, CurrencyTransaction.tokenToUnits(0.00000001));
            assertEquals(100000000L, CurrencyTransaction.tokenToUnits(1.0));
        }

        @Test
        @DisplayName("unitsToToken converts correctly")
        void unitsToTokenConvertsCorrectly() {
            assertEquals(100.5, CurrencyTransaction.unitsToToken(10050000000L));
            assertEquals(0.00000001, CurrencyTransaction.unitsToToken(1L));
            assertEquals(1.0, CurrencyTransaction.unitsToToken(100000000L));
        }

        @Test
        @DisplayName("TOKEN_DECIMALS constant is correct")
        void tokenDecimalsConstant() {
            assertEquals(1e-8, CurrencyTypes.TOKEN_DECIMALS);
        }

        @Test
        @DisplayName("isValidDagAddress validates addresses")
        void isValidDagAddressValidatesAddresses() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            assertTrue(CurrencyTransaction.isValidDagAddress(keyPair.getAddress()));
            assertFalse(CurrencyTransaction.isValidDagAddress("invalid"));
            assertFalse(CurrencyTransaction.isValidDagAddress(""));
            assertFalse(CurrencyTransaction.isValidDagAddress("DAG"));
        }
    }

    @Nested
    @DisplayName("Transaction creation")
    class TransactionCreation {

        @Test
        @DisplayName("creates valid currency transaction")
        void createsValidCurrencyTransaction() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();

            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                new CurrencyTypes.TransferParams(keyPair2.getAddress(), 100.5, 0),
                keyPair.getPrivateKey(),
                lastRef
            );

            assertNotNull(tx);
            assertEquals(keyPair.getAddress(), tx.getValue().getSource());
            assertEquals(keyPair2.getAddress(), tx.getValue().getDestination());
            assertEquals(10050000000L, tx.getValue().getAmount()); // 100.5 * 1e8
            assertEquals(0, tx.getValue().getFee());
            assertEquals(lastRef, tx.getValue().getParent());
            assertEquals(1, tx.getProofs().size());
            assertNotNull(tx.getProofs().get(0).getId());
            assertNotNull(tx.getProofs().get(0).getSignature());
        }

        @Test
        @DisplayName("throws on invalid destination")
        void throwsOnInvalidDestination() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            Exception exception = assertThrows(Types.SdkException.class, () -> {
                CurrencyTransaction.createCurrencyTransaction(
                    new CurrencyTypes.TransferParams("invalid", 100, 0),
                    keyPair.getPrivateKey(),
                    lastRef
                );
            });

            assertTrue(exception.getMessage().contains("Invalid destination address"));
        }

        @Test
        @DisplayName("throws on same source and destination")
        void throwsOnSameAddress() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            Exception exception = assertThrows(Types.SdkException.class, () -> {
                CurrencyTransaction.createCurrencyTransaction(
                    new CurrencyTypes.TransferParams(keyPair.getAddress(), 100, 0),
                    keyPair.getPrivateKey(),
                    lastRef
                );
            });

            assertTrue(exception.getMessage().contains("Source and destination addresses cannot be the same"));
        }

        @Test
        @DisplayName("throws on amount too small")
        void throwsOnAmountTooSmall() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            Exception exception = assertThrows(Types.SdkException.class, () -> {
                CurrencyTransaction.createCurrencyTransaction(
                    new CurrencyTypes.TransferParams(keyPair2.getAddress(), 0.000000001, 0),
                    keyPair.getPrivateKey(),
                    lastRef
                );
            });

            assertTrue(exception.getMessage().contains("Transfer amount must be greater than 1e-8"));
        }

        @Test
        @DisplayName("throws on negative fee")
        void throwsOnNegativeFee() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            Exception exception = assertThrows(Types.SdkException.class, () -> {
                CurrencyTransaction.createCurrencyTransaction(
                    new CurrencyTypes.TransferParams(keyPair2.getAddress(), 100, -1),
                    keyPair.getPrivateKey(),
                    lastRef
                );
            });

            assertTrue(exception.getMessage().contains("Fee must be greater than or equal to zero"));
        }
    }

    @Nested
    @DisplayName("Batch transactions")
    class BatchTransactions {

        @Test
        @DisplayName("creates multiple transactions")
        void createsMultipleTransactions() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair recipient1 = Wallet.generateKeyPair();
            Types.KeyPair recipient2 = Wallet.generateKeyPair();
            Types.KeyPair recipient3 = Wallet.generateKeyPair();

            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 5
            );

            List<CurrencyTypes.TransferParams> transfers = Arrays.asList(
                new CurrencyTypes.TransferParams(recipient1.getAddress(), 10, 0),
                new CurrencyTypes.TransferParams(recipient2.getAddress(), 20, 0),
                new CurrencyTypes.TransferParams(recipient3.getAddress(), 30, 0)
            );

            List<CurrencyTypes.CurrencyTransaction> txns = CurrencyTransaction.createCurrencyTransactionBatch(
                transfers,
                keyPair.getPrivateKey(),
                lastRef
            );

            assertEquals(3, txns.size());
            assertEquals(1000000000L, txns.get(0).getValue().getAmount()); // 10 * 1e8
            assertEquals(2000000000L, txns.get(1).getValue().getAmount()); // 20 * 1e8
            assertEquals(3000000000L, txns.get(2).getValue().getAmount()); // 30 * 1e8

            // Check parent references are chained
            assertEquals(lastRef, txns.get(0).getValue().getParent());
            assertEquals(6, txns.get(1).getValue().getParent().getOrdinal());
            assertEquals(7, txns.get(2).getValue().getParent().getOrdinal());
        }
    }

    @Nested
    @DisplayName("Transaction verification")
    class TransactionVerification {

        @Test
        @DisplayName("verifies correct signatures")
        void verifiesCorrectSignatures() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                new CurrencyTypes.TransferParams(keyPair2.getAddress(), 100, 0),
                keyPair.getPrivateKey(),
                lastRef
            );

            Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);

            assertTrue(result.isValid());
            assertEquals(1, result.getValidProofs().size());
            assertEquals(0, result.getInvalidProofs().size());
        }

        @Test
        @DisplayName("detects invalid signatures")
        void detectsInvalidSignatures() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                new CurrencyTypes.TransferParams(keyPair2.getAddress(), 100, 0),
                keyPair.getPrivateKey(),
                lastRef
            );

            // Replace with invalid proof
            Types.SignatureProof invalidProof = new Types.SignatureProof(
                tx.getProofs().get(0).getId(),
                "invalid_signature"
            );

            CurrencyTypes.CurrencyTransaction invalidTx = new CurrencyTypes.CurrencyTransaction(
                tx.getValue(),
                Arrays.asList(invalidProof)
            );

            Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(invalidTx);

            assertFalse(result.isValid());
            assertEquals(0, result.getValidProofs().size());
            assertEquals(1, result.getInvalidProofs().size());
        }
    }

    @Nested
    @DisplayName("Multi-signature support")
    class MultiSignatureSupport {

        @Test
        @DisplayName("adds additional signature")
        void addsAdditionalSignature() {
            Types.KeyPair keyPair1 = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            Types.KeyPair recipient = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            // Create transaction with first signature
            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                new CurrencyTypes.TransferParams(recipient.getAddress(), 100, 0),
                keyPair1.getPrivateKey(),
                lastRef
            );

            assertEquals(1, tx.getProofs().size());

            // Add second signature
            tx = CurrencyTransaction.signCurrencyTransaction(tx, keyPair2.getPrivateKey());

            assertEquals(2, tx.getProofs().size());

            // Verify both signatures
            Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);

            assertTrue(result.isValid());
            assertEquals(2, result.getValidProofs().size());
            assertEquals(0, result.getInvalidProofs().size());
        }
    }

    @Nested
    @DisplayName("Transaction hashing")
    class TransactionHashing {

        @Test
        @DisplayName("produces consistent hashes")
        void producesConsistentHashes() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                new CurrencyTypes.TransferParams(keyPair2.getAddress(), 100, 0),
                keyPair.getPrivateKey(),
                lastRef
            );

            Types.Hash hash1 = CurrencyTransaction.hashCurrencyTransaction(tx);
            Types.Hash hash2 = CurrencyTransaction.hashCurrencyTransaction(tx);

            assertEquals(hash1.getValue(), hash2.getValue());
            assertEquals(64, hash1.getValue().length()); // SHA-256 hex string
            assertEquals(32, hash1.getBytes().length); // 32 bytes
        }

        @Test
        @DisplayName("creates correct transaction reference")
        void createsCorrectTransactionReference() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                new CurrencyTypes.TransferParams(keyPair2.getAddress(), 100, 0),
                keyPair.getPrivateKey(),
                lastRef
            );

            CurrencyTypes.TransactionReference ref = CurrencyTransaction.getTransactionReference(tx, 1);

            assertEquals(1, ref.getOrdinal());
            assertEquals(64, ref.getHash().length());
        }

        @Test
        @DisplayName("encodes transaction to string")
        void encodesTransactionToString() {
            Types.KeyPair keyPair = Wallet.generateKeyPair();
            Types.KeyPair keyPair2 = Wallet.generateKeyPair();
            CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
                "a".repeat(64), 0
            );

            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                new CurrencyTypes.TransferParams(keyPair2.getAddress(), 100, 0),
                keyPair.getPrivateKey(),
                lastRef
            );

            String encoded = CurrencyTransaction.encodeCurrencyTransaction(tx);

            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
        }
    }
}
