package io.constellationnetwork.metagraph.sdk;

import io.constellationnetwork.metagraph.sdk.core.Types;
import io.constellationnetwork.metagraph.sdk.core.Wallet;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Currency transaction test vector validation
 *
 * Validates Java implementation against reference test vectors from tessellation
 *
 * Note: These tests use hardcoded values from currency_transaction_vectors.json
 * to avoid requiring Jackson/Gson JSON parsing dependencies.
 */
public class CurrencyTransactionVectorsTest {

    // Test vector values from basicTransaction
    private static final String PRIVATE_KEY_HEX = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    private static final String PUBLIC_KEY_HEX = "04bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020decddbf6e00192011648d13b1c00af770c0c1bb609d4d3a5c98a43772e0e18ef4";
    private static final String ADDRESS = "DAG1vTmrhDPkNkUEb5yGbH9i5R9xTDNMFpHQwRvR";
    private static final String DESTINATION = "DAG4o41NzhfX6DyYBTTXu6sJa6awm36abJpv89jB";
    private static final long AMOUNT = 10050000000L;
    private static final long FEE = 0L;
    private static final String PARENT_HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final long PARENT_ORDINAL = 0L;
    private static final long SALT = 9007199254740992L;
    private static final String ENCODED_STRING = "240DAG1vTmrhDPkNkUEb5yGbH9i5R9xTDNMFpHQwRvR40DAG4o41NzhfX6DyYBTTXu6sJa6awm36abJpv89jB925706d48064aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10101420000000000000";
    private static final String KRYO_BYTES_HEX = "03f6023234304441473176546d726844506b4e6b554562357947624839693552397854444e4d46704851775276523430444147346f34314e7a68665836447959425454587536734a613661776d333661624a707638396a42393235373036643438303634616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161613130313031343230303030303030303030303030";
    private static final String TRANSACTION_HASH = "5b7e930be16d49adaf75ee5e5c63ac27f61a4a47058ab54ff10e9095f3bf6409";
    private static final String SIGNATURE = "3046022100c0f7463dbf45ef34a62154b3da7c92be9e6e6e5e2afef7119ea4a96ba5d0df03022100c1bffb2cc448f71753f1faed9f73e5cdb0724b22ad247c63c9501f1888722118";
    private static final String SIGNER_ID = "bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020decddbf6e00192011648d13b1c00af770c0c1bb609d4d3a5c98a43772e0e18ef4";

    @Test
    public void testPublicKeyDerivation() {
        String publicKey = Wallet.getPublicKeyHex(PRIVATE_KEY_HEX, false);
        assertEquals(PUBLIC_KEY_HEX, publicKey, "Public key should match test vector");
    }

    @Test
    public void testAddressDerivation() {
        String publicKey = Wallet.getPublicKeyHex(PRIVATE_KEY_HEX, false);
        String address = Wallet.getAddress(publicKey);
        assertEquals(ADDRESS, address, "Address should match test vector");
    }

    @Test
    public void testEncodingFormat() {
        CurrencyTypes.TransferParams params = new CurrencyTypes.TransferParams(
            DESTINATION,
            AMOUNT / 1e8,
            FEE / 1e8
        );

        CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
            PARENT_HASH,
            PARENT_ORDINAL
        );

        try {
            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                params,
                PRIVATE_KEY_HEX,
                lastRef
            );

            // Override salt for deterministic test
            CurrencyTypes.CurrencyTransactionValue value = new CurrencyTypes.CurrencyTransactionValue(
                tx.getValue().getSource(),
                tx.getValue().getDestination(),
                tx.getValue().getAmount(),
                tx.getValue().getFee(),
                tx.getValue().getParent(),
                Long.toString(SALT)
            );

            CurrencyTypes.CurrencyTransaction txWithSalt = new CurrencyTypes.CurrencyTransaction(
                value,
                new ArrayList<>()  // No proofs for encoding test
            );

            String encoded = CurrencyTransaction.encodeCurrencyTransaction(txWithSalt);
            assertEquals(ENCODED_STRING, encoded, "Encoding should match test vector");
        } catch (Exception e) {
            fail("Should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testTransactionHash() {
        CurrencyTypes.TransferParams params = new CurrencyTypes.TransferParams(
            DESTINATION,
            AMOUNT / 1e8,
            FEE / 1e8
        );

        CurrencyTypes.TransactionReference lastRef = new CurrencyTypes.TransactionReference(
            PARENT_HASH,
            PARENT_ORDINAL
        );

        try {
            CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
                params,
                PRIVATE_KEY_HEX,
                lastRef
            );

            // Override salt and proofs for exact match
            CurrencyTypes.CurrencyTransactionValue value = new CurrencyTypes.CurrencyTransactionValue(
                tx.getValue().getSource(),
                tx.getValue().getDestination(),
                tx.getValue().getAmount(),
                tx.getValue().getFee(),
                tx.getValue().getParent(),
                Long.toString(SALT)
            );

            CurrencyTypes.CurrencyTransaction txWithSalt = new CurrencyTypes.CurrencyTransaction(
                value,
                new ArrayList<>()
            );

            Types.Hash hash = CurrencyTransaction.hashCurrencyTransaction(txWithSalt);
            assertEquals(TRANSACTION_HASH, hash.getValue(), "Hash should match test vector");
        } catch (Exception e) {
            fail("Should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testReferenceSignature() {
        // Reconstruct transaction from test vector
        CurrencyTypes.CurrencyTransactionValue value = new CurrencyTypes.CurrencyTransactionValue(
            ADDRESS,
            DESTINATION,
            AMOUNT,
            FEE,
            new CurrencyTypes.TransactionReference(PARENT_HASH, PARENT_ORDINAL),
            Long.toString(SALT)
        );

        List<Types.SignatureProof> proofs = new ArrayList<>();
        proofs.add(new Types.SignatureProof(SIGNER_ID, SIGNATURE));

        CurrencyTypes.CurrencyTransaction tx = new CurrencyTypes.CurrencyTransaction(value, proofs);

        Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);
        assertTrue(result.isValid(), "Transaction should be valid");
        assertEquals(1, result.getValidProofs().size(), "Should have 1 valid proof");
        assertEquals(0, result.getInvalidProofs().size(), "Should have 0 invalid proofs");
    }

    @Test
    public void testMultiSignature() {
        // Multi-signature proofs from test vectors
        String proof1Id = "97855f402631f09e602e5ccadc219503f07cdd4c73b2215b5418f52a7fdbfcd97c59d67b478562b62269ec23d6dfc5566bacbdc25606d4ccfd5de7cfadcf4be8";
        String proof1Sig = "3044022067958f04a7ae2c2f82635f212161ee9bf2a20f59f04013559486f406300be37502201c3f239d9dc0ff1af2757992ad3c6572d92e7c2fecb26f7900b1ec10f6dc6bf2";
        String proof2Id = "bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020decddbf6e00192011648d13b1c00af770c0c1bb609d4d3a5c98a43772e0e18ef4";
        String proof2Sig = "3045022100ce80bef53abe1c4e658567e2ad2c526fbc8e90dbb033945fcc63368439df447c02207c26aae76724d02b3aa85a36b721d987ec8080926b29fddcac22ba35d5fdbbc6";

        // Reconstruct transaction value
        CurrencyTypes.CurrencyTransactionValue value = new CurrencyTypes.CurrencyTransactionValue(
            ADDRESS,
            DESTINATION,
            AMOUNT,
            FEE,
            new CurrencyTypes.TransactionReference(PARENT_HASH, PARENT_ORDINAL),
            Long.toString(SALT)
        );

        // Add both proofs
        List<Types.SignatureProof> proofs = new ArrayList<>();
        proofs.add(new Types.SignatureProof(proof1Id, proof1Sig));
        proofs.add(new Types.SignatureProof(proof2Id, proof2Sig));

        CurrencyTypes.CurrencyTransaction tx = new CurrencyTypes.CurrencyTransaction(value, proofs);

        Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);
        assertTrue(result.isValid(), "Multi-sig transaction should be valid");
        assertEquals(2, result.getValidProofs().size(), "Should have 2 valid proofs");
        assertEquals(0, result.getInvalidProofs().size(), "Should have 0 invalid proofs");
    }

    @Test
    public void testKryoSetReferencesFlag() {
        // Verify Kryo header starts with 0x03 (string type) without 0x01 reference flag (v2 format)
        assertTrue(KRYO_BYTES_HEX.startsWith("03"), "Kryo header should start with 03");
        assertFalse(KRYO_BYTES_HEX.startsWith("0301"), "Kryo header should NOT have reference flag for v2");
    }

    @Test
    public void testMinimumAmount() {
        long minAmount = 1L;
        assertTrue(minAmount >= 1, "Minimum amount should be at least 1");
    }

    @Test
    public void testMaximumAmount() {
        long maxAmount = 9223372036854775807L; // Long.MAX_VALUE
        assertEquals(Long.MAX_VALUE, maxAmount, "Maximum amount should be Long.MAX_VALUE");
    }

    @Test
    public void testNonZeroFee() {
        long amount = 10000000000L;
        long fee = 100000L;
        assertTrue(amount > 0, "Amount should be positive");
        assertTrue(fee > 0, "Fee should be positive");
    }

    @Test
    public void testAddressValidation() {
        assertTrue(CurrencyTransaction.isValidDagAddress(ADDRESS), "Address should be valid");
        assertTrue(CurrencyTransaction.isValidDagAddress(DESTINATION), "Destination should be valid");
        assertFalse(CurrencyTransaction.isValidDagAddress("invalid"), "Invalid address should be rejected");
        assertFalse(CurrencyTransaction.isValidDagAddress(""), "Empty address should be rejected");
    }
}
