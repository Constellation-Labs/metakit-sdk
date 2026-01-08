package io.constellationnetwork.metagraph.sdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hashing utilities for the Constellation signature protocol.
 */
public final class Hash {

    private Hash() {
        // Utility class
    }

    /**
     * Compute SHA-256 hash of canonical JSON data.
     *
     * @param data Object to hash
     * @return Hash result with hex string and raw bytes
     */
    public static Types.Hash hash(Object data) {
        byte[] bytes = Binary.toBytes(data, false);
        return hashBytes(bytes);
    }

    /**
     * Compute SHA-256 hash of raw bytes.
     *
     * @param bytes Input bytes
     * @return Hash result with hex string and raw bytes
     */
    public static Types.Hash hashBytes(byte[] bytes) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = sha256.digest(bytes);
            String hashHex = Wallet.bytesToHex(hashBytes);
            return new Types.Hash(hashHex, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Compute SHA-256 hash of data with optional DataUpdate encoding.
     *
     * @param data Object to hash
     * @param isDataUpdate Whether to apply DataUpdate encoding
     * @return Hash result
     */
    public static Types.Hash hashData(Object data, boolean isDataUpdate) {
        byte[] bytes = Binary.toBytes(data, isDataUpdate);
        return hashBytes(bytes);
    }

    /**
     * Compute the full signing digest according to Constellation protocol.
     *
     * <p>Protocol:
     * <ol>
     *   <li>Serialize data to binary (with optional DataUpdate prefix)</li>
     *   <li>Compute SHA-256 hash</li>
     *   <li>Convert hash to hex string</li>
     *   <li>Treat hex string as UTF-8 bytes (NOT hex decode)</li>
     *   <li>Compute SHA-512 of those bytes</li>
     *   <li>Truncate to 32 bytes for secp256k1 signing</li>
     * </ol>
     *
     * @param data Object to compute digest for
     * @param isDataUpdate Whether to apply DataUpdate encoding
     * @return 32-byte digest ready for ECDSA signing
     */
    public static byte[] computeDigest(Object data, boolean isDataUpdate) {
        // Step 1: Serialize to binary
        byte[] dataBytes = Binary.toBytes(data, isDataUpdate);

        // Step 2: SHA-256 hash
        Types.Hash sha256Hash = hashBytes(dataBytes);

        // Step 3-4: Hex string as UTF-8 bytes (critical: NOT hex decode)
        byte[] hexAsUtf8 = sha256Hash.getValue().getBytes(StandardCharsets.UTF_8);

        // Step 5-6: SHA-512 and truncate to 32 bytes
        return computeDigestFromHash(sha256Hash.getValue());
    }

    /**
     * Compute signing digest from a SHA-256 hash hex string.
     *
     * @param hashHex SHA-256 hash as 64-character hex string
     * @return 32-byte digest
     */
    public static byte[] computeDigestFromHash(String hashHex) {
        try {
            // Treat hex as UTF-8 bytes
            byte[] hexAsUtf8 = hashHex.getBytes(StandardCharsets.UTF_8);

            // SHA-512 hash
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] sha512Hash = sha512.digest(hexAsUtf8);

            // Truncate to 32 bytes
            byte[] digest = new byte[32];
            System.arraycopy(sha512Hash, 0, digest, 0, 32);
            return digest;
        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-512 not available", e);
        }
    }
}
