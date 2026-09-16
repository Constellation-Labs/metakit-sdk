package io.constellationnetwork.metagraph.sdk.core;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Wallet and key management utilities.
 */
public final class Wallet {

    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final ECDomainParameters EC_PARAMS;

    static {
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        EC_PARAMS = new ECDomainParameters(
            params.getCurve(),
            params.getG(),
            params.getN(),
            params.getH()
        );
    }

    private Wallet() {
        // Utility class
    }

    /**
     * Get the EC domain parameters for secp256k1.
     */
    public static ECDomainParameters getEcParams() {
        return EC_PARAMS;
    }

    /**
     * Generate a new random key pair.
     *
     * @return New key pair with private key, public key, and DAG address
     */
    public static Types.KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyBytes = new byte[32];
        random.nextBytes(privateKeyBytes);

        String privateKey = bytesToHex(privateKeyBytes);
        String publicKey = getPublicKeyHex(privateKey, false);
        String address = getAddress(publicKey);

        return new Types.KeyPair(privateKey, publicKey, address);
    }

    /**
     * Derive a key pair from an existing private key.
     *
     * @param privateKey Private key in hex format (64 characters)
     * @return Key pair derived from the private key
     * @throws Types.SdkException if the private key is invalid
     */
    public static Types.KeyPair keyPairFromPrivateKey(String privateKey) {
        if (!isValidPrivateKey(privateKey)) {
            throw new Types.SdkException("Invalid private key format");
        }

        String publicKey = getPublicKeyHex(privateKey, false);
        String address = getAddress(publicKey);

        return new Types.KeyPair(privateKey, publicKey, address);
    }

    /**
     * Get the public key hex from a private key.
     *
     * @param privateKey Private key in hex format
     * @param compressed If true, returns compressed public key (33 bytes)
     * @return Public key in hex format
     */
    public static String getPublicKeyHex(String privateKey, boolean compressed) {
        byte[] privateKeyBytes = hexToBytes(privateKey);
        BigInteger privateKeyInt = new BigInteger(1, privateKeyBytes);
        ECPoint publicPoint = EC_PARAMS.getG().multiply(privateKeyInt);
        byte[] publicKeyBytes = publicPoint.getEncoded(compressed);
        return bytesToHex(publicKeyBytes);
    }

    /**
     * Get the public key ID (without 04 prefix) from a private key.
     *
     * @param privateKey Private key in hex format
     * @return Public key ID (128 characters, no 04 prefix)
     */
    public static String getPublicKeyId(String privateKey) {
        String publicKey = getPublicKeyHex(privateKey, false);
        return normalizePublicKeyToId(publicKey);
    }

    /**
     * Get DAG address from a public key.
     *
     * Uses Constellation's address derivation:
     * 1. Normalize public key to include 04 prefix
     * 2. Prepend PKCS prefix (X.509 DER encoding header)
     * 3. SHA-256 hash
     * 4. Base58 encode
     * 5. Take last 36 characters
     * 6. Calculate parity digit (sum of numeric characters mod 9)
     * 7. Result: DAG + parity + last36
     *
     * @param publicKey Public key in hex format (with or without 04 prefix)
     * @return DAG address (40 characters: DAG + parity + 36 chars)
     */
    public static String getAddress(String publicKey) {
        // PKCS prefix for X.509 DER encoding (secp256k1)
        final String PKCS_PREFIX = "3056301006072a8648ce3d020106052b8104000a034200";

        // Normalize public key to include 04 prefix
        String normalizedKey = normalizePublicKey(publicKey);

        // Prepend PKCS prefix
        String pkcsEncoded = PKCS_PREFIX + normalizedKey;

        try {
            // SHA-256 hash
            byte[] pkcsBytes = hexToBytes(pkcsEncoded);
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(pkcsBytes);

            // Base58 encode
            String encoded = base58Encode(hash);

            // Take last 36 characters
            String last36 = encoded.length() > 36
                    ? encoded.substring(encoded.length() - 36)
                    : encoded;

            // Calculate parity digit (sum of numeric characters mod 9)
            int digitSum = 0;
            for (char c : last36.toCharArray()) {
                if (Character.isDigit(c)) {
                    digitSum += Character.getNumericValue(c);
                }
            }
            int parity = digitSum % 9;

            // Return with DAG prefix, parity, and last36
            return "DAG" + parity + last36;
        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Validate that a private key is correctly formatted.
     *
     * @param privateKey Private key to validate
     * @return true if valid hex string of correct length
     */
    public static boolean isValidPrivateKey(String privateKey) {
        if (privateKey == null || privateKey.length() != 64) {
            return false;
        }
        return privateKey.chars().allMatch(c ->
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
        );
    }

    /**
     * Validate that a public key is correctly formatted.
     *
     * @param publicKey Public key to validate
     * @return true if valid hex string of correct length
     */
    public static boolean isValidPublicKey(String publicKey) {
        if (publicKey == null) {
            return false;
        }
        // With 04 prefix: 130 chars, without: 128 chars
        if (publicKey.length() != 128 && publicKey.length() != 130) {
            return false;
        }
        return publicKey.chars().allMatch(c ->
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
        );
    }

    /**
     * Normalize public key to include 04 prefix.
     */
    public static String normalizePublicKey(String publicKey) {
        if (publicKey.length() == 128) {
            return "04" + publicKey;
        }
        return publicKey;
    }

    /**
     * Normalize public key to ID format (without 04 prefix).
     */
    public static String normalizePublicKeyToId(String publicKey) {
        if (publicKey.length() == 130 && publicKey.startsWith("04")) {
            return publicKey.substring(2);
        }
        return publicKey;
    }

    /**
     * Base58 encode bytes using Bitcoin/Constellation alphabet.
     */
    static String base58Encode(byte[] data) {
        if (data.length == 0) {
            return "";
        }

        // Count leading zeros
        int leadingZeros = 0;
        for (byte b : data) {
            if (b == 0) {
                leadingZeros++;
            } else {
                break;
            }
        }

        // Convert to big integer and encode
        BigInteger num = new BigInteger(1, data);
        StringBuilder result = new StringBuilder();

        while (num.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divmod = num.divideAndRemainder(BigInteger.valueOf(58));
            result.insert(0, BASE58_ALPHABET.charAt(divmod[1].intValue()));
            num = divmod[0];
        }

        // Add '1' for each leading zero byte
        for (int i = 0; i < leadingZeros; i++) {
            result.insert(0, '1');
        }

        return result.toString();
    }

    /**
     * Convert bytes to hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * Convert hex string to bytes.
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                  + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }
}
