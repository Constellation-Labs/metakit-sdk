package io.constellationnetwork.metagraph.sdk;

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
    static ECDomainParameters getEcParams() {
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
     * @param publicKey Public key in hex format (with or without 04 prefix)
     * @return DAG address
     */
    public static String getAddress(String publicKey) {
        String normalizedKey = normalizePublicKey(publicKey);
        byte[] publicKeyBytes = hexToBytes(normalizedKey);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(publicKeyBytes);
            String encoded = base58Encode(hash);
            return "DAG" + encoded;
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
    static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * Convert hex string to bytes.
     */
    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                  + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }
}
