package io.constellationnetwork.metagraph.sdk;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * ECDSA signing using secp256k1 curve.
 */
public final class Sign {

    private Sign() {
        // Utility class
    }

    /**
     * Sign data using the regular Constellation protocol (non-DataUpdate).
     *
     * <p>Protocol:
     * <ol>
     *   <li>Canonicalize JSON (RFC 8785)</li>
     *   <li>SHA-256 hash the canonical JSON string</li>
     *   <li>Treat hash hex as UTF-8 bytes</li>
     *   <li>SHA-512 hash, truncate to 32 bytes</li>
     *   <li>Sign with ECDSA secp256k1</li>
     * </ol>
     *
     * @param data Object to sign
     * @param privateKey Private key in hex format
     * @return SignatureProof with public key ID and signature
     */
    public static Types.SignatureProof sign(Object data, String privateKey) {
        // Step 1: Canonicalize JSON
        String canonicalJson = Canonicalize.canonicalize(data);

        // Step 2: SHA-256 hash
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] utf8Bytes = canonicalJson.getBytes(StandardCharsets.UTF_8);
            byte[] hashBytes = sha256.digest(utf8Bytes);
            String hashHex = Wallet.bytesToHex(hashBytes);

            // Step 3-5: Sign the hash
            String signature = signHash(hashHex, privateKey);

            // Get public key ID
            String publicKeyId = Wallet.getPublicKeyId(privateKey);

            return new Types.SignatureProof(publicKeyId, signature);
        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Sign data as a DataUpdate (with Constellation prefix).
     *
     * <p>Protocol:
     * <ol>
     *   <li>Canonicalize JSON (RFC 8785)</li>
     *   <li>Base64 encode the canonical JSON</li>
     *   <li>Prepend Constellation prefix</li>
     *   <li>SHA-256 hash the prefixed message</li>
     *   <li>Sign the hash</li>
     * </ol>
     *
     * @param data Object to sign
     * @param privateKey Private key in hex format
     * @return SignatureProof
     */
    public static Types.SignatureProof signDataUpdate(Object data, String privateKey) {
        // Step 1: Canonicalize JSON
        String canonicalJson = Canonicalize.canonicalize(data);

        // Step 2: Base64 encode
        String base64String = Base64.getEncoder().encodeToString(
            canonicalJson.getBytes(StandardCharsets.UTF_8)
        );

        // Step 3: Create prefixed message
        String message = Types.CONSTELLATION_PREFIX + base64String.length() + "\n" + base64String;

        // Step 4: SHA-256 hash
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] hashBytes = sha256.digest(messageBytes);
            String hashHex = Wallet.bytesToHex(hashBytes);

            // Step 5: Sign the hash
            String signature = signHash(hashHex, privateKey);

            // Get public key ID
            String publicKeyId = Wallet.getPublicKeyId(privateKey);

            return new Types.SignatureProof(publicKeyId, signature);
        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Sign a pre-computed SHA-256 hash.
     *
     * <p>Protocol:
     * <ol>
     *   <li>Treat hashHex as UTF-8 bytes (64 ASCII characters = 64 bytes)</li>
     *   <li>SHA-512 hash those bytes (produces 64 bytes)</li>
     *   <li>Truncate to first 32 bytes (for secp256k1 curve order)</li>
     *   <li>Sign with ECDSA secp256k1</li>
     *   <li>Return DER-encoded signature</li>
     * </ol>
     *
     * @param hashHex SHA-256 hash as 64-character hex string
     * @param privateKey Private key in hex format
     * @return DER-encoded signature in hex format
     */
    public static String signHash(String hashHex, String privateKey) {
        try {
            // Step 1: Treat hex as UTF-8 bytes
            byte[] hashBytesForSigning = hashHex.getBytes(StandardCharsets.UTF_8);

            // Step 2: SHA-512 hash
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] sha512Hash = sha512.digest(hashBytesForSigning);

            // Step 3: Truncate to 32 bytes
            byte[] truncatedHash = new byte[32];
            System.arraycopy(sha512Hash, 0, truncatedHash, 0, 32);

            // Step 4: Sign with ECDSA
            byte[] privateKeyBytes = Wallet.hexToBytes(privateKey);
            BigInteger privateKeyInt = new BigInteger(1, privateKeyBytes);
            ECDomainParameters ecParams = Wallet.getEcParams();
            ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(privateKeyInt, ecParams);

            ECDSASigner signer = new ECDSASigner();
            signer.init(true, privKeyParams);
            BigInteger[] signature = signer.generateSignature(truncatedHash);

            // Normalize S to low-S form (BIP 62/146)
            BigInteger r = signature[0];
            BigInteger s = signature[1];
            BigInteger halfN = ecParams.getN().shiftRight(1);
            if (s.compareTo(halfN) > 0) {
                s = ecParams.getN().subtract(s);
            }

            // Step 5: Encode to DER
            byte[] derSignature = encodeToDER(r, s);
            return Wallet.bytesToHex(derSignature);

        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-512 not available", e);
        }
    }

    /**
     * Encode ECDSA signature (r, s) to DER format.
     */
    private static byte[] encodeToDER(BigInteger r, BigInteger s) {
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        // DER format: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
        int rLen = rBytes.length;
        int sLen = sBytes.length;
        int totalLen = 2 + rLen + 2 + sLen;

        byte[] der = new byte[2 + totalLen];
        int offset = 0;

        der[offset++] = 0x30;
        der[offset++] = (byte) totalLen;

        der[offset++] = 0x02;
        der[offset++] = (byte) rLen;
        System.arraycopy(rBytes, 0, der, offset, rLen);
        offset += rLen;

        der[offset++] = 0x02;
        der[offset++] = (byte) sLen;
        System.arraycopy(sBytes, 0, der, offset, sLen);

        return der;
    }
}
