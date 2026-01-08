package io.constellationnetwork.metagraph.sdk;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Signature verification using ECDSA secp256k1.
 */
public final class Verify {

    // secp256k1 curve order for signature normalization
    private static final BigInteger SECP256K1_N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
    );
    private static final BigInteger SECP256K1_HALF_N = SECP256K1_N.shiftRight(1);

    private Verify() {
        // Utility class
    }

    /**
     * Verify a signed object.
     *
     * @param signed Signed object with value and proofs
     * @param isDataUpdate Whether the value was signed as a DataUpdate
     * @return VerificationResult with valid/invalid proof lists
     */
    public static <T> Types.VerificationResult verify(Types.Signed<T> signed, boolean isDataUpdate) {
        // Compute the hash that should have been signed
        byte[] bytes = Binary.toBytes(signed.getValue(), isDataUpdate);
        Types.Hash hash = Hash.hashBytes(bytes);

        List<Types.SignatureProof> validProofs = new ArrayList<>();
        List<Types.SignatureProof> invalidProofs = new ArrayList<>();

        for (Types.SignatureProof proof : signed.getProofs()) {
            try {
                boolean isValid = verifyHash(hash.getValue(), proof.getSignature(), proof.getId());
                if (isValid) {
                    validProofs.add(proof);
                } else {
                    invalidProofs.add(proof);
                }
            } catch (Exception e) {
                invalidProofs.add(proof);
            }
        }

        boolean isValid = invalidProofs.isEmpty() && !validProofs.isEmpty();
        return new Types.VerificationResult(isValid, validProofs, invalidProofs);
    }

    /**
     * Verify a signature against a SHA-256 hash.
     *
     * <p>Protocol:
     * <ol>
     *   <li>Treat hash hex as UTF-8 bytes (NOT hex decode)</li>
     *   <li>SHA-512 hash</li>
     *   <li>Truncate to 32 bytes</li>
     *   <li>Verify ECDSA signature</li>
     * </ol>
     *
     * @param hashHex SHA-256 hash as 64-character hex string
     * @param signature DER-encoded signature in hex format
     * @param publicKeyId Public key in hex (with or without 04 prefix)
     * @return true if signature is valid
     */
    public static boolean verifyHash(String hashHex, String signature, String publicKeyId) {
        try {
            // Normalize and parse public key
            String fullPublicKey = Wallet.normalizePublicKey(publicKeyId);
            byte[] publicKeyBytes = Wallet.hexToBytes(fullPublicKey);

            ECDomainParameters ecParams = Wallet.getEcParams();
            ECPoint publicPoint = ecParams.getCurve().decodePoint(publicKeyBytes);
            ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(publicPoint, ecParams);

            // Parse signature
            byte[] signatureBytes = Wallet.hexToBytes(signature);
            BigInteger[] rs = decodeDER(signatureBytes);
            BigInteger r = rs[0];
            BigInteger s = rs[1];

            // Normalize S to low-S form for verification compatibility
            if (s.compareTo(SECP256K1_HALF_N) > 0) {
                s = SECP256K1_N.subtract(s);
            }

            // Compute signing digest
            byte[] digest = Hash.computeDigestFromHash(hashHex);

            // Verify signature
            ECDSASigner verifier = new ECDSASigner();
            verifier.init(false, pubKeyParams);
            return verifier.verifySignature(digest, r, s);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify a single signature proof against data.
     *
     * @param data The original data that was signed
     * @param proof The signature proof to verify
     * @param isDataUpdate Whether data was signed as DataUpdate
     * @return true if signature is valid
     */
    public static boolean verifySignature(Object data, Types.SignatureProof proof, boolean isDataUpdate) {
        byte[] bytes = Binary.toBytes(data, isDataUpdate);
        Types.Hash hash = Hash.hashBytes(bytes);
        return verifyHash(hash.getValue(), proof.getSignature(), proof.getId());
    }

    /**
     * Decode DER-encoded signature to (r, s) components.
     */
    private static BigInteger[] decodeDER(byte[] der) {
        if (der[0] != 0x30) {
            throw new Types.SdkException("Invalid DER signature format");
        }

        int offset = 2; // Skip 0x30 and total length

        // Parse R
        if (der[offset] != 0x02) {
            throw new Types.SdkException("Invalid DER signature: expected 0x02 for R");
        }
        int rLen = der[offset + 1] & 0xFF;
        byte[] rBytes = new byte[rLen];
        System.arraycopy(der, offset + 2, rBytes, 0, rLen);
        BigInteger r = new BigInteger(1, rBytes);
        offset += 2 + rLen;

        // Parse S
        if (der[offset] != 0x02) {
            throw new Types.SdkException("Invalid DER signature: expected 0x02 for S");
        }
        int sLen = der[offset + 1] & 0xFF;
        byte[] sBytes = new byte[sLen];
        System.arraycopy(der, offset + 2, sBytes, 0, sLen);
        BigInteger s = new BigInteger(1, sBytes);

        return new BigInteger[]{r, s};
    }
}
