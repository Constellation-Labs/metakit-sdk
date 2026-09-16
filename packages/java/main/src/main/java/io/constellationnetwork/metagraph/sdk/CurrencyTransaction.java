package io.constellationnetwork.metagraph.sdk;

import io.constellationnetwork.metagraph.sdk.core.Types;
import io.constellationnetwork.metagraph.sdk.core.Wallet;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Currency transaction operations for metagraph token transfers.
 */
public final class CurrencyTransaction {

    /** Minimum salt complexity (from dag4.js) */
    private static final long MIN_SALT = (1L << 53) - (1L << 48);

    private static final Pattern DAG_ADDRESS_BASE58_PATTERN =
        Pattern.compile("^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{36}$");

    private CurrencyTransaction() {
        // Utility class
    }

    /**
     * Convert token amount to smallest units.
     *
     * @param amount Amount in token units
     * @return Amount in smallest units (1e-8)
     */
    public static long tokenToUnits(double amount) {
        return (long) Math.floor(amount * 1e8);
    }

    /**
     * Convert smallest units to token amount.
     *
     * @param units Amount in smallest units (1e-8)
     * @return Amount in token units
     */
    public static double unitsToToken(long units) {
        return units * CurrencyTypes.TOKEN_DECIMALS;
    }

    /**
     * Validate DAG address format.
     *
     * DAG addresses: DAG + parity digit (0-8) + 36 base58 chars = 40 chars total
     *
     * @param address DAG address to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidDagAddress(String address) {
        if (address == null || !address.startsWith("DAG")) {
            return false;
        }
        // Exact length check
        if (address.length() != 40) {
            return false;
        }
        // Position 3 (after DAG) must be parity digit 0-8
        char parityChar = address.charAt(3);
        if (parityChar < '0' || parityChar > '8') {
            return false;
        }
        // Remaining 36 characters must be base58 (no 0, O, I, l)
        return DAG_ADDRESS_BASE58_PATTERN.matcher(address.substring(4)).matches();
    }

    /**
     * Generate a random salt for transaction uniqueness.
     *
     * @return Random salt as string
     */
    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[6];
        random.nextBytes(randomBytes);

        long randomInt = 0;
        for (int i = 0; i < 6; i++) {
            randomInt = (randomInt << 8) | (randomBytes[i] & 0xFF);
        }

        long salt = MIN_SALT + randomInt;
        return Long.toString(salt);
    }

    /**
     * Encode a currency transaction for hashing.
     *
     * @param tx Currency transaction
     * @return Encoded string
     */
    public static String encodeCurrencyTransaction(CurrencyTypes.CurrencyTransaction tx) {
        CurrencyTypes.CurrencyTransactionValue value = tx.getValue();

        String parentCount = "2"; // Always 2 parents for v2
        String source = value.getSource();
        String destination = value.getDestination();
        String amountHex = Long.toHexString(value.getAmount());
        String parentHash = value.getParent().getHash();
        String ordinal = Long.toString(value.getParent().getOrdinal());
        String fee = Long.toString(value.getFee());

        // Convert salt to hex
        BigInteger saltInt = new BigInteger(value.getSalt());
        String saltHex = saltInt.toString(16);

        // Build encoded string (length-prefixed format)
        return parentCount +
               source.length() + source +
               destination.length() + destination +
               amountHex.length() + amountHex +
               parentHash.length() + parentHash +
               ordinal.length() + ordinal +
               fee.length() + fee +
               saltHex.length() + saltHex;
    }

    /**
     * Kryo serialization for transaction encoding.
     *
     * @param msg Message to serialize
     * @param setReferences Whether to set references (always false for v2)
     * @return Serialized bytes
     */
    private static byte[] kryoSerialize(String msg, boolean setReferences) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        // Write header
        output.write(0x03);
        if (setReferences) {
            output.write(0x01);
        }

        // Write UTF-8 length
        int length = msg.length() + 1;
        byte[] lengthBytes = utf8Length(length);
        try {
            output.write(lengthBytes);
            output.write(msg.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new Types.SdkException("Failed to serialize", e);
        }

        return output.toByteArray();
    }

    /**
     * Encode length using Kryo's variable-length encoding.
     */
    private static byte[] utf8Length(int value) {
        if ((value >>> 6) == 0) {
            return new byte[]{(byte) (value | 0x80)};
        } else if ((value >>> 13) == 0) {
            return new byte[]{
                (byte) (value | 0x40 | 0x80),
                (byte) (value >>> 6)
            };
        } else if ((value >>> 20) == 0) {
            return new byte[]{
                (byte) (value | 0x40 | 0x80),
                (byte) ((value >>> 6) | 0x80),
                (byte) (value >>> 13)
            };
        } else if ((value >>> 27) == 0) {
            return new byte[]{
                (byte) (value | 0x40 | 0x80),
                (byte) ((value >>> 6) | 0x80),
                (byte) ((value >>> 13) | 0x80),
                (byte) (value >>> 20)
            };
        } else {
            return new byte[]{
                (byte) (value | 0x40 | 0x80),
                (byte) ((value >>> 6) | 0x80),
                (byte) ((value >>> 13) | 0x80),
                (byte) ((value >>> 20) | 0x80),
                (byte) (value >>> 27)
            };
        }
    }

    /**
     * Sign a hash using Constellation signing protocol.
     */
    private static String signHashInternal(String hashHex, String privateKey) {
        try {
            // Hash hex as UTF-8 -> SHA-512 -> truncate 32 bytes
            byte[] hashUtf8 = hashHex.getBytes(StandardCharsets.UTF_8);
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] sha512Hash = sha512.digest(hashUtf8);
            byte[] digest = new byte[32];
            System.arraycopy(sha512Hash, 0, digest, 0, 32);

            // Sign with ECDSA
            byte[] privateKeyBytes = Wallet.hexToBytes(privateKey);
            BigInteger privateKeyInt = new BigInteger(1, privateKeyBytes);
            ECDomainParameters ecParams = Wallet.getEcParams();
            org.bouncycastle.crypto.params.ECPrivateKeyParameters privKeyParams =
                new org.bouncycastle.crypto.params.ECPrivateKeyParameters(privateKeyInt, ecParams);

            ECDSASigner signer = new ECDSASigner();
            signer.init(true, privKeyParams);
            BigInteger[] signature = signer.generateSignature(digest);

            // Normalize S to low-S form
            BigInteger r = signature[0];
            BigInteger s = signature[1];
            BigInteger halfN = ecParams.getN().shiftRight(1);
            if (s.compareTo(halfN) > 0) {
                s = ecParams.getN().subtract(s);
            }

            // Encode to DER
            byte[] derSignature = encodeToDER(r, s);
            return Wallet.bytesToHex(derSignature);

        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-512 not available", e);
        }
    }

    /**
     * Verify a signature on a hash.
     */
    private static boolean verifyHashInternal(String publicKeyHex, String hashHex, String signatureHex) {
        try {
            // Hash hex as UTF-8 -> SHA-512 -> truncate 32 bytes
            byte[] hashUtf8 = hashHex.getBytes(StandardCharsets.UTF_8);
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] sha512Hash = sha512.digest(hashUtf8);
            byte[] digest = new byte[32];
            System.arraycopy(sha512Hash, 0, digest, 0, 32);

            // Parse public key
            byte[] publicKeyBytes = Wallet.hexToBytes(publicKeyHex);
            ECDomainParameters ecParams = Wallet.getEcParams();
            ECPoint publicKeyPoint = ecParams.getCurve().decodePoint(publicKeyBytes);
            ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(publicKeyPoint, ecParams);

            // Parse signature from DER
            byte[] signatureBytes = Wallet.hexToBytes(signatureHex);
            BigInteger[] rs = decodeFromDER(signatureBytes);

            // Verify signature
            ECDSASigner verifier = new ECDSASigner();
            verifier.init(false, pubKeyParams);
            return verifier.verifySignature(digest, rs[0], rs[1]);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Encode ECDSA signature (r, s) to DER format.
     */
    private static byte[] encodeToDER(BigInteger r, BigInteger s) {
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

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

    /**
     * Decode DER signature to (r, s) values.
     */
    private static BigInteger[] decodeFromDER(byte[] der) {
        if (der[0] != 0x30) {
            throw new IllegalArgumentException("Invalid DER signature");
        }

        int offset = 2;

        // Read r
        if (der[offset++] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature");
        }
        int rLen = der[offset++] & 0xFF;
        byte[] rBytes = new byte[rLen];
        System.arraycopy(der, offset, rBytes, 0, rLen);
        offset += rLen;

        // Read s
        if (der[offset++] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature");
        }
        int sLen = der[offset++] & 0xFF;
        byte[] sBytes = new byte[sLen];
        System.arraycopy(der, offset, sBytes, 0, sLen);

        return new BigInteger[]{new BigInteger(1, rBytes), new BigInteger(1, sBytes)};
    }

    /**
     * Create a metagraph token transaction.
     *
     * @param params Transfer parameters
     * @param privateKey Private key in hex format
     * @param lastRef Last transaction reference
     * @return Currency transaction
     */
    public static CurrencyTypes.CurrencyTransaction createCurrencyTransaction(
            CurrencyTypes.TransferParams params,
            String privateKey,
            CurrencyTypes.TransactionReference lastRef) {

        // Get source address from private key
        String publicKey = Wallet.getPublicKeyHex(privateKey, false);
        String source = Wallet.getAddress(publicKey);

        // Validate addresses
        if (!isValidDagAddress(source)) {
            throw new Types.SdkException("Invalid source address");
        }
        if (!isValidDagAddress(params.getDestination())) {
            throw new Types.SdkException("Invalid destination address");
        }
        if (source.equals(params.getDestination())) {
            throw new Types.SdkException("Source and destination addresses cannot be the same");
        }

        // Convert amounts to smallest units
        long amount = tokenToUnits(params.getAmount());
        long fee = tokenToUnits(params.getFee());

        // Validate amounts
        if (amount < 1) {
            throw new Types.SdkException("Transfer amount must be greater than 1e-8");
        }
        if (fee < 0) {
            throw new Types.SdkException("Fee must be greater than or equal to zero");
        }

        // Generate salt
        String salt = generateSalt();

        // Create transaction value
        CurrencyTypes.CurrencyTransactionValue txValue = new CurrencyTypes.CurrencyTransactionValue(
            source,
            params.getDestination(),
            amount,
            fee,
            lastRef,
            salt
        );

        // Create signed transaction
        CurrencyTypes.CurrencyTransaction tx = new CurrencyTypes.CurrencyTransaction(
            txValue,
            new ArrayList<>()
        );

        // Encode and hash
        String encoded = encodeCurrencyTransaction(tx);
        byte[] serialized = kryoSerialize(encoded, false);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = sha256.digest(serialized);
            String hashHex = Wallet.bytesToHex(hashBytes);

            // Sign
            String signature = signHashInternal(hashHex, privateKey);

            // Create proof
            String publicKeyId = publicKey.substring(2); // Remove '04' prefix
            Types.SignatureProof proof = new Types.SignatureProof(publicKeyId, signature);

            // Add proof to transaction
            List<Types.SignatureProof> proofs = new ArrayList<>();
            proofs.add(proof);

            return new CurrencyTypes.CurrencyTransaction(txValue, proofs);

        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Create multiple metagraph token transactions (batch).
     *
     * @param transfers List of transfer parameters
     * @param privateKey Private key in hex format
     * @param lastRef Last transaction reference
     * @return List of currency transactions
     */
    public static List<CurrencyTypes.CurrencyTransaction> createCurrencyTransactionBatch(
            List<CurrencyTypes.TransferParams> transfers,
            String privateKey,
            CurrencyTypes.TransactionReference lastRef) {

        List<CurrencyTypes.CurrencyTransaction> transactions = new ArrayList<>();
        CurrencyTypes.TransactionReference currentRef = lastRef;

        for (CurrencyTypes.TransferParams transfer : transfers) {
            CurrencyTypes.CurrencyTransaction tx = createCurrencyTransaction(
                transfer,
                privateKey,
                currentRef
            );

            // Calculate hash for next transaction's parent reference
            Types.Hash hashResult = hashCurrencyTransaction(tx);

            // Update reference for next transaction
            currentRef = new CurrencyTypes.TransactionReference(
                hashResult.getValue(),
                currentRef.getOrdinal() + 1
            );

            transactions.add(tx);
        }

        return transactions;
    }

    /**
     * Add a signature to an existing currency transaction (for multi-sig).
     *
     * @param transaction Existing currency transaction
     * @param privateKey Private key in hex format
     * @return Currency transaction with additional signature
     */
    public static CurrencyTypes.CurrencyTransaction signCurrencyTransaction(
            CurrencyTypes.CurrencyTransaction transaction,
            String privateKey) {

        // Encode and hash
        String encoded = encodeCurrencyTransaction(transaction);
        byte[] serialized = kryoSerialize(encoded, false);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = sha256.digest(serialized);
            String hashHex = Wallet.bytesToHex(hashBytes);

            // Sign
            String signature = signHashInternal(hashHex, privateKey);

            // Get public key
            String publicKey = Wallet.getPublicKeyHex(privateKey, false);

            // Verify signature
            if (!verifyHashInternal(publicKey, hashHex, signature)) {
                throw new Types.SdkException("Sign-Verify failed");
            }

            // Create proof
            String publicKeyId = publicKey.substring(2); // Remove '04' prefix
            Types.SignatureProof proof = new Types.SignatureProof(publicKeyId, signature);

            // Create new signed transaction with updated proofs
            List<Types.SignatureProof> newProofs = new ArrayList<>(transaction.getProofs());
            newProofs.add(proof);

            return new CurrencyTypes.CurrencyTransaction(transaction.getValue(), newProofs);

        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Verify all signatures on a currency transaction.
     *
     * @param transaction Currency transaction to verify
     * @return Verification result
     */
    public static Types.VerificationResult verifyCurrencyTransaction(
            CurrencyTypes.CurrencyTransaction transaction) {

        // Encode and hash
        String encoded = encodeCurrencyTransaction(transaction);
        byte[] serialized = kryoSerialize(encoded, false);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = sha256.digest(serialized);
            String hashHex = Wallet.bytesToHex(hashBytes);

            List<Types.SignatureProof> validProofs = new ArrayList<>();
            List<Types.SignatureProof> invalidProofs = new ArrayList<>();

            // Verify each proof
            for (Types.SignatureProof proof : transaction.getProofs()) {
                String publicKey = "04" + proof.getId(); // Add back '04' prefix
                boolean isValid = verifyHashInternal(publicKey, hashHex, proof.getSignature());

                if (isValid) {
                    validProofs.add(proof);
                } else {
                    invalidProofs.add(proof);
                }
            }

            boolean isValid = invalidProofs.isEmpty() && !validProofs.isEmpty();
            return new Types.VerificationResult(isValid, validProofs, invalidProofs);

        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Hash a currency transaction.
     *
     * @param transaction Currency transaction
     * @return Hash result
     */
    public static Types.Hash hashCurrencyTransaction(CurrencyTypes.CurrencyTransaction transaction) {
        String encoded = encodeCurrencyTransaction(transaction);
        byte[] serialized = kryoSerialize(encoded, false);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = sha256.digest(serialized);
            String hashHex = Wallet.bytesToHex(hashBytes);

            return new Types.Hash(hashHex, hashBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new Types.SdkException("SHA-256 not available", e);
        }
    }

    /**
     * Get transaction reference from a currency transaction.
     *
     * @param transaction Currency transaction
     * @param ordinal Ordinal number for the reference
     * @return Transaction reference
     */
    public static CurrencyTypes.TransactionReference getTransactionReference(
            CurrencyTypes.CurrencyTransaction transaction,
            long ordinal) {

        Types.Hash hashResult = hashCurrencyTransaction(transaction);
        return new CurrencyTypes.TransactionReference(hashResult.getValue(), ordinal);
    }
}
