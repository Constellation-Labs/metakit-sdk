package io.constellationnetwork.metagraph.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * High-level API for creating and managing signed objects.
 */
public final class SignedObject {

    private SignedObject() {
        // Utility class
    }

    /**
     * Create a signed object with a single signature.
     *
     * @param value The value to sign
     * @param privateKey Private key in hex format
     * @param isDataUpdate Whether to use DataUpdate encoding
     * @return Signed object with the value and signature proof
     */
    public static <T> Types.Signed<T> createSignedObject(T value, String privateKey, boolean isDataUpdate) {
        Types.SignatureProof proof;
        if (isDataUpdate) {
            proof = Sign.signDataUpdate(value, privateKey);
        } else {
            proof = Sign.sign(value, privateKey);
        }
        return new Types.Signed<>(value, Collections.singletonList(proof));
    }

    /**
     * Add a signature to an existing signed object.
     *
     * @param signed Existing signed object
     * @param privateKey Private key to add signature with
     * @param isDataUpdate Whether to use DataUpdate encoding
     * @return New signed object with additional signature
     */
    public static <T> Types.Signed<T> addSignature(Types.Signed<T> signed, String privateKey, boolean isDataUpdate) {
        Types.SignatureProof newProof;
        if (isDataUpdate) {
            newProof = Sign.signDataUpdate(signed.getValue(), privateKey);
        } else {
            newProof = Sign.sign(signed.getValue(), privateKey);
        }

        List<Types.SignatureProof> proofs = new ArrayList<>(signed.getProofs());
        proofs.add(newProof);
        return new Types.Signed<>(signed.getValue(), proofs);
    }

    /**
     * Create a signed object with multiple signatures.
     *
     * @param value The value to sign
     * @param privateKeys List of private keys
     * @param isDataUpdate Whether to use DataUpdate encoding
     * @return Signed object with multiple signature proofs
     * @throws Types.SdkException if no private keys provided
     */
    public static <T> Types.Signed<T> batchSign(T value, List<String> privateKeys, boolean isDataUpdate) {
        if (privateKeys == null || privateKeys.isEmpty()) {
            throw new Types.SdkException("At least one private key is required");
        }

        List<Types.SignatureProof> proofs = new ArrayList<>();
        for (String privateKey : privateKeys) {
            Types.SignatureProof proof;
            if (isDataUpdate) {
                proof = Sign.signDataUpdate(value, privateKey);
            } else {
                proof = Sign.sign(value, privateKey);
            }
            proofs.add(proof);
        }

        return new Types.Signed<>(value, proofs);
    }

    /**
     * Verify a signed object.
     *
     * @param signed Signed object to verify
     * @param isDataUpdate Whether the object was signed as DataUpdate
     * @return Verification result
     */
    public static <T> Types.VerificationResult verify(Types.Signed<T> signed, boolean isDataUpdate) {
        return Verify.verify(signed, isDataUpdate);
    }
}
