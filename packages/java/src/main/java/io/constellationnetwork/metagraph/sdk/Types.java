package io.constellationnetwork.metagraph.sdk;

import java.util.List;
import java.util.Objects;

/**
 * Core type definitions for the Constellation Metagraph SDK.
 */
public final class Types {

    /** Signature algorithm identifier */
    public static final String ALGORITHM = "SECP256K1_RFC8785_V1";

    /** Prefix for DataUpdate encoding */
    public static final String CONSTELLATION_PREFIX = "\u0019Constellation Signed Data:\n";

    private Types() {
        // Utility class
    }

    /**
     * Key pair containing private key, public key, and DAG address.
     */
    public static class KeyPair {
        private final String privateKey;
        private final String publicKey;
        private final String address;

        public KeyPair(String privateKey, String publicKey, String address) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.address = address;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public String getAddress() {
            return address;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            KeyPair keyPair = (KeyPair) o;
            return Objects.equals(privateKey, keyPair.privateKey) &&
                   Objects.equals(publicKey, keyPair.publicKey) &&
                   Objects.equals(address, keyPair.address);
        }

        @Override
        public int hashCode() {
            return Objects.hash(privateKey, publicKey, address);
        }
    }

    /**
     * Signature proof containing public key ID and signature.
     */
    public static class SignatureProof {
        private final String id;
        private final String signature;

        public SignatureProof(String id, String signature) {
            this.id = id;
            this.signature = signature;
        }

        public String getId() {
            return id;
        }

        public String getSignature() {
            return signature;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SignatureProof that = (SignatureProof) o;
            return Objects.equals(id, that.id) &&
                   Objects.equals(signature, that.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, signature);
        }
    }

    /**
     * Signed object containing a value and its signature proofs.
     *
     * @param <T> Type of the signed value
     */
    public static class Signed<T> {
        private final T value;
        private final List<SignatureProof> proofs;

        public Signed(T value, List<SignatureProof> proofs) {
            this.value = value;
            this.proofs = proofs;
        }

        public T getValue() {
            return value;
        }

        public List<SignatureProof> getProofs() {
            return proofs;
        }
    }

    /**
     * Result of signature verification.
     */
    public static class VerificationResult {
        private final boolean isValid;
        private final List<SignatureProof> validProofs;
        private final List<SignatureProof> invalidProofs;

        public VerificationResult(boolean isValid, List<SignatureProof> validProofs, List<SignatureProof> invalidProofs) {
            this.isValid = isValid;
            this.validProofs = validProofs;
            this.invalidProofs = invalidProofs;
        }

        public boolean isValid() {
            return isValid;
        }

        public List<SignatureProof> getValidProofs() {
            return validProofs;
        }

        public List<SignatureProof> getInvalidProofs() {
            return invalidProofs;
        }
    }

    /**
     * Hash result containing hex string and raw bytes.
     */
    public static class Hash {
        private final String value;
        private final byte[] bytes;

        public Hash(String value, byte[] bytes) {
            this.value = value;
            this.bytes = bytes;
        }

        public String getValue() {
            return value;
        }

        public byte[] getBytes() {
            return bytes;
        }
    }

    /**
     * SDK exception for errors during cryptographic operations.
     */
    public static class SdkException extends RuntimeException {
        public SdkException(String message) {
            super(message);
        }

        public SdkException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
