package io.constellationnetwork.metagraph.sdk;

import io.constellationnetwork.metagraph.sdk.core.Types;

import java.util.Objects;

/**
 * Currency transaction types for metagraph token transfers.
 * <p>
 * Type definitions for v2 currency transactions.
 */
public final class CurrencyTypes {

    /** Token decimals constant (1e-8) - same as DAG_DECIMALS from dag4.js */
    public static final double TOKEN_DECIMALS = 1e-8;

    private CurrencyTypes() {
        // Utility class
    }

    /**
     * Reference to a previous transaction for chaining.
     */
    public static class TransactionReference {
        private final String hash;
        private final long ordinal;

        public TransactionReference(String hash, long ordinal) {
            this.hash = hash;
            this.ordinal = ordinal;
        }

        public String getHash() {
            return hash;
        }

        public long getOrdinal() {
            return ordinal;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TransactionReference that = (TransactionReference) o;
            return ordinal == that.ordinal && Objects.equals(hash, that.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(hash, ordinal);
        }
    }

    /**
     * Currency transaction value structure (v2).
     * <p>
     * Contains the actual transaction data before signing.
     * Used for metagraph token transfers.
     */
    public static class CurrencyTransactionValue {
        private final String source;
        private final String destination;
        private final long amount;
        private final long fee;
        private final TransactionReference parent;
        private final String salt;

        public CurrencyTransactionValue(
                String source,
                String destination,
                long amount,
                long fee,
                TransactionReference parent,
                String salt) {
            this.source = source;
            this.destination = destination;
            this.amount = amount;
            this.fee = fee;
            this.parent = parent;
            this.salt = salt;
        }

        public String getSource() {
            return source;
        }

        public String getDestination() {
            return destination;
        }

        public long getAmount() {
            return amount;
        }

        public long getFee() {
            return fee;
        }

        public TransactionReference getParent() {
            return parent;
        }

        public String getSalt() {
            return salt;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CurrencyTransactionValue that = (CurrencyTransactionValue) o;
            return amount == that.amount &&
                   fee == that.fee &&
                   Objects.equals(source, that.source) &&
                   Objects.equals(destination, that.destination) &&
                   Objects.equals(parent, that.parent) &&
                   Objects.equals(salt, that.salt);
        }

        @Override
        public int hashCode() {
            return Objects.hash(source, destination, amount, fee, parent, salt);
        }
    }

    /**
     * Currency transaction structure (v2).
     * <p>
     * A signed currency transaction value.
     * Used for metagraph token transfers.
     */
    public static class CurrencyTransaction extends Types.Signed<CurrencyTransactionValue> {
        public CurrencyTransaction(CurrencyTransactionValue value, java.util.List<Types.SignatureProof> proofs) {
            super(value, proofs);
        }
    }

    /**
     * Parameters for creating a token transfer.
     */
    public static class TransferParams {
        private final String destination;
        private final double amount;
        private final double fee;

        public TransferParams(String destination, double amount, double fee) {
            this.destination = destination;
            this.amount = amount;
            this.fee = fee;
        }

        public TransferParams(String destination, double amount) {
            this(destination, amount, 0.0);
        }

        public String getDestination() {
            return destination;
        }

        public double getAmount() {
            return amount;
        }

        public double getFee() {
            return fee;
        }
    }
}
