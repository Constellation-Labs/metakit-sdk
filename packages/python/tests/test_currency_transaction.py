"""Tests for currency transaction functionality."""

import pytest

from constellation_sdk import (
    TOKEN_DECIMALS,
    TransactionReference,
    TransferParams,
    create_currency_transaction,
    create_currency_transaction_batch,
    encode_currency_transaction,
    generate_key_pair,
    get_transaction_reference,
    hash_currency_transaction,
    is_valid_dag_address,
    sign_currency_transaction,
    token_to_units,
    units_to_token,
    verify_currency_transaction,
)


class TestUtilityFunctions:
    """Test utility conversion functions."""

    def test_token_to_units_converts_correctly(self):
        """Test token to units conversion."""
        assert token_to_units(100.5) == 10050000000
        assert token_to_units(0.00000001) == 1
        assert token_to_units(1) == 100000000

    def test_units_to_token_converts_correctly(self):
        """Test units to token conversion."""
        assert units_to_token(10050000000) == 100.5
        assert units_to_token(1) == 0.00000001
        assert units_to_token(100000000) == 1.0

    def test_token_decimals_constant(self):
        """Test TOKEN_DECIMALS constant."""
        assert TOKEN_DECIMALS == 1e-8

    def test_is_valid_dag_address_validates_addresses(self):
        """Test DAG address validation."""
        key_pair = generate_key_pair()
        assert is_valid_dag_address(key_pair.address) is True
        assert is_valid_dag_address("invalid") is False
        assert is_valid_dag_address("") is False
        assert is_valid_dag_address("DAG") is False


class TestTransactionCreation:
    """Test transaction creation."""

    def test_create_currency_transaction_creates_valid_transaction(self):
        """Test creating a valid currency transaction."""
        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()

        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        tx = create_currency_transaction(
            TransferParams(destination=key_pair2.address, amount=100.5, fee=0),
            key_pair.private_key,
            last_ref,
        )

        assert tx is not None
        assert tx.value.source == key_pair.address
        assert tx.value.destination == key_pair2.address
        assert tx.value.amount == 10050000000  # 100.5 * 1e8
        assert tx.value.fee == 0
        assert tx.value.parent == last_ref
        assert len(tx.proofs) == 1
        assert hasattr(tx.proofs[0], "id")
        assert hasattr(tx.proofs[0], "signature")

    def test_create_currency_transaction_throws_on_invalid_destination(self):
        """Test that invalid destination address raises error."""
        key_pair = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        with pytest.raises(ValueError, match="Invalid destination address"):
            create_currency_transaction(
                TransferParams(destination="invalid", amount=100, fee=0),
                key_pair.private_key,
                last_ref,
            )

    def test_create_currency_transaction_throws_on_same_address(self):
        """Test that same source and destination raises error."""
        key_pair = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        with pytest.raises(ValueError, match="Source and destination addresses cannot be the same"):
            create_currency_transaction(
                TransferParams(destination=key_pair.address, amount=100, fee=0),
                key_pair.private_key,
                last_ref,
            )

    def test_create_currency_transaction_throws_on_amount_too_small(self):
        """Test that amount too small raises error."""
        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        with pytest.raises(ValueError, match="Transfer amount must be greater than 1e-8"):
            create_currency_transaction(
                TransferParams(destination=key_pair2.address, amount=0.000000001, fee=0),
                key_pair.private_key,
                last_ref,
            )

    def test_create_currency_transaction_throws_on_negative_fee(self):
        """Test that negative fee raises error."""
        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        with pytest.raises(ValueError, match="Fee must be greater than or equal to zero"):
            create_currency_transaction(
                TransferParams(destination=key_pair2.address, amount=100, fee=-1),
                key_pair.private_key,
                last_ref,
            )


class TestBatchTransactions:
    """Test batch transaction creation."""

    def test_create_currency_transaction_batch_creates_multiple(self):
        """Test creating multiple transactions in a batch."""
        key_pair = generate_key_pair()
        recipient1 = generate_key_pair()
        recipient2 = generate_key_pair()
        recipient3 = generate_key_pair()

        last_ref = TransactionReference(hash="a" * 64, ordinal=5)

        transfers = [
            TransferParams(destination=recipient1.address, amount=10),
            TransferParams(destination=recipient2.address, amount=20),
            TransferParams(destination=recipient3.address, amount=30),
        ]

        txns = create_currency_transaction_batch(transfers, key_pair.private_key, last_ref)

        assert len(txns) == 3
        assert txns[0].value.amount == 1000000000  # 10 * 1e8
        assert txns[1].value.amount == 2000000000  # 20 * 1e8
        assert txns[2].value.amount == 3000000000  # 30 * 1e8

        # Check parent references are chained
        assert txns[0].value.parent == last_ref
        assert txns[1].value.parent.ordinal == 6
        assert txns[2].value.parent.ordinal == 7


class TestTransactionVerification:
    """Test transaction verification."""

    def test_verify_currency_transaction_validates_correct_signatures(self):
        """Test that correct signatures verify successfully."""
        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        tx = create_currency_transaction(
            TransferParams(destination=key_pair2.address, amount=100, fee=0),
            key_pair.private_key,
            last_ref,
        )

        result = verify_currency_transaction(tx)

        assert result.is_valid is True
        assert len(result.valid_proofs) == 1
        assert len(result.invalid_proofs) == 0

    def test_verify_currency_transaction_detects_invalid_signatures(self):
        """Test that invalid signatures are detected."""
        from constellation_sdk import SignatureProof

        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        tx = create_currency_transaction(
            TransferParams(destination=key_pair2.address, amount=100, fee=0),
            key_pair.private_key,
            last_ref,
        )

        # Replace with invalid proof (SignatureProof is frozen)
        tx.proofs[0] = SignatureProof(id=tx.proofs[0].id, signature="invalid_signature")

        result = verify_currency_transaction(tx)

        assert result.is_valid is False
        assert len(result.valid_proofs) == 0
        assert len(result.invalid_proofs) == 1


class TestMultiSignatureSupport:
    """Test multi-signature functionality."""

    def test_sign_currency_transaction_adds_additional_signature(self):
        """Test adding additional signature to a transaction."""
        key_pair1 = generate_key_pair()
        key_pair2 = generate_key_pair()
        recipient = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        # Create transaction with first signature
        tx = create_currency_transaction(
            TransferParams(destination=recipient.address, amount=100, fee=0),
            key_pair1.private_key,
            last_ref,
        )

        assert len(tx.proofs) == 1

        # Add second signature
        tx = sign_currency_transaction(tx, key_pair2.private_key)

        assert len(tx.proofs) == 2

        # Verify both signatures
        result = verify_currency_transaction(tx)

        assert result.is_valid is True
        assert len(result.valid_proofs) == 2
        assert len(result.invalid_proofs) == 0


class TestTransactionHashing:
    """Test transaction hashing."""

    def test_hash_currency_transaction_produces_consistent_hashes(self):
        """Test that hashing produces consistent results."""
        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        tx = create_currency_transaction(
            TransferParams(destination=key_pair2.address, amount=100, fee=0),
            key_pair.private_key,
            last_ref,
        )

        hash1 = hash_currency_transaction(tx)
        hash2 = hash_currency_transaction(tx)

        assert hash1.value == hash2.value
        assert len(hash1.value) == 64  # SHA-256 hex string
        assert len(hash1.bytes) == 32  # 32 bytes

    def test_get_transaction_reference_creates_correct_reference(self):
        """Test creating transaction reference."""
        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        tx = create_currency_transaction(
            TransferParams(destination=key_pair2.address, amount=100, fee=0),
            key_pair.private_key,
            last_ref,
        )

        ref = get_transaction_reference(tx, 1)

        assert ref.ordinal == 1
        assert len(ref.hash) == 64

    def test_encode_currency_transaction_returns_string(self):
        """Test encoding transaction."""
        key_pair = generate_key_pair()
        key_pair2 = generate_key_pair()
        last_ref = TransactionReference(hash="a" * 64, ordinal=0)

        tx = create_currency_transaction(
            TransferParams(destination=key_pair2.address, amount=100, fee=0),
            key_pair.private_key,
            last_ref,
        )

        encoded = encode_currency_transaction(tx)

        assert isinstance(encoded, str)
        assert len(encoded) > 0
