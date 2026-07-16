"""Integration tests for the full signing workflow."""

import pytest

from constellation_metagraph.core import (
    add_signature,
    batch_sign,
    create_signed_object,
    generate_key_pair,
    is_valid_private_key,
    is_valid_public_key,
    key_pair_from_private_key,
    sign,
    sign_data_update,
    verify,
    verify_signature,
)


class TestKeyGeneration:
    """Test key generation."""

    def test_generates_valid_key_pair(self):
        """Should generate valid key pair."""
        key_pair = generate_key_pair()

        assert key_pair.private_key
        assert key_pair.public_key
        assert key_pair.address

        assert is_valid_private_key(key_pair.private_key)
        assert is_valid_public_key(key_pair.public_key)
        assert key_pair.address.startswith("DAG")

    def test_derives_same_key_pair(self):
        """Same private key should derive same key pair."""
        key_pair1 = generate_key_pair()
        key_pair2 = key_pair_from_private_key(key_pair1.private_key)

        assert key_pair2.public_key == key_pair1.public_key
        assert key_pair2.address == key_pair1.address


class TestRegularSigning:
    """Test regular (non-DataUpdate) signing."""

    @pytest.fixture
    def key_pair(self):
        """Generate a key pair for tests."""
        return generate_key_pair()

    def test_sign_and_verify(self, key_pair):
        """Should sign and verify data."""
        data = {"action": "test", "value": 42}
        proof = sign(data, key_pair.private_key)

        assert proof.id
        assert proof.signature
        assert len(proof.id) == 128  # Without 04 prefix

        is_valid = verify_signature(data, proof, is_data_update=False)
        assert is_valid

    def test_create_signed_object(self, key_pair):
        """Should create signed object."""
        data = {"action": "test", "value": 123}
        signed = create_signed_object(data, key_pair.private_key)

        assert signed.value == data
        assert len(signed.proofs) == 1

        result = verify(signed, is_data_update=False)
        assert result.is_valid
        assert len(result.valid_proofs) == 1
        assert len(result.invalid_proofs) == 0


class TestDataUpdateSigning:
    """Test DataUpdate signing."""

    @pytest.fixture
    def key_pair(self):
        """Generate a key pair for tests."""
        return generate_key_pair()

    def test_sign_and_verify_data_update(self, key_pair):
        """Should sign and verify DataUpdate."""
        data = {"action": "update", "payload": {"key": "value"}}
        proof = sign_data_update(data, key_pair.private_key)

        assert proof.id
        assert proof.signature

        is_valid = verify_signature(data, proof, is_data_update=True)
        assert is_valid

    def test_create_signed_data_update(self, key_pair):
        """Should create signed DataUpdate object."""
        data = {"action": "update", "value": 999}
        signed = create_signed_object(data, key_pair.private_key, is_data_update=True)

        assert signed.value == data
        assert len(signed.proofs) == 1

        result = verify(signed, is_data_update=True)
        assert result.is_valid


class TestMultiSignature:
    """Test multi-signature functionality."""

    def test_add_signature(self):
        """Should add signature to existing signed object."""
        key_pair1 = generate_key_pair()
        key_pair2 = generate_key_pair()
        data = {"action": "multi-sig", "value": "test"}

        # First signature
        signed = create_signed_object(data, key_pair1.private_key)
        assert len(signed.proofs) == 1

        # Add second signature
        signed = add_signature(signed, key_pair2.private_key)
        assert len(signed.proofs) == 2

        # Both proofs should be valid
        result = verify(signed, is_data_update=False)
        assert result.is_valid
        assert len(result.valid_proofs) == 2

    def test_batch_sign(self):
        """Should batch sign with multiple keys."""
        key_pair1 = generate_key_pair()
        key_pair2 = generate_key_pair()
        key_pair3 = generate_key_pair()
        data = {"action": "batch", "value": "test"}

        signed = batch_sign(
            data,
            [key_pair1.private_key, key_pair2.private_key, key_pair3.private_key],
        )

        assert len(signed.proofs) == 3

        result = verify(signed, is_data_update=False)
        assert result.is_valid
        assert len(result.valid_proofs) == 3


class TestTamperDetection:
    """Test tamper detection."""

    @pytest.fixture
    def key_pair(self):
        """Generate a key pair for tests."""
        return generate_key_pair()

    def test_detects_modified_data(self, key_pair):
        """Should detect modified data."""
        from constellation_metagraph.core.types import Signed

        data = {"action": "test", "value": 42}
        signed = create_signed_object(data, key_pair.private_key)

        # Modify the data
        tampered = Signed(value={"action": "test", "value": 999}, proofs=signed.proofs)

        result = verify(tampered, is_data_update=False)
        assert not result.is_valid
        assert len(result.invalid_proofs) == 1

    def test_detects_wrong_signing_mode(self, key_pair):
        """Should detect wrong signing mode."""
        data = {"action": "test", "value": 42}
        # Sign as regular
        signed = create_signed_object(data, key_pair.private_key, is_data_update=False)

        # Verify as DataUpdate (should fail)
        result = verify(signed, is_data_update=True)
        assert not result.is_valid


class TestErrorHandling:
    """Test error handling."""

    def test_batch_sign_requires_keys(self):
        """Should raise error if no keys provided."""
        with pytest.raises(ValueError, match="At least one private key"):
            batch_sign({"test": 1}, [])
