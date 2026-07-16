"""Cross-language compatibility tests."""

import json
from pathlib import Path

import pytest

from constellation_metagraph.core import canonicalize, hash_bytes, to_bytes, verify_hash


@pytest.fixture
def test_vectors():
    """Load test vectors from shared file."""
    vectors_path = (
        Path(__file__).parent.parent.parent.parent.parent / "shared" / "test_vectors.json"
    )
    with open(vectors_path) as f:
        return json.load(f)


class TestCanonicalJson:
    """Test canonical JSON matches all test vectors."""

    def test_all_vectors(self, test_vectors):
        """Canonical JSON should match all test vectors."""
        for vector in test_vectors:
            canonical = canonicalize(vector["data"])
            assert (
                canonical == vector["canonical_json"]
            ), f"Mismatch for {vector['source']} {vector['type']}"


class TestBinaryEncoding:
    """Test binary encoding matches all test vectors."""

    def test_all_vectors(self, test_vectors):
        """UTF-8 bytes should match all test vectors."""
        for vector in test_vectors:
            is_data_update = vector["type"] == "TestDataUpdate"
            result = to_bytes(vector["data"], is_data_update)
            result_hex = result.hex()
            assert (
                result_hex == vector["utf8_bytes_hex"]
            ), f"Mismatch for {vector['source']} {vector['type']}"


class TestHashing:
    """Test SHA-256 hashes match all test vectors."""

    def test_all_vectors(self, test_vectors):
        """SHA-256 hashes should match all test vectors."""
        for vector in test_vectors:
            is_data_update = vector["type"] == "TestDataUpdate"
            data_bytes = to_bytes(vector["data"], is_data_update)
            hash_result = hash_bytes(data_bytes)
            assert (
                hash_result.value == vector["sha256_hash_hex"]
            ), f"Mismatch for {vector['source']} {vector['type']}"


class TestSignatureVerification:
    """Test signature verification for all test vectors."""

    def test_all_signatures_valid(self, test_vectors):
        """All signatures from test vectors should verify."""
        for vector in test_vectors:
            is_valid = verify_hash(
                vector["sha256_hash_hex"],
                vector["signature_hex"],
                vector["public_key_hex"],
            )
            assert is_valid, f"Signature invalid for {vector['source']} {vector['type']}"

    def test_tampered_signature_rejected(self, test_vectors):
        """Tampered signatures should be rejected."""
        vector = test_vectors[0]
        # Modify the hash slightly
        tampered_hash = vector["sha256_hash_hex"].replace("0", "1")
        is_valid = verify_hash(tampered_hash, vector["signature_hex"], vector["public_key_hex"])
        assert not is_valid


class TestBySourceLanguage:
    """Test vectors grouped by source language."""

    @pytest.mark.parametrize("language", ["python", "javascript", "rust", "go"])
    def test_regular_data_signatures(self, test_vectors, language):
        """Verify regular data signatures from each language."""
        vectors = [v for v in test_vectors if v["source"] == language and v["type"] == "TestData"]
        assert len(vectors) > 0, f"No TestData vectors for {language}"

        for vector in vectors:
            data_bytes = to_bytes(vector["data"], is_data_update=False)
            hash_result = hash_bytes(data_bytes)
            assert hash_result.value == vector["sha256_hash_hex"]

            is_valid = verify_hash(
                vector["sha256_hash_hex"],
                vector["signature_hex"],
                vector["public_key_hex"],
            )
            assert is_valid

    @pytest.mark.parametrize("language", ["python", "javascript", "rust", "go"])
    def test_data_update_signatures(self, test_vectors, language):
        """Verify DataUpdate signatures from each language."""
        vectors = [
            v for v in test_vectors if v["source"] == language and v["type"] == "TestDataUpdate"
        ]
        assert len(vectors) > 0, f"No TestDataUpdate vectors for {language}"

        for vector in vectors:
            data_bytes = to_bytes(vector["data"], is_data_update=True)
            hash_result = hash_bytes(data_bytes)
            assert hash_result.value == vector["sha256_hash_hex"]

            is_valid = verify_hash(
                vector["sha256_hash_hex"],
                vector["signature_hex"],
                vector["public_key_hex"],
            )
            assert is_valid
