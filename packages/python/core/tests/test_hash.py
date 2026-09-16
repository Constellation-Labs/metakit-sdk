"""Tests for hashing utilities."""

from constellation_metagraph.core import compute_digest, hash_bytes, hash_data


class TestHashData:
    """Test hash_data function."""

    def test_consistent_hash(self):
        """Same data should produce same hash."""
        data = {"id": "test", "value": 42}
        result1 = hash_data(data)
        result2 = hash_data(data)
        assert result1.value == result2.value

    def test_returns_64_char_hex(self):
        """Hash should be 64-character hex string."""
        result = hash_data({"test": "data"})
        assert len(result.value) == 64
        assert all(c in "0123456789abcdef" for c in result.value)

    def test_returns_32_bytes(self):
        """Hash bytes should be 32 bytes."""
        result = hash_data({"test": "data"})
        assert len(result.bytes) == 32

    def test_different_data_different_hash(self):
        """Different data should produce different hashes."""
        hash1 = hash_data({"value": 1})
        hash2 = hash_data({"value": 2})
        assert hash1.value != hash2.value


class TestHashBytes:
    """Test hash_bytes function."""

    def test_known_hash(self):
        """Should match known SHA-256 output."""
        data = b"hello world"
        result = hash_bytes(data)
        # Known SHA-256 of "hello world"
        assert result.value == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_consistent_results(self):
        """Same bytes should produce same hash."""
        data = bytes([1, 2, 3, 4, 5])
        result1 = hash_bytes(data)
        result2 = hash_bytes(data)
        assert result1.value == result2.value


class TestComputeDigest:
    """Test compute_digest function."""

    def test_returns_32_bytes(self):
        """Digest should be 32 bytes."""
        data = {"id": "test", "value": 42}
        digest = compute_digest(data)
        assert len(digest) == 32

    def test_different_for_data_update(self):
        """DataUpdate should produce different digest."""
        data = {"id": "test", "value": 42}
        regular_digest = compute_digest(data, is_data_update=False)
        data_update_digest = compute_digest(data, is_data_update=True)
        assert regular_digest != data_update_digest

    def test_is_deterministic(self):
        """Same data should produce same digest."""
        data = {"action": "test"}
        digest1 = compute_digest(data)
        digest2 = compute_digest(data)
        assert digest1 == digest2
