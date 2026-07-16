"""Tests for binary encoding."""

from constellation_metagraph.core import encode_data_update, to_bytes
from constellation_metagraph.core.types import CONSTELLATION_PREFIX


class TestToBytes:
    """Test to_bytes function."""

    def test_encodes_simple_object(self):
        """Simple object should encode to UTF-8."""
        data = {"a": 1}
        result = to_bytes(data)
        assert result == b'{"a":1}'

    def test_canonicalizes_before_encoding(self):
        """Keys should be sorted before encoding."""
        data = {"b": 2, "a": 1}
        result = to_bytes(data)
        assert result == b'{"a":1,"b":2}'

    def test_is_deterministic(self):
        """Same data should produce same bytes."""
        data = {"id": "test", "value": 42}
        result1 = to_bytes(data)
        result2 = to_bytes(data)
        assert result1 == result2


class TestRegularEncoding:
    """Test regular (non-DataUpdate) encoding."""

    def test_returns_plain_utf8(self):
        """Regular encoding should be plain UTF-8."""
        data = {"test": "value"}
        result = to_bytes(data, is_data_update=False)
        assert result == b'{"test":"value"}'


class TestDataUpdateEncoding:
    """Test DataUpdate encoding."""

    def test_includes_constellation_prefix(self):
        """DataUpdate should include Constellation prefix."""
        data = {"test": "value"}
        result = to_bytes(data, is_data_update=True)
        assert result.startswith(CONSTELLATION_PREFIX.encode("utf-8"))

    def test_base64_encodes_json(self):
        """DataUpdate should base64 encode the canonical JSON."""
        import base64

        data = {"id": "test"}
        result = to_bytes(data, is_data_update=True)
        decoded = result.decode("utf-8")

        # Extract base64 from format: \x19Constellation Signed Data:\n{length}\n{base64}
        parts = decoded.split("\n")
        assert len(parts) == 3

        base64_part = parts[2]
        decoded_base64 = base64.b64decode(base64_part).decode("utf-8")
        assert decoded_base64 == '{"id":"test"}'

    def test_includes_correct_length(self):
        """DataUpdate should include correct length."""
        data = {"id": "test"}
        result = to_bytes(data, is_data_update=True)
        decoded = result.decode("utf-8")

        parts = decoded.split("\n")
        length = int(parts[1])
        base64_part = parts[2]
        assert length == len(base64_part)


class TestEncodeDataUpdate:
    """Test encode_data_update convenience function."""

    def test_equivalent_to_to_bytes_with_flag(self):
        """Should be equivalent to to_bytes with is_data_update=True."""
        data = {"action": "update", "value": 123}
        result1 = to_bytes(data, is_data_update=True)
        result2 = encode_data_update(data)
        assert result1 == result2
