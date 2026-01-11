"""
Tests for network operations.
"""

import pytest

from constellation_sdk import (
    CurrencyL1Client,
    DataL1Client,
    NetworkConfig,
    NetworkError,
)


class TestCurrencyL1Client:
    def test_requires_l1_url_in_config(self):
        with pytest.raises(ValueError, match="l1_url is required"):
            CurrencyL1Client(NetworkConfig())

    def test_creates_client_with_valid_config(self):
        config = NetworkConfig(l1_url="http://localhost:9010")
        client = CurrencyL1Client(config)
        assert client is not None

    def test_accepts_optional_timeout(self):
        config = NetworkConfig(l1_url="http://localhost:9010", timeout=5.0)
        client = CurrencyL1Client(config)
        assert client is not None


class TestDataL1Client:
    def test_requires_data_l1_url_in_config(self):
        with pytest.raises(ValueError, match="data_l1_url is required"):
            DataL1Client(NetworkConfig())

    def test_creates_client_with_valid_config(self):
        config = NetworkConfig(data_l1_url="http://localhost:8080")
        client = DataL1Client(config)
        assert client is not None

    def test_accepts_optional_timeout(self):
        config = NetworkConfig(data_l1_url="http://localhost:8080", timeout=10.0)
        client = DataL1Client(config)
        assert client is not None


class TestNetworkError:
    def test_creates_error_with_message_only(self):
        error = NetworkError("Connection failed")
        assert str(error) == "Connection failed"
        assert error.status_code is None
        assert error.response is None

    def test_creates_error_with_status_code(self):
        error = NetworkError("Not found", status_code=404)
        assert "Not found" in str(error)
        assert error.status_code == 404

    def test_creates_error_with_response_body(self):
        error = NetworkError("Bad request", status_code=400, response='{"error":"invalid"}')
        assert error.status_code == 400
        assert error.response == '{"error":"invalid"}'

    def test_is_instance_of_exception(self):
        error = NetworkError("Test")
        assert isinstance(error, Exception)
        assert isinstance(error, NetworkError)


class TestCombinedConfig:
    def test_allows_both_urls_in_same_config(self):
        config = NetworkConfig(
            l1_url="http://localhost:9010",
            data_l1_url="http://localhost:8080",
            timeout=30.0,
        )

        l1_client = CurrencyL1Client(config)
        data_client = DataL1Client(config)

        assert l1_client is not None
        assert data_client is not None
