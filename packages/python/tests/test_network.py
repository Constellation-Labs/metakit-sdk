"""
Tests for network operations.
"""

import pytest

from constellation_sdk.network import (
    LayerType,
    MetagraphClient,
    MetagraphClientConfig,
    NetworkError,
    create_metagraph_client,
)


class TestMetagraphClient:
    def test_requires_base_url_in_config(self):
        with pytest.raises(ValueError, match="base_url is required"):
            MetagraphClient(MetagraphClientConfig(base_url="", layer=LayerType.DL1))

    def test_requires_layer_in_config(self):
        with pytest.raises(ValueError, match="layer is required"):
            MetagraphClient(MetagraphClientConfig(base_url="http://localhost:9400", layer=None))  # type: ignore

    def test_creates_client_for_dl1(self):
        client = MetagraphClient(
            MetagraphClientConfig(base_url="http://localhost:9400", layer=LayerType.DL1)
        )
        assert client is not None
        assert client.layer == LayerType.DL1

    def test_creates_client_for_cl1(self):
        client = MetagraphClient(
            MetagraphClientConfig(base_url="http://localhost:9300", layer=LayerType.CL1)
        )
        assert client is not None
        assert client.layer == LayerType.CL1

    def test_creates_client_for_ml0(self):
        client = MetagraphClient(
            MetagraphClientConfig(base_url="http://localhost:9200", layer=LayerType.ML0)
        )
        assert client is not None
        assert client.layer == LayerType.ML0

    def test_accepts_optional_timeout(self):
        client = MetagraphClient(
            MetagraphClientConfig(
                base_url="http://localhost:9400",
                layer=LayerType.DL1,
                timeout=5000,
            )
        )
        assert client is not None


class TestMetagraphClientLayerGuards:
    def test_rejects_post_data_on_cl1(self):
        client = create_metagraph_client("http://localhost:9300", LayerType.CL1)
        with pytest.raises(ValueError, match="post_data.*not available on CL1"):
            client.post_data({"value": "test", "proofs": []})

    def test_rejects_post_transaction_on_dl1(self):
        client = create_metagraph_client("http://localhost:9400", LayerType.DL1)
        mock_tx = type("MockTx", (), {"value": None, "proofs": []})()
        with pytest.raises(ValueError, match="post_transaction.*not available on DL1"):
            client.post_transaction(mock_tx)

    def test_rejects_estimate_fee_on_cl1(self):
        client = create_metagraph_client("http://localhost:9300", LayerType.CL1)
        with pytest.raises(ValueError, match="estimate_fee.*not available on CL1"):
            client.estimate_fee({"value": "test", "proofs": []})


class TestCreateMetagraphClientHelper:
    def test_creates_client_with_convenience_function(self):
        client = create_metagraph_client("http://localhost:9400", LayerType.DL1)
        assert isinstance(client, MetagraphClient)
        assert client.layer == LayerType.DL1

    def test_accepts_optional_timeout(self):
        client = create_metagraph_client("http://localhost:9400", LayerType.DL1, timeout=10000)
        assert isinstance(client, MetagraphClient)


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


class TestCombinedUsage:
    def test_creates_multiple_clients_for_different_layers(self):
        cl1 = create_metagraph_client("http://localhost:9300", LayerType.CL1)
        dl1 = create_metagraph_client("http://localhost:9400", LayerType.DL1)
        ml0 = create_metagraph_client("http://localhost:9200", LayerType.ML0)

        assert isinstance(cl1, MetagraphClient)
        assert isinstance(dl1, MetagraphClient)
        assert isinstance(ml0, MetagraphClient)
        assert cl1.layer == LayerType.CL1
        assert dl1.layer == LayerType.DL1
        assert ml0.layer == LayerType.ML0
