package constellation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetagraphClientRequiresBaseURL(t *testing.T) {
	_, err := NewMetagraphClient("", LayerDL1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "baseURL is required")
}

func TestMetagraphClientRequiresLayer(t *testing.T) {
	_, err := NewMetagraphClient("http://localhost:9400", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "layer is required")
}

func TestMetagraphClientCreatesForDL1(t *testing.T) {
	client, err := NewMetagraphClient("http://localhost:9400", LayerDL1)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, LayerDL1, client.Layer())
}

func TestMetagraphClientCreatesForCL1(t *testing.T) {
	client, err := NewMetagraphClient("http://localhost:9300", LayerCL1)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, LayerCL1, client.Layer())
}

func TestMetagraphClientCreatesForML0(t *testing.T) {
	client, err := NewMetagraphClient("http://localhost:9200", LayerML0)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, LayerML0, client.Layer())
}

func TestMetagraphClientWithConfigTimeout(t *testing.T) {
	config := MetagraphClientConfig{
		BaseURL: "http://localhost:9400",
		Layer:   LayerDL1,
		Timeout: 5000,
	}
	client, err := NewMetagraphClientWithConfig(config)
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestLayerTypeString(t *testing.T) {
	assert.Equal(t, "ML0", LayerML0.String())
	assert.Equal(t, "CL1", LayerCL1.String())
	assert.Equal(t, "DL1", LayerDL1.String())
}

func TestNetworkErrorMessage(t *testing.T) {
	err := NewNetworkError("Connection failed", 0, "")
	assert.Equal(t, "Connection failed", err.Error())
	assert.Equal(t, 0, err.StatusCode)
}

func TestNetworkErrorWithStatusCode(t *testing.T) {
	err := NewNetworkError("Not found", 404, "")
	assert.Contains(t, err.Error(), "Not found")
	assert.Contains(t, err.Error(), "404")
	assert.Equal(t, 404, err.StatusCode)
}

func TestNetworkErrorWithResponseBody(t *testing.T) {
	err := NewNetworkError("Bad request", 400, `{"error":"invalid"}`)
	assert.Equal(t, 400, err.StatusCode)
	assert.Equal(t, `{"error":"invalid"}`, err.Response)
}

func TestMultipleClientsForDifferentLayers(t *testing.T) {
	cl1, err := NewMetagraphClient("http://localhost:9300", LayerCL1)
	assert.NoError(t, err)
	assert.NotNil(t, cl1)

	dl1, err := NewMetagraphClient("http://localhost:9400", LayerDL1)
	assert.NoError(t, err)
	assert.NotNil(t, dl1)

	ml0, err := NewMetagraphClient("http://localhost:9200", LayerML0)
	assert.NoError(t, err)
	assert.NotNil(t, ml0)

	assert.Equal(t, LayerCL1, cl1.Layer())
	assert.Equal(t, LayerDL1, dl1.Layer())
	assert.Equal(t, LayerML0, ml0.Layer())
}
