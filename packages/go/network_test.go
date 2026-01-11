package constellation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrencyL1ClientRequiresL1URL(t *testing.T) {
	config := NetworkConfig{}
	_, err := NewCurrencyL1Client(config)
	assert.ErrorIs(t, err, ErrL1URLRequired)
}

func TestCurrencyL1ClientCreatesWithValidConfig(t *testing.T) {
	config := NetworkConfig{L1URL: "http://localhost:9010"}
	client, err := NewCurrencyL1Client(config)
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestCurrencyL1ClientAcceptsOptionalTimeout(t *testing.T) {
	config := NetworkConfig{
		L1URL:   "http://localhost:9010",
		Timeout: 5,
	}
	client, err := NewCurrencyL1Client(config)
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestDataL1ClientRequiresDataL1URL(t *testing.T) {
	config := NetworkConfig{}
	_, err := NewDataL1Client(config)
	assert.ErrorIs(t, err, ErrDataL1URLRequired)
}

func TestDataL1ClientCreatesWithValidConfig(t *testing.T) {
	config := NetworkConfig{DataL1URL: "http://localhost:8080"}
	client, err := NewDataL1Client(config)
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestDataL1ClientAcceptsOptionalTimeout(t *testing.T) {
	config := NetworkConfig{
		DataL1URL: "http://localhost:8080",
		Timeout:   10,
	}
	client, err := NewDataL1Client(config)
	assert.NoError(t, err)
	assert.NotNil(t, client)
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

func TestCombinedConfigBothURLs(t *testing.T) {
	config := NetworkConfig{
		L1URL:     "http://localhost:9010",
		DataL1URL: "http://localhost:8080",
		Timeout:   30,
	}

	l1Client, err := NewCurrencyL1Client(config)
	assert.NoError(t, err)
	assert.NotNil(t, l1Client)

	dataClient, err := NewDataL1Client(config)
	assert.NoError(t, err)
	assert.NotNil(t, dataClient)
}
