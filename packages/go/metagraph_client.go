package constellation

import (
	"fmt"
)

// LayerType represents the supported L1 layer types
type LayerType string

const (
	// LayerML0 represents Metagraph L0 - state channel operations
	LayerML0 LayerType = "ml0"
	// LayerCL1 represents Currency L1 - currency transactions
	LayerCL1 LayerType = "cl1"
	// LayerDL1 represents Data L1 - data/update submissions
	LayerDL1 LayerType = "dl1"
)

// String returns the uppercase string representation of the layer type
func (l LayerType) String() string {
	switch l {
	case LayerML0:
		return "ML0"
	case LayerCL1:
		return "CL1"
	case LayerDL1:
		return "DL1"
	default:
		return string(l)
	}
}

// ClusterInfo represents cluster information from any L1 node
type ClusterInfo struct {
	Size      *int    `json:"size,omitempty"`
	ClusterID *string `json:"clusterId,omitempty"`
}

// MetagraphClientConfig is the configuration for MetagraphClient
type MetagraphClientConfig struct {
	// BaseURL is the base URL of the L1 node (e.g., "http://localhost:9200")
	BaseURL string
	// Layer is the layer type for API path selection
	Layer LayerType
	// Timeout is the request timeout in milliseconds (default: 30000)
	Timeout int
}

// MetagraphClient is a generic client for interacting with any Metagraph L1 layer
//
// This client provides a unified interface for ML0, CL1, and DL1 nodes,
// automatically selecting the correct API paths based on layer type.
//
// Example:
//
//	// Connect to a Currency L1 node
//	cl1, err := NewMetagraphClient("http://localhost:9300", LayerCL1)
//
//	// Connect to a Data L1 node
//	dl1, err := NewMetagraphClient("http://localhost:9400", LayerDL1)
//
//	// Connect to a Metagraph L0 node
//	ml0, err := NewMetagraphClient("http://localhost:9200", LayerML0)
type MetagraphClient struct {
	client *HTTPClient
	layer  LayerType
}

// NewMetagraphClient creates a new MetagraphClient
//
// Arguments:
//   - baseURL: Base URL of the L1 node
//   - layer: Layer type (ML0, CL1, or DL1)
//
// Returns an error if the HTTP client cannot be initialized
func NewMetagraphClient(baseURL string, layer LayerType) (*MetagraphClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL is required for MetagraphClient")
	}
	if layer == "" {
		return nil, fmt.Errorf("layer is required for MetagraphClient")
	}

	client := NewHTTPClient(baseURL, 0)
	return &MetagraphClient{client: client, layer: layer}, nil
}

// NewMetagraphClientWithConfig creates a new MetagraphClient with full configuration
func NewMetagraphClientWithConfig(config MetagraphClientConfig) (*MetagraphClient, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required for MetagraphClient")
	}
	if config.Layer == "" {
		return nil, fmt.Errorf("Layer is required for MetagraphClient")
	}

	client := NewHTTPClient(config.BaseURL, config.Timeout)
	return &MetagraphClient{client: client, layer: config.Layer}, nil
}

// Layer returns the layer type of this client
func (c *MetagraphClient) Layer() LayerType {
	return c.layer
}

// ============================================
// Common operations (all layers)
// ============================================

// CheckHealth checks the health/availability of the node
func (c *MetagraphClient) CheckHealth() bool {
	var result interface{}
	return c.client.Get("/cluster/info", &result) == nil
}

// GetClusterInfo gets cluster information
func (c *MetagraphClient) GetClusterInfo() (*ClusterInfo, error) {
	var result ClusterInfo
	if err := c.client.Get("/cluster/info", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================
// Currency operations (CL1 and ML0)
// ============================================

// GetLastReference gets the last accepted transaction reference for an address
//
// This is needed to create a new transaction that chains from
// the address's most recent transaction.
//
// Available on: CL1, ML0 (if currency enabled)
//
// Returns an error if called on an unsupported layer
func (c *MetagraphClient) GetLastReference(address string) (*TransactionReference, error) {
	if err := c.assertLayer([]LayerType{LayerCL1, LayerML0}, "GetLastReference"); err != nil {
		return nil, err
	}

	var result TransactionReference
	path := fmt.Sprintf("/transactions/last-reference/%s", address)
	if err := c.client.Get(path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PostTransaction submits a signed currency transaction
//
// Available on: CL1
//
// Returns an error if called on an unsupported layer
func (c *MetagraphClient) PostTransaction(transaction *CurrencyTransaction) (*PostTransactionResponse, error) {
	if err := c.assertLayer([]LayerType{LayerCL1}, "PostTransaction"); err != nil {
		return nil, err
	}

	var result PostTransactionResponse
	if err := c.client.Post("/transactions", transaction, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPendingTransaction gets a pending transaction by hash
//
// Available on: CL1
//
// Returns an error if called on an unsupported layer
func (c *MetagraphClient) GetPendingTransaction(hash string) (*PendingTransaction, error) {
	if err := c.assertLayer([]LayerType{LayerCL1}, "GetPendingTransaction"); err != nil {
		return nil, err
	}

	var result PendingTransaction
	path := fmt.Sprintf("/transactions/%s", hash)
	if err := c.client.Get(path, &result); err != nil {
		if netErr, ok := err.(*NetworkError); ok && netErr.StatusCode == 404 {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

// ============================================
// Data operations (DL1)
// ============================================

// EstimateFee estimates the fee for submitting data
//
// Available on: DL1
//
// Returns an error if called on an unsupported layer
func (c *MetagraphClient) EstimateFee(data interface{}) (*EstimateFeeResponse, error) {
	if err := c.assertLayer([]LayerType{LayerDL1}, "EstimateFee"); err != nil {
		return nil, err
	}

	var result EstimateFeeResponse
	if err := c.client.Post("/data/estimate-fee", data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PostData submits signed data to the Data L1 node
//
// Available on: DL1
//
// Returns an error if called on an unsupported layer
func (c *MetagraphClient) PostData(data interface{}) (*PostDataResponse, error) {
	if err := c.assertLayer([]LayerType{LayerDL1}, "PostData"); err != nil {
		return nil, err
	}

	var result PostDataResponse
	if err := c.client.Post("/data", data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================
// Raw HTTP access
// ============================================

// Get makes a raw GET request to the node
func (c *MetagraphClient) Get(path string, result interface{}) error {
	return c.client.Get(path, result)
}

// Post makes a raw POST request to the node
func (c *MetagraphClient) Post(path string, body interface{}, result interface{}) error {
	return c.client.Post(path, body, result)
}

// ============================================
// Helpers
// ============================================

func (c *MetagraphClient) assertLayer(allowed []LayerType, method string) error {
	for _, l := range allowed {
		if c.layer == l {
			return nil
		}
	}

	allowedStr := ""
	for i, l := range allowed {
		if i > 0 {
			allowedStr += ", "
		}
		allowedStr += l.String()
	}

	return fmt.Errorf(
		"%s() is not available on %s layer. Available on: %s",
		method, c.layer.String(), allowedStr,
	)
}

// CreateMetagraphClient creates a MetagraphClient for a specific layer
//
// Arguments:
//   - baseURL: Node URL
//   - layer: Layer type
//
// Example:
//
//	client, err := CreateMetagraphClient("http://localhost:9400", LayerDL1)
func CreateMetagraphClient(baseURL string, layer LayerType) (*MetagraphClient, error) {
	return NewMetagraphClient(baseURL, layer)
}
