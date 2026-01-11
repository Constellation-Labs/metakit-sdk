package constellation

// DataL1Client is a client for interacting with Data L1 nodes (metagraphs)
//
// Example:
//
//	config := NetworkConfig{DataL1URL: "http://localhost:8080"}
//	client, err := NewDataL1Client(config)
//	if err != nil {
//	    return err
//	}
//
//	// Estimate fee for data submission
//	feeInfo, err := client.EstimateFee(signedData)
//
//	// Submit data
//	result, err := client.PostData(signedData)
type DataL1Client struct {
	client *HTTPClient
}

// NewDataL1Client creates a new DataL1Client
//
// Returns an error if DataL1URL is not provided in the config
func NewDataL1Client(config NetworkConfig) (*DataL1Client, error) {
	if config.DataL1URL == "" {
		return nil, ErrDataL1URLRequired
	}

	client := NewHTTPClient(config.DataL1URL, config.Timeout)
	return &DataL1Client{client: client}, nil
}

// EstimateFee estimates the fee for submitting data
//
// Some metagraphs charge fees for data submissions.
// Call this before PostData to know the required fee.
func (c *DataL1Client) EstimateFee(data interface{}) (*EstimateFeeResponse, error) {
	var result EstimateFeeResponse
	if err := c.client.Post("/data/estimate-fee", data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PostData submits signed data to the Data L1 node
func (c *DataL1Client) PostData(data interface{}) (*PostDataResponse, error) {
	var result PostDataResponse
	if err := c.client.Post("/data", data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckHealth checks the health/availability of the Data L1 node
func (c *DataL1Client) CheckHealth() bool {
	var result interface{}
	return c.client.Get("/cluster/info", &result) == nil
}
