package constellation

import "fmt"

// CurrencyL1Client is a client for interacting with Currency L1 nodes
//
// Example:
//
//	config := NetworkConfig{L1URL: "http://localhost:9010"}
//	client, err := NewCurrencyL1Client(config)
//	if err != nil {
//	    return err
//	}
//
//	// Get last reference for an address
//	lastRef, err := client.GetLastReference("DAG...")
//
//	// Submit a transaction
//	result, err := client.PostTransaction(signedTx)
//
//	// Check transaction status
//	pending, err := client.GetPendingTransaction(result.Hash)
type CurrencyL1Client struct {
	client *HTTPClient
}

// NewCurrencyL1Client creates a new CurrencyL1Client
//
// Returns an error if L1URL is not provided in the config
func NewCurrencyL1Client(config NetworkConfig) (*CurrencyL1Client, error) {
	if config.L1URL == "" {
		return nil, ErrL1URLRequired
	}

	client := NewHTTPClient(config.L1URL, config.Timeout)
	return &CurrencyL1Client{client: client}, nil
}

// GetLastReference gets the last accepted transaction reference for an address
//
// This is needed to create a new transaction that chains from
// the address's most recent transaction.
func (c *CurrencyL1Client) GetLastReference(address string) (*TransactionReference, error) {
	var result TransactionReference
	path := fmt.Sprintf("/transactions/last-reference/%s", address)
	if err := c.client.Get(path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PostTransaction submits a signed currency transaction to the L1 network
func (c *CurrencyL1Client) PostTransaction(transaction *CurrencyTransaction) (*PostTransactionResponse, error) {
	var result PostTransactionResponse
	if err := c.client.Post("/transactions", transaction, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPendingTransaction gets a pending transaction by hash
//
// Use this to poll for transaction status after submission.
// Returns nil if the transaction is not found (already confirmed or invalid).
func (c *CurrencyL1Client) GetPendingTransaction(hash string) (*PendingTransaction, error) {
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

// CheckHealth checks the health/availability of the L1 node
func (c *CurrencyL1Client) CheckHealth() bool {
	var result interface{}
	return c.client.Get("/cluster/info", &result) == nil
}
