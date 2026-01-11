package constellation

import (
	"errors"
	"fmt"
)

// NetworkConfig holds configuration for connecting to L1 nodes
type NetworkConfig struct {
	// L1URL is the Currency L1 endpoint URL (e.g., "http://localhost:9010")
	L1URL string
	// DataL1URL is the Data L1 endpoint URL (e.g., "http://localhost:8080")
	DataL1URL string
	// Timeout is the request timeout in seconds (default: 30)
	Timeout int
}

// RequestOptions holds options for individual requests
type RequestOptions struct {
	// Timeout is the request timeout in seconds
	Timeout int
}

// TransactionStatus represents the status of a transaction in the network
type TransactionStatus string

const (
	StatusWaiting    TransactionStatus = "Waiting"
	StatusInProgress TransactionStatus = "InProgress"
	StatusAccepted   TransactionStatus = "Accepted"
)

// PendingTransaction represents a pending transaction response from L1
type PendingTransaction struct {
	// Hash is the transaction hash
	Hash string `json:"hash"`
	// Status is the current status
	Status TransactionStatus `json:"status"`
	// Transaction is the transaction data
	Transaction CurrencyTransaction `json:"transaction"`
}

// PostTransactionResponse is the response from posting a transaction
type PostTransactionResponse struct {
	// Hash is the transaction hash
	Hash string `json:"hash"`
}

// EstimateFeeResponse is the response from estimating data transaction fee
type EstimateFeeResponse struct {
	// Fee is the estimated fee in smallest units
	Fee int64 `json:"fee"`
	// Address is the fee destination address
	Address string `json:"address"`
}

// PostDataResponse is the response from posting data
type PostDataResponse struct {
	// Hash is the data hash
	Hash string `json:"hash"`
}

// NetworkError represents a network operation error
type NetworkError struct {
	Message    string
	StatusCode int
	Response   string
}

func (e *NetworkError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s (status: %d)", e.Message, e.StatusCode)
	}
	return e.Message
}

// NewNetworkError creates a new NetworkError
func NewNetworkError(message string, statusCode int, response string) *NetworkError {
	return &NetworkError{
		Message:    message,
		StatusCode: statusCode,
		Response:   response,
	}
}

// Common network errors
var (
	ErrL1URLRequired     = errors.New("L1URL is required for CurrencyL1Client")
	ErrDataL1URLRequired = errors.New("DataL1URL is required for DataL1Client")
	ErrRequestTimeout    = errors.New("request timeout")
)
