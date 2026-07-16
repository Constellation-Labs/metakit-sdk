package constellation

import "github.com/Constellation-Labs/metakit-sdk/packages/go/core"

// TokenDecimals is the token decimals constant (1e-8)
// Same as DAG_DECIMALS from dag4.js
const TokenDecimals = 1e-8

// TransactionReference refers to a previous transaction for chaining
type TransactionReference struct {
	// Hash is the transaction hash (64-character hex string)
	Hash string `json:"hash"`
	// Ordinal is the transaction ordinal number
	Ordinal int `json:"ordinal"`
}

// CurrencyTransactionValue holds the transaction data before signing
type CurrencyTransactionValue struct {
	// Source is the source DAG address
	Source string `json:"source"`
	// Destination is the destination DAG address
	Destination string `json:"destination"`
	// Amount in smallest units (1e-8)
	Amount int64 `json:"amount"`
	// Fee in smallest units (1e-8)
	Fee int64 `json:"fee"`
	// Parent is the reference to parent transaction
	Parent TransactionReference `json:"parent"`
	// Salt is a random salt for uniqueness (as string)
	Salt string `json:"salt"`
}

// CurrencyTransaction represents a v2 currency transaction for metagraph token transfers
// A signed currency transaction value
type CurrencyTransaction = core.Signed[CurrencyTransactionValue]

// TransferParams holds parameters for creating a token transfer
type TransferParams struct {
	// Destination is the destination DAG address
	Destination string
	// Amount in token units (e.g., 100.5 tokens)
	Amount float64
	// Fee in token units (defaults to 0)
	Fee float64
}
