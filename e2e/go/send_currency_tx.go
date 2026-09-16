// Simple script to send a currency transaction to a local metagraph.
//
// Reads configuration from config.json and submits a currency transaction
// to the Currency L1 endpoint.
//
// Usage:
//
//	go run send_currency_tx.go
//	go run send_currency_tx.go -config other_config.json
//	go run send_currency_tx.go -generate-keypair
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	constellation "github.com/Constellation-Labs/metakit-sdk/packages/go"
	"github.com/Constellation-Labs/metakit-sdk/packages/go/core"
)

type Config struct {
	PrivateKey    string  `json:"private_key"`
	Destination   string  `json:"destination"`
	Amount        float64 `json:"amount"`
	Fee           float64 `json:"fee"`
	CurrencyL1URL string  `json:"currency_l1_url"`
}

func loadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func generateKeypairCommand() {
	keypair, err := core.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generated new keypair:")
	fmt.Printf("  Private Key: %s\n", keypair.PrivateKey)
	fmt.Printf("  Public Key:  %s\n", keypair.PublicKey)
	fmt.Printf("  DAG Address: %s\n", keypair.Address)
	fmt.Println("\nSave the private key to your config.json to use it for transactions.")
}

func sendTransaction(config *Config) {
	// Validate config
	if config.PrivateKey == "" {
		fmt.Println("Error: Missing required field 'private_key' in config")
		os.Exit(1)
	}
	if config.Destination == "" {
		fmt.Println("Error: Missing required field 'destination' in config")
		os.Exit(1)
	}
	if config.CurrencyL1URL == "" {
		fmt.Println("Error: Missing required field 'currency_l1_url' in config")
		os.Exit(1)
	}

	privateKey := config.PrivateKey
	destination := config.Destination
	amount := config.Amount
	fee := config.Fee
	currencyL1URL := config.CurrencyL1URL

	// Validate private key format
	if privateKey == "YOUR_64_CHAR_HEX_PRIVATE_KEY_HERE" {
		fmt.Println("Error: Please set your private key in config.json")
		fmt.Println("Run with -generate-keypair to create a new keypair")
		os.Exit(1)
	}

	if len(privateKey) != 64 {
		fmt.Printf("Error: Private key must be 64 hex characters, got %d\n", len(privateKey))
		os.Exit(1)
	}

	// Derive address from private key
	keypair, err := core.KeyPairFromPrivateKey(privateKey)
	if err != nil {
		fmt.Printf("Error deriving keypair: %v\n", err)
		os.Exit(1)
	}
	sourceAddress := keypair.Address

	fmt.Printf("Source Address: %s\n", sourceAddress)
	fmt.Printf("Destination:    %s\n", destination)
	fmt.Printf("Amount:         %v tokens\n", amount)
	fmt.Printf("Fee:            %v tokens\n", fee)
	fmt.Printf("Currency L1:    %s\n", currencyL1URL)
	fmt.Println()

	// Create client
	client, err := constellation.NewMetagraphClient(currencyL1URL, constellation.LayerCL1)
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		os.Exit(1)
	}

	// Check health
	fmt.Println("Checking node health...")
	if !client.CheckHealth() {
		fmt.Println("Error: Currency L1 node is not responding")
		os.Exit(1)
	}
	fmt.Println("Node is healthy!")
	fmt.Println()

	// Get last reference
	fmt.Printf("Fetching last reference for %s...\n", sourceAddress)
	lastRef, err := client.GetLastReference(sourceAddress)
	if err != nil {
		fmt.Printf("Error getting last reference: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Last Reference Hash:    %s\n", lastRef.Hash)
	fmt.Printf("Last Reference Ordinal: %d\n", lastRef.Ordinal)
	fmt.Println()

	// Create transaction
	fmt.Println("Creating transaction...")
	transferParams := constellation.TransferParams{
		Destination: destination,
		Amount:      amount,
		Fee:         fee,
	}
	tx, err := constellation.CreateCurrencyTransaction(transferParams, privateKey, *lastRef)
	if err != nil {
		fmt.Printf("Error creating transaction: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Transaction created successfully!")

	// Verify transaction locally
	fmt.Println("Verifying transaction signature...")
	result := constellation.VerifyCurrencyTransaction(tx)
	if !result.IsValid {
		fmt.Println("Error: Transaction signature verification failed!")
		os.Exit(1)
	}
	fmt.Println("Signature verified!")
	fmt.Println()

	// Submit transaction
	fmt.Println("Submitting transaction to network...")
	response, err := client.PostTransaction(tx)
	if err != nil {
		fmt.Printf("Error submitting transaction: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Transaction submitted!")
	fmt.Printf("Transaction Hash: %s\n", response.Hash)
	fmt.Println()

	// Poll for status (optional)
	fmt.Println("Checking transaction status...")
	pending, err := client.GetPendingTransaction(response.Hash)
	if err != nil {
		fmt.Printf("Could not check status: %v\n", err)
	} else if pending != nil {
		fmt.Printf("Status: %s\n", pending.Status)
	} else {
		fmt.Println("Transaction not found in pending pool (may already be confirmed)")
	}

	fmt.Println()
	fmt.Println("Done!")
}

func main() {
	configFile := flag.String("config", "config.json", "Path to config file")
	generateKeypair := flag.Bool("generate-keypair", false, "Generate a new keypair and exit")
	flag.Parse()

	if *generateKeypair {
		generateKeypairCommand()
		return
	}

	// Get the directory of the executable/script
	execPath, err := os.Executable()
	if err != nil {
		// Fallback to working directory
		execPath, _ = os.Getwd()
	}
	scriptDir := filepath.Dir(execPath)

	// For `go run`, use the source file's directory instead
	if args := os.Args; len(args) > 0 {
		// Check if running via `go run`
		if _, err := os.Stat(filepath.Join(scriptDir, *configFile)); os.IsNotExist(err) {
			// Try current working directory
			cwd, _ := os.Getwd()
			scriptDir = cwd
		}
	}

	configPath := filepath.Join(scriptDir, *configFile)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("Error: Config file not found: %s\n", configPath)
		os.Exit(1)
	}

	config, err := loadConfig(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	sendTransaction(config)
}
