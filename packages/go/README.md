# Constellation Metagraph SDK - Go

Go SDK for signing data and currency transactions on Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:** This SDK supports both data transactions (state updates) and metagraph token transactions (value transfers). It implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

## Installation

```bash
go get github.com/Constellation-Labs/metakit-sdk/packages/go
```

## Quick Start

```go
package main

import (
    "fmt"
    constellation "github.com/Constellation-Labs/metakit-sdk/packages/go"
)

func main() {
    // Generate a key pair
    keyPair, err := constellation.GenerateKeyPair()
    if err != nil {
        panic(err)
    }
    fmt.Println("Address:", keyPair.Address)

    // Sign data
    data := map[string]interface{}{
        "action": "UPDATE",
        "payload": map[string]interface{}{"key": "value"},
    }
    signed, err := constellation.CreateSignedObject(data, keyPair.PrivateKey, false)
    if err != nil {
        panic(err)
    }

    // Verify
    result := constellation.Verify(signed, false)
    fmt.Println("Valid:", result.IsValid)
}
```

## API Reference

### High-Level API

#### `CreateSignedObject(value, privateKey, isDataUpdate) (*Signed, error)`

Create a signed object with a single signature.

```go
signed, err := constellation.CreateSignedObject(data, privateKey, false)

// For L1 submission (DataUpdate)
signed, err := constellation.CreateSignedObject(data, privateKey, true)
```

#### `AddSignature(signed, privateKey, isDataUpdate) (*Signed, error)`

Add an additional signature to an existing signed object.

```go
signed, _ := constellation.CreateSignedObject(data, party1Key, false)
signed, _ = constellation.AddSignature(signed, party2Key, false)
// len(signed.Proofs) == 2
```

#### `BatchSign(value, privateKeys, isDataUpdate) (*Signed, error)`

Create a signed object with multiple signatures at once.

```go
signed, _ := constellation.BatchSign(data, []string{key1, key2, key3}, false)
// len(signed.Proofs) == 3
```

#### `Verify(signed, isDataUpdate) *VerificationResult`

Verify all signatures on a signed object.

```go
result := constellation.Verify(signed, false)
if result.IsValid {
    fmt.Println("All signatures valid")
} else {
    fmt.Println("Invalid proofs:", result.InvalidProofs)
}
```

### Low-Level Primitives

#### `Canonicalize(data) (string, error)`

Canonicalize JSON data according to RFC 8785.

```go
canonical, _ := constellation.Canonicalize(map[string]int{"b": 2, "a": 1})
// `{"a":1,"b":2}`
```

#### `ToBytes(data, isDataUpdate) ([]byte, error)`

Convert data to binary bytes for signing.

```go
// Regular encoding
bytes, _ := constellation.ToBytes(data, false)

// DataUpdate encoding (with Constellation prefix)
bytes, _ := constellation.ToBytes(data, true)
```

#### `HashData(data) (*Hash, error)` / `HashBytes(bytes) *Hash`

Compute SHA-256 hash.

```go
hash, _ := constellation.HashData(data)
fmt.Println(hash.Value)  // 64-char hex
fmt.Println(hash.Bytes)  // [32]byte
```

#### `Sign(data, privateKey)` / `SignDataUpdate(data, privateKey)`

Sign data and return a proof.

```go
proof, _ := constellation.Sign(data, privateKey)
// SignatureProof{ID: "...", Signature: "..."}
```

#### `SignHash(hashHex, privateKey) (string, error)`

Sign a pre-computed hash.

```go
hash, _ := constellation.HashData(data)
signature, _ := constellation.SignHash(hash.Value, privateKey)
```

### Wallet Utilities

#### `GenerateKeyPair() (*KeyPair, error)`

Generate a new random key pair.

```go
keyPair, _ := constellation.GenerateKeyPair()
// KeyPair{PrivateKey, PublicKey, Address}
```

#### `KeyPairFromPrivateKey(privateKey) (*KeyPair, error)`

Derive a key pair from an existing private key.

```go
keyPair, _ := constellation.KeyPairFromPrivateKey(existingPrivateKey)
```

#### `GetPublicKeyID(privateKey) (string, error)`

Get the public key ID (128 chars, no 04 prefix) for use in proofs.

```go
id, _ := constellation.GetPublicKeyID(privateKey)
```

### Currency Transactions

#### `CreateCurrencyTransaction(params TransferParams, privateKey string, lastRef TransactionReference) (*CurrencyTransaction, error)`

Create a metagraph token transaction.

```go
tx, err := constellation.CreateCurrencyTransaction(
    constellation.TransferParams{
        Destination: "DAG88C9WDSKH5CYZTCEOZD...",
        Amount:      100.5, // Tokens
        Fee:         0,
    },
    privateKey,
    constellation.TransactionReference{Hash: "parent_hash...", Ordinal: 5},
)
```

#### `VerifyCurrencyTransaction(transaction *CurrencyTransaction) *VerificationResult`

Verify all signatures on a currency transaction.

```go
result := constellation.VerifyCurrencyTransaction(tx)
if result.IsValid {
    fmt.Printf("Valid: %d proofs\n", len(result.ValidProofs))
}
```

#### `SignCurrencyTransaction(transaction *CurrencyTransaction, privateKey string) (*CurrencyTransaction, error)`

Add an additional signature to a currency transaction (multi-sig).

```go
// Add second signature
txMultiSig, err := constellation.SignCurrencyTransaction(tx, privateKey2)
// txMultiSig.Proofs has 2 signatures now
```

#### `CreateCurrencyTransactionBatch(transfers []TransferParams, privateKey string, lastRef TransactionReference) ([]*CurrencyTransaction, error)`

Create multiple currency transactions in a batch.

```go
transactions, err := constellation.CreateCurrencyTransactionBatch(
    []constellation.TransferParams{
        {Destination: "DAG...1", Amount: 10, Fee: 0},
        {Destination: "DAG...2", Amount: 20, Fee: 0},
    },
    privateKey,
    lastRef,
)
```

#### `HashCurrencyTransaction(transaction *CurrencyTransaction) *Hash`

Hash a currency transaction.

```go
hash := constellation.HashCurrencyTransaction(tx)
fmt.Println("Hash:", hash.Value)
```

#### `IsValidDAGAddress(address string) bool`

Validate a DAG address format.

```go
if constellation.IsValidDAGAddress("DAG88C9WDSKH5CYZTCEOZD...") {
    fmt.Println("Valid address")
}
```

#### `TokenToUnits(amount float64) int64` / `UnitsToToken(units int64) float64`

Convert between token amounts and smallest units (1e-8).

```go
units := constellation.TokenToUnits(100.5)       // 10050000000
tokens := constellation.UnitsToToken(10050000000) // 100.5
```

## Types

```go
type SignatureProof struct {
    ID        string `json:"id"`        // Public key (128 chars)
    Signature string `json:"signature"` // DER signature hex
}

type Signed struct {
    Value  interface{}      `json:"value"`
    Proofs []SignatureProof `json:"proofs"`
}

type KeyPair struct {
    PrivateKey string
    PublicKey  string
    Address    string
}

type Hash struct {
    Value string   // 64-char hex
    Bytes [32]byte // 32 bytes
}

type VerificationResult struct {
    IsValid       bool
    ValidProofs   []SignatureProof
    InvalidProofs []SignatureProof
}
```

## Usage Examples

### Submit DataUpdate to L1

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"

    constellation "github.com/Constellation-Labs/metakit-sdk/packages/go"
)

func main() {
    dataUpdate := map[string]interface{}{
        "action": "TRANSFER",
        "from":   "address1",
        "to":     "address2",
        "amount": 100,
    }

    // Sign as DataUpdate
    signed, _ := constellation.CreateSignedObject(dataUpdate, privateKey, true)

    // Submit to data-l1
    body, _ := json.Marshal(signed)
    http.Post("http://l1-node:9300/data", "application/json", bytes.NewReader(body))
}
```

### Multi-Signature Workflow

```go
package main

import (
    "fmt"
    constellation "github.com/Constellation-Labs/metakit-sdk/packages/go"
)

func main() {
    data := map[string]interface{}{"action": "multisig-test"}

    // Party 1 creates and signs
    signed, _ := constellation.CreateSignedObject(data, party1Key, false)

    // Party 2 adds signature
    signed, _ = constellation.AddSignature(signed, party2Key, false)

    // Party 3 adds signature
    signed, _ = constellation.AddSignature(signed, party3Key, false)

    // Verify all signatures
    result := constellation.Verify(signed, false)
    fmt.Printf("%d valid signatures\n", len(result.ValidProofs))
}
```

## Development

```bash
# Run tests
go test -v ./...

# Run specific test
go test -v -run TestSign

# Check for issues
go vet ./...

# Format code
go fmt ./...

# Build
go build ./...
```

## License

Apache-2.0
