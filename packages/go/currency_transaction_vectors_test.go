package constellation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/Constellation-Labs/metakit-sdk/packages/go/core"
)

// testCurrencyTransactionValue is a wrapper for test vectors that can handle salt as number or string
type testCurrencyTransactionValue struct {
	Source      string               `json:"source"`
	Destination string               `json:"destination"`
	Amount      int64                `json:"amount"`
	Fee         int64                `json:"fee"`
	Parent      TransactionReference `json:"parent"`
	Salt        json.Number          `json:"salt"` // Can be number or string in JSON
}

// toCurrencyTransactionValue converts test value to runtime value
func (t *testCurrencyTransactionValue) toCurrencyTransactionValue() CurrencyTransactionValue {
	return CurrencyTransactionValue{
		Source:      t.Source,
		Destination: t.Destination,
		Amount:      t.Amount,
		Fee:         t.Fee,
		Parent:      t.Parent,
		Salt:        string(t.Salt),
	}
}

// TestVectors represents the structure of the test vectors JSON
type TestVectors struct {
	CryptoParams struct {
		KryoSetReferences bool `json:"kryoSetReferences"`
	} `json:"cryptoParams"`
	TestVectors struct {
		BasicTransaction struct {
			PrivateKeyHex   string                        `json:"privateKeyHex"`
			PublicKeyHex    string                        `json:"publicKeyHex"`
			Address         string                        `json:"address"`
			Transaction     testCurrencyTransactionValue  `json:"transaction"`
			EncodedString   string                        `json:"encodedString"`
			KryoBytesHex    string                        `json:"kryoBytesHex"`
			TransactionHash string                        `json:"transactionHash"`
			Signature       string                        `json:"signature"`
			SignerID        string                        `json:"signerId"`
		} `json:"basicTransaction"`
		EncodingBreakdown struct {
			Components struct {
				VersionPrefix string `json:"versionPrefix"`
				Source        struct {
					Length int    `json:"length"`
					Value  string `json:"value"`
				} `json:"source"`
				Destination struct {
					Length int    `json:"length"`
					Value  string `json:"value"`
				} `json:"destination"`
				AmountHex struct {
					Length int    `json:"length"`
					Value  string `json:"value"`
				} `json:"amountHex"`
				ParentHash struct {
					Length int    `json:"length"`
					Value  string `json:"value"`
				} `json:"parentHash"`
			} `json:"components"`
			FullEncoded string `json:"fullEncoded"`
		} `json:"encodingBreakdown"`
		MultiSignature struct {
			TransactionHash string            `json:"transactionHash"`
			Proofs          []core.SignatureProof  `json:"proofs"`
		} `json:"multiSignature"`
		TransactionChaining struct {
			Transactions []struct {
				Index        int    `json:"index"`
				Hash         string `json:"hash"`
				Ordinal      int    `json:"ordinal"`
				ParentHash   string `json:"parentHash"`
				ParentOrdinal int   `json:"parentOrdinal"`
			} `json:"transactions"`
		} `json:"transactionChaining"`
		EdgeCases struct {
			MinAmount struct {
				Amount    int64  `json:"amount"`
				Hash      string `json:"hash"`
				Signature string `json:"signature"`
			} `json:"minAmount"`
			MaxAmount struct {
				Amount    int64  `json:"amount"`
				Hash      string `json:"hash"`
				Signature string `json:"signature"`
			} `json:"maxAmount"`
			WithFee struct {
				Amount    int64  `json:"amount"`
				Fee       int64  `json:"fee"`
				Hash      string `json:"hash"`
				Signature string `json:"signature"`
			} `json:"withFee"`
		} `json:"edgeCases"`
	} `json:"testVectors"`
}

func loadCurrencyTestVectors(t *testing.T) *TestVectors {
	vectorsPath := filepath.Join("..", "..", "shared", "currency_transaction_vectors.json")
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("Failed to read test vectors: %v", err)
	}

	var vectors TestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}

	return &vectors
}

func TestKeyDerivation(t *testing.T) {
	vectors := loadCurrencyTestVectors(t)
	basic := vectors.TestVectors.BasicTransaction

	t.Run("derives correct public key", func(t *testing.T) {
		privateKeyBytes, err := hex.DecodeString(basic.PrivateKeyHex)
		if err != nil {
			t.Fatalf("Failed to decode private key: %v", err)
		}

		privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
		publicKeyHex := hex.EncodeToString(privateKey.PubKey().SerializeUncompressed())

		if publicKeyHex != basic.PublicKeyHex {
			t.Errorf("Public key mismatch: got %s, want %s", publicKeyHex, basic.PublicKeyHex)
		}
	})

	t.Run("derives correct address", func(t *testing.T) {
		privateKeyBytes, err := hex.DecodeString(basic.PrivateKeyHex)
		if err != nil {
			t.Fatalf("Failed to decode private key: %v", err)
		}

		privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
		publicKeyHex := hex.EncodeToString(privateKey.PubKey().SerializeUncompressed())
		address := core.GetAddress(publicKeyHex)

		if address != basic.Address {
			t.Errorf("Address mismatch: got %s, want %s", address, basic.Address)
		}
	})
}

func TestTransactionEncoding(t *testing.T) {
	vectors := loadCurrencyTestVectors(t)
	basic := vectors.TestVectors.BasicTransaction
	txValue := basic.Transaction.toCurrencyTransactionValue()

	t.Run("encodes transaction correctly", func(t *testing.T) {
		// Create transaction with known values
		tx, err := CreateCurrencyTransaction(
			TransferParams{
				Destination: txValue.Destination,
				Amount:      float64(txValue.Amount) / 1e8,
				Fee:         float64(txValue.Fee) / 1e8,
			},
			basic.PrivateKeyHex,
			txValue.Parent,
		)
		if err != nil {
			t.Fatalf("Failed to create transaction: %v", err)
		}

		// Override salt for deterministic test
		tx.Value.Salt = txValue.Salt
		tx.Proofs = []core.SignatureProof{}

		encoded := encodeTransaction(tx)
		if encoded != basic.EncodedString {
			t.Errorf("Encoding mismatch:\ngot:  %s\nwant: %s", encoded, basic.EncodedString)
		}
	})

	t.Run("validates encoding breakdown", func(t *testing.T) {
		breakdown := vectors.TestVectors.EncodingBreakdown
		components := breakdown.Components

		// Verify version prefix
		if components.VersionPrefix != "2" {
			t.Errorf("Version prefix mismatch: got %s, want 2", components.VersionPrefix)
		}

		// Verify components are present in full encoding
		fullEncoded := breakdown.FullEncoded
		if fullEncoded[0] != '2' {
			t.Error("Encoding should start with version prefix '2'")
		}
	})
}

func TestCurrencyTransactionVectorsHashing(t *testing.T) {
	vectors := loadCurrencyTestVectors(t)
	basic := vectors.TestVectors.BasicTransaction
	txValue := basic.Transaction.toCurrencyTransactionValue()

	t.Run("produces correct transaction hash", func(t *testing.T) {
		// Create transaction with deterministic values
		tx, err := CreateCurrencyTransaction(
			TransferParams{
				Destination: txValue.Destination,
				Amount:      float64(txValue.Amount) / 1e8,
				Fee:         float64(txValue.Fee) / 1e8,
			},
			basic.PrivateKeyHex,
			txValue.Parent,
		)
		if err != nil {
			t.Fatalf("Failed to create transaction: %v", err)
		}

		// Override salt for exact match
		tx.Value.Salt = txValue.Salt
		tx.Proofs = []core.SignatureProof{}

		hash := HashCurrencyTransaction(tx)
		if hash.Value != basic.TransactionHash {
			t.Errorf("Hash mismatch:\ngot:  %s\nwant: %s", hash.Value, basic.TransactionHash)
		}
	})
}

func TestSignatureVerification(t *testing.T) {
	vectors := loadCurrencyTestVectors(t)
	basic := vectors.TestVectors.BasicTransaction
	txValue := basic.Transaction.toCurrencyTransactionValue()

	t.Run("verifies reference signature", func(t *testing.T) {
		// Reconstruct transaction from test vector
		tx := &CurrencyTransaction{
			Value: txValue,
			Proofs: []core.SignatureProof{
				{
					ID:        basic.SignerID,
					Signature: basic.Signature,
				},
			},
		}

		result := VerifyCurrencyTransaction(tx)
		if !result.IsValid {
			t.Error("Transaction should be valid")
		}
		if len(result.ValidProofs) != 1 {
			t.Errorf("Expected 1 valid proof, got %d", len(result.ValidProofs))
		}
		if len(result.InvalidProofs) != 0 {
			t.Errorf("Expected 0 invalid proofs, got %d", len(result.InvalidProofs))
		}
	})

	t.Run("verifies multi-signature transaction", func(t *testing.T) {
		multiSig := vectors.TestVectors.MultiSignature

		tx := &CurrencyTransaction{
			Value:  txValue,
			Proofs: multiSig.Proofs,
		}

		result := VerifyCurrencyTransaction(tx)
		if !result.IsValid {
			t.Error("Multi-sig transaction should be valid")
		}
		if len(result.ValidProofs) != 2 {
			t.Errorf("Expected 2 valid proofs, got %d", len(result.ValidProofs))
		}
		if len(result.InvalidProofs) != 0 {
			t.Errorf("Expected 0 invalid proofs, got %d", len(result.InvalidProofs))
		}
	})
}

func TestTransactionChaining(t *testing.T) {
	vectors := loadCurrencyTestVectors(t)
	chain := vectors.TestVectors.TransactionChaining.Transactions

	t.Run("validates chain parent references", func(t *testing.T) {
		// Verify first transaction parent
		if chain[0].ParentHash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Error("First transaction parent hash mismatch")
		}
		if chain[0].ParentOrdinal != 5 {
			t.Errorf("First transaction parent ordinal: got %d, want 5", chain[0].ParentOrdinal)
		}
		if chain[0].Ordinal != 6 {
			t.Errorf("First transaction ordinal: got %d, want 6", chain[0].Ordinal)
		}

		// Verify second transaction chains to first
		if chain[1].ParentHash != chain[0].Hash {
			t.Error("Second transaction should chain to first")
		}
		if chain[1].ParentOrdinal != chain[0].Ordinal {
			t.Error("Second transaction parent ordinal should match first ordinal")
		}
		if chain[1].Ordinal != 7 {
			t.Errorf("Second transaction ordinal: got %d, want 7", chain[1].Ordinal)
		}

		// Verify third transaction chains to second
		if chain[2].ParentHash != chain[1].Hash {
			t.Error("Third transaction should chain to second")
		}
		if chain[2].ParentOrdinal != chain[1].Ordinal {
			t.Error("Third transaction parent ordinal should match second ordinal")
		}
		if chain[2].Ordinal != 8 {
			t.Errorf("Third transaction ordinal: got %d, want 8", chain[2].Ordinal)
		}
	})
}

func TestEdgeCases(t *testing.T) {
	vectors := loadCurrencyTestVectors(t)
	edgeCases := vectors.TestVectors.EdgeCases

	t.Run("validates minimum amount", func(t *testing.T) {
		minAmount := edgeCases.MinAmount
		if minAmount.Amount != 1 {
			t.Errorf("Min amount: got %d, want 1", minAmount.Amount)
		}
		if minAmount.Hash == "" {
			t.Error("Min amount hash should not be empty")
		}
		if minAmount.Signature == "" {
			t.Error("Min amount signature should not be empty")
		}
	})

	t.Run("validates maximum amount", func(t *testing.T) {
		maxAmount := edgeCases.MaxAmount
		if maxAmount.Amount != 9223372036854775807 {
			t.Errorf("Max amount: got %d, want 9223372036854775807", maxAmount.Amount)
		}
		if maxAmount.Hash == "" {
			t.Error("Max amount hash should not be empty")
		}
		if maxAmount.Signature == "" {
			t.Error("Max amount signature should not be empty")
		}
	})

	t.Run("validates non-zero fee", func(t *testing.T) {
		withFee := edgeCases.WithFee
		if withFee.Amount != 10000000000 {
			t.Errorf("Fee amount: got %d, want 10000000000", withFee.Amount)
		}
		if withFee.Fee != 100000 {
			t.Errorf("Fee: got %d, want 100000", withFee.Fee)
		}
		if withFee.Hash == "" {
			t.Error("Fee hash should not be empty")
		}
		if withFee.Signature == "" {
			t.Error("Fee signature should not be empty")
		}
	})
}

func TestKryoSerialization(t *testing.T) {
	vectors := loadCurrencyTestVectors(t)

	t.Run("validates setReferences flag (v2 format)", func(t *testing.T) {
		if vectors.CryptoParams.KryoSetReferences {
			t.Error("Kryo setReferences should be false for v2 transactions")
		}
	})

	t.Run("validates Kryo header without reference flag (v2 format)", func(t *testing.T) {
		basic := vectors.TestVectors.BasicTransaction
		kryoHex := basic.KryoBytesHex
		// Should start with 0x03 (string type) followed by length, no 0x01 reference flag for v2
		if !strings.HasPrefix(kryoHex, "03") {
			t.Errorf("Kryo header should start with 03, got %s", kryoHex[:2])
		}
		if strings.HasPrefix(kryoHex, "0301") {
			t.Error("Kryo header should NOT have reference flag (0301) for v2 transactions")
		}
	})
}
