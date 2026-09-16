package constellation

import (
	"testing"

	"github.com/Constellation-Labs/metakit-sdk/packages/go/core"
)

func TestUtilityFunctions(t *testing.T) {
	t.Run("TokenToUnits converts correctly", func(t *testing.T) {
		if TokenToUnits(100.5) != 10050000000 {
			t.Errorf("TokenToUnits(100.5) = %d, want 10050000000", TokenToUnits(100.5))
		}
		if TokenToUnits(0.00000001) != 1 {
			t.Errorf("TokenToUnits(0.00000001) = %d, want 1", TokenToUnits(0.00000001))
		}
		if TokenToUnits(1) != 100000000 {
			t.Errorf("TokenToUnits(1) = %d, want 100000000", TokenToUnits(1))
		}
	})

	t.Run("UnitsToToken converts correctly", func(t *testing.T) {
		if UnitsToToken(10050000000) != 100.5 {
			t.Errorf("UnitsToToken(10050000000) = %f, want 100.5", UnitsToToken(10050000000))
		}
		if UnitsToToken(1) != 0.00000001 {
			t.Errorf("UnitsToToken(1) = %f, want 0.00000001", UnitsToToken(1))
		}
		if UnitsToToken(100000000) != 1.0 {
			t.Errorf("UnitsToToken(100000000) = %f, want 1.0", UnitsToToken(100000000))
		}
	})

	t.Run("TokenDecimals constant", func(t *testing.T) {
		if TokenDecimals != 1e-8 {
			t.Errorf("TokenDecimals = %f, want 1e-8", TokenDecimals)
		}
	})

	t.Run("IsValidDAGAddress validates addresses", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		if !IsValidDAGAddress(keyPair.Address) {
			t.Errorf("IsValidDAGAddress(%s) = false, want true", keyPair.Address)
		}
		if IsValidDAGAddress("invalid") {
			t.Error("IsValidDAGAddress('invalid') = true, want false")
		}
		if IsValidDAGAddress("") {
			t.Error("IsValidDAGAddress('') = true, want false")
		}
	})
}

func TestTransactionCreation(t *testing.T) {
	t.Run("CreateCurrencyTransaction creates valid transaction", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()

		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 0,
		}

		tx, err := CreateCurrencyTransaction(
			TransferParams{
				Destination: keyPair2.Address,
				Amount:      100.5,
				Fee:         0,
			},
			keyPair.PrivateKey,
			lastRef,
		)

		if err != nil {
			t.Fatalf("CreateCurrencyTransaction failed: %v", err)
		}
		if tx == nil {
			t.Fatal("Transaction is nil")
		}
		if tx.Value.Source != keyPair.Address {
			t.Errorf("Source = %s, want %s", tx.Value.Source, keyPair.Address)
		}
		if tx.Value.Destination != keyPair2.Address {
			t.Errorf("Destination = %s, want %s", tx.Value.Destination, keyPair2.Address)
		}
		if tx.Value.Amount != 10050000000 {
			t.Errorf("Amount = %d, want 10050000000", tx.Value.Amount)
		}
		if tx.Value.Fee != 0 {
			t.Errorf("Fee = %d, want 0", tx.Value.Fee)
		}
		if tx.Value.Parent != lastRef {
			t.Errorf("Parent mismatch")
		}
		if len(tx.Proofs) != 1 {
			t.Errorf("Proofs length = %d, want 1", len(tx.Proofs))
		}
	})

	t.Run("CreateCurrencyTransaction throws on invalid destination", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{Hash: "a" + string(make([]byte, 63)), Ordinal: 0}

		_, err := CreateCurrencyTransaction(
			TransferParams{Destination: "invalid", Amount: 100, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		if err != ErrInvalidAddress {
			t.Errorf("Expected ErrInvalidAddress, got %v", err)
		}
	})

	t.Run("CreateCurrencyTransaction throws on same address", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{Hash: "a" + string(make([]byte, 63)), Ordinal: 0}

		_, err := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair.Address, Amount: 100, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		if err != ErrSameAddress {
			t.Errorf("Expected ErrSameAddress, got %v", err)
		}
	})

	t.Run("CreateCurrencyTransaction throws on amount too small", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{Hash: "a" + string(make([]byte, 63)), Ordinal: 0}

		_, err := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair2.Address, Amount: 0.000000001, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		if err != ErrInvalidAmount {
			t.Errorf("Expected ErrInvalidAmount, got %v", err)
		}
	})

	t.Run("CreateCurrencyTransaction throws on negative fee", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{Hash: "a" + string(make([]byte, 63)), Ordinal: 0}

		_, err := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair2.Address, Amount: 100, Fee: -1},
			keyPair.PrivateKey,
			lastRef,
		)

		if err != ErrInvalidFee {
			t.Errorf("Expected ErrInvalidFee, got %v", err)
		}
	})
}

func TestBatchTransactions(t *testing.T) {
	t.Run("CreateCurrencyTransactionBatch creates multiple transactions", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		recipient1, _ := core.GenerateKeyPair()
		recipient2, _ := core.GenerateKeyPair()
		recipient3, _ := core.GenerateKeyPair()

		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 5,
		}

		transfers := []TransferParams{
			{Destination: recipient1.Address, Amount: 10},
			{Destination: recipient2.Address, Amount: 20},
			{Destination: recipient3.Address, Amount: 30},
		}

		txns, err := CreateCurrencyTransactionBatch(transfers, keyPair.PrivateKey, lastRef)

		if err != nil {
			t.Fatalf("CreateCurrencyTransactionBatch failed: %v", err)
		}
		if len(txns) != 3 {
			t.Errorf("Batch length = %d, want 3", len(txns))
		}
		if txns[0].Value.Amount != 1000000000 {
			t.Errorf("Transaction 0 amount = %d, want 1000000000", txns[0].Value.Amount)
		}
		if txns[1].Value.Amount != 2000000000 {
			t.Errorf("Transaction 1 amount = %d, want 2000000000", txns[1].Value.Amount)
		}
		if txns[2].Value.Amount != 3000000000 {
			t.Errorf("Transaction 2 amount = %d, want 3000000000", txns[2].Value.Amount)
		}

		// Check parent references are chained
		if txns[0].Value.Parent != lastRef {
			t.Error("Transaction 0 parent mismatch")
		}
		if txns[1].Value.Parent.Ordinal != 6 {
			t.Errorf("Transaction 1 ordinal = %d, want 6", txns[1].Value.Parent.Ordinal)
		}
		if txns[2].Value.Parent.Ordinal != 7 {
			t.Errorf("Transaction 2 ordinal = %d, want 7", txns[2].Value.Parent.Ordinal)
		}
	})
}

func TestTransactionVerification(t *testing.T) {
	t.Run("VerifyCurrencyTransaction validates correct signatures", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 0,
		}

		tx, _ := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair2.Address, Amount: 100, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		result := VerifyCurrencyTransaction(tx)

		if !result.IsValid {
			t.Error("Transaction should be valid")
		}
		if len(result.ValidProofs) != 1 {
			t.Errorf("ValidProofs length = %d, want 1", len(result.ValidProofs))
		}
		if len(result.InvalidProofs) != 0 {
			t.Errorf("InvalidProofs length = %d, want 0", len(result.InvalidProofs))
		}
	})

	t.Run("VerifyCurrencyTransaction detects invalid signatures", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 0,
		}

		tx, _ := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair2.Address, Amount: 100, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		// Corrupt the signature
		tx.Proofs[0].Signature = "invalid_signature"

		result := VerifyCurrencyTransaction(tx)

		if result.IsValid {
			t.Error("Transaction should be invalid")
		}
		if len(result.ValidProofs) != 0 {
			t.Errorf("ValidProofs length = %d, want 0", len(result.ValidProofs))
		}
		if len(result.InvalidProofs) != 1 {
			t.Errorf("InvalidProofs length = %d, want 1", len(result.InvalidProofs))
		}
	})
}

func TestMultiSignatureSupport(t *testing.T) {
	t.Run("SignCurrencyTransaction adds additional signature", func(t *testing.T) {
		keyPair1, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		recipient, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 0,
		}

		// Create transaction with first signature
		tx, _ := CreateCurrencyTransaction(
			TransferParams{Destination: recipient.Address, Amount: 100, Fee: 0},
			keyPair1.PrivateKey,
			lastRef,
		)

		if len(tx.Proofs) != 1 {
			t.Errorf("Initial proofs length = %d, want 1", len(tx.Proofs))
		}

		// Add second signature
		tx, err := SignCurrencyTransaction(tx, keyPair2.PrivateKey)
		if err != nil {
			t.Fatalf("SignCurrencyTransaction failed: %v", err)
		}

		if len(tx.Proofs) != 2 {
			t.Errorf("Proofs length after signing = %d, want 2", len(tx.Proofs))
		}

		// Verify both signatures
		result := VerifyCurrencyTransaction(tx)

		if !result.IsValid {
			t.Error("Transaction should be valid")
		}
		if len(result.ValidProofs) != 2 {
			t.Errorf("ValidProofs length = %d, want 2", len(result.ValidProofs))
		}
		if len(result.InvalidProofs) != 0 {
			t.Errorf("InvalidProofs length = %d, want 0", len(result.InvalidProofs))
		}
	})
}

func TestTransactionHashing(t *testing.T) {
	t.Run("HashCurrencyTransaction produces consistent hashes", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 0,
		}

		tx, _ := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair2.Address, Amount: 100, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		hash1 := HashCurrencyTransaction(tx)
		hash2 := HashCurrencyTransaction(tx)

		if hash1.Value != hash2.Value {
			t.Error("Hash values should be consistent")
		}
		if len(hash1.Value) != 64 {
			t.Errorf("Hash value length = %d, want 64", len(hash1.Value))
		}
		if len(hash1.Bytes) != 32 {
			t.Errorf("Hash bytes length = %d, want 32", len(hash1.Bytes))
		}
	})

	t.Run("GetTransactionReference creates correct reference", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 0,
		}

		tx, _ := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair2.Address, Amount: 100, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		ref := GetTransactionReference(tx, 1)

		if ref.Ordinal != 1 {
			t.Errorf("Reference ordinal = %d, want 1", ref.Ordinal)
		}
		if len(ref.Hash) != 64 {
			t.Errorf("Reference hash length = %d, want 64", len(ref.Hash))
		}
	})

	t.Run("EncodeCurrencyTransaction returns string", func(t *testing.T) {
		keyPair, _ := core.GenerateKeyPair()
		keyPair2, _ := core.GenerateKeyPair()
		lastRef := TransactionReference{
			Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Ordinal: 0,
		}

		tx, _ := CreateCurrencyTransaction(
			TransferParams{Destination: keyPair2.Address, Amount: 100, Fee: 0},
			keyPair.PrivateKey,
			lastRef,
		)

		encoded := EncodeCurrencyTransaction(tx)

		if len(encoded) == 0 {
			t.Error("Encoded transaction should not be empty")
		}
	})
}
