package constellation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyGeneration(t *testing.T) {
	t.Run("generates valid key pair", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		assert.Len(t, keyPair.PrivateKey, 64, "Private key should be 64 hex chars")
		assert.Len(t, keyPair.PublicKey, 130, "Public key should be 130 hex chars")
		assert.True(t, strings.HasPrefix(keyPair.Address, "DAG"), "Address should start with DAG")
	})

	t.Run("derives consistent key pair", func(t *testing.T) {
		original, err := GenerateKeyPair()
		require.NoError(t, err)

		derived, err := KeyPairFromPrivateKey(original.PrivateKey)
		require.NoError(t, err)

		assert.Equal(t, original.PublicKey, derived.PublicKey)
		assert.Equal(t, original.Address, derived.Address)
	})

	t.Run("generates unique key pairs", func(t *testing.T) {
		key1, err := GenerateKeyPair()
		require.NoError(t, err)

		key2, err := GenerateKeyPair()
		require.NoError(t, err)

		assert.NotEqual(t, key1.PrivateKey, key2.PrivateKey)
		assert.NotEqual(t, key1.PublicKey, key2.PublicKey)
		assert.NotEqual(t, key1.Address, key2.Address)
	})
}

func TestRegularSigning(t *testing.T) {
	t.Run("signs and verifies data", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{
			"action": "test",
			"value":  42,
		}

		signed, err := CreateSignedObject(data, keyPair.PrivateKey, false)
		require.NoError(t, err)

		result := Verify(signed, false)
		assert.True(t, result.IsValid)
		assert.Len(t, result.ValidProofs, 1)
		assert.Empty(t, result.InvalidProofs)
	})

	t.Run("signature contains public key id", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{"test": true}
		proof, err := Sign(data, keyPair.PrivateKey)
		require.NoError(t, err)

		// ID should be public key without 04 prefix
		assert.Len(t, proof.ID, 128)
		assert.Equal(t, keyPair.PublicKey[2:], proof.ID)
	})
}

func TestDataUpdateSigning(t *testing.T) {
	t.Run("signs and verifies data update", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{
			"id":    "update-001",
			"value": 123,
		}

		signed, err := CreateSignedObject(data, keyPair.PrivateKey, true)
		require.NoError(t, err)

		result := Verify(signed, true)
		assert.True(t, result.IsValid)
	})

	t.Run("data update verification fails with wrong mode", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{"id": "test"}

		// Sign as DataUpdate
		signed, err := CreateSignedObject(data, keyPair.PrivateKey, true)
		require.NoError(t, err)

		// Verify as regular (should fail)
		result := Verify(signed, false)
		assert.False(t, result.IsValid)
	})

	t.Run("produces different signatures than regular", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{"id": "test"}

		regularProof, err := Sign(data, keyPair.PrivateKey)
		require.NoError(t, err)

		updateProof, err := SignDataUpdate(data, keyPair.PrivateKey)
		require.NoError(t, err)

		// Same key
		assert.Equal(t, regularProof.ID, updateProof.ID)
		// Different signatures
		assert.NotEqual(t, regularProof.Signature, updateProof.Signature)
	})
}

func TestMultiSignature(t *testing.T) {
	t.Run("adds signature to existing object", func(t *testing.T) {
		key1, err := GenerateKeyPair()
		require.NoError(t, err)

		key2, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{"action": "multi-sig"}

		signed, err := CreateSignedObject(data, key1.PrivateKey, false)
		require.NoError(t, err)

		signed, err = AddSignature(signed, key2.PrivateKey, false)
		require.NoError(t, err)

		assert.Len(t, signed.Proofs, 2)

		result := Verify(signed, false)
		assert.True(t, result.IsValid)
		assert.Len(t, result.ValidProofs, 2)
	})

	t.Run("batch signs with multiple keys", func(t *testing.T) {
		key1, err := GenerateKeyPair()
		require.NoError(t, err)

		key2, err := GenerateKeyPair()
		require.NoError(t, err)

		key3, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{"action": "batch"}

		signed, err := BatchSign(data, []string{key1.PrivateKey, key2.PrivateKey, key3.PrivateKey}, false)
		require.NoError(t, err)

		assert.Len(t, signed.Proofs, 3)

		result := Verify(signed, false)
		assert.True(t, result.IsValid)
		assert.Len(t, result.ValidProofs, 3)
	})

	t.Run("all signatures are unique", func(t *testing.T) {
		key1, err := GenerateKeyPair()
		require.NoError(t, err)

		key2, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{"id": "test"}

		signed, err := BatchSign(data, []string{key1.PrivateKey, key2.PrivateKey}, false)
		require.NoError(t, err)

		assert.NotEqual(t, signed.Proofs[0].ID, signed.Proofs[1].ID)
		assert.NotEqual(t, signed.Proofs[0].Signature, signed.Proofs[1].Signature)
	})
}

func TestTamperDetection(t *testing.T) {
	t.Run("detects modified value", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		original := map[string]interface{}{"amount": 100}
		proof, err := Sign(original, keyPair.PrivateKey)
		require.NoError(t, err)

		// Create signed object with tampered value
		tampered := map[string]interface{}{"amount": 999}
		signed := &Signed[map[string]interface{}]{
			Value:  tampered,
			Proofs: []SignatureProof{*proof},
		}

		result := Verify(signed, false)
		assert.False(t, result.IsValid)
		assert.Empty(t, result.ValidProofs)
		assert.Len(t, result.InvalidProofs, 1)
	})

	t.Run("detects modified signature", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)

		data := map[string]interface{}{"id": "test"}
		proof, err := Sign(data, keyPair.PrivateKey)
		require.NoError(t, err)

		// Tamper with signature
		proof.Signature = strings.ReplaceAll(proof.Signature, "0", "1")

		signed := &Signed[map[string]interface{}]{
			Value:  data,
			Proofs: []SignatureProof{*proof},
		}

		result := Verify(signed, false)
		assert.False(t, result.IsValid)
	})
}

func TestCodecOperations(t *testing.T) {
	t.Run("encodes and decodes data update", func(t *testing.T) {
		data := map[string]interface{}{
			"id":     "test",
			"nested": map[string]interface{}{"key": "value"},
			"array":  []int{1, 2, 3},
		}

		encoded, err := EncodeDataUpdate(data)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = DecodeDataUpdate(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, data["id"], decoded["id"])
	})

	t.Run("canonicalizes json consistently", func(t *testing.T) {
		data := map[string]interface{}{
			"z": 26,
			"a": 1,
			"m": 13,
		}

		canonical, err := Canonicalize(data)
		require.NoError(t, err)

		assert.Equal(t, `{"a":1,"m":13,"z":26}`, canonical)
	})

	t.Run("to bytes produces different output for data update", func(t *testing.T) {
		data := map[string]interface{}{"id": "test"}

		regular, err := ToBytes(data, false)
		require.NoError(t, err)

		update, err := ToBytes(data, true)
		require.NoError(t, err)

		assert.NotEqual(t, regular, update)
		assert.Contains(t, string(update), "Constellation Signed Data")
	})
}

func TestHashing(t *testing.T) {
	t.Run("produces consistent hashes", func(t *testing.T) {
		data := map[string]interface{}{"id": "test", "value": 42}

		hash1, err := HashData(data, false)
		require.NoError(t, err)

		hash2, err := HashData(data, false)
		require.NoError(t, err)

		assert.Equal(t, hash1.Value, hash2.Value)
		assert.Equal(t, hash1.Bytes, hash2.Bytes)
	})

	t.Run("hash is 32 bytes", func(t *testing.T) {
		data := map[string]interface{}{"test": true}

		hash, err := HashData(data, false)
		require.NoError(t, err)

		assert.Len(t, hash.Bytes, 32)
		assert.Len(t, hash.Value, 64)
	})

	t.Run("different data produces different hash", func(t *testing.T) {
		data1 := map[string]interface{}{"value": 1}
		data2 := map[string]interface{}{"value": 2}

		hash1, err := HashData(data1, false)
		require.NoError(t, err)

		hash2, err := HashData(data2, false)
		require.NoError(t, err)

		assert.NotEqual(t, hash1.Value, hash2.Value)
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("rejects invalid private key", func(t *testing.T) {
		_, err := KeyPairFromPrivateKey("invalid")
		assert.Error(t, err)
	})

	t.Run("batch sign requires at least one key", func(t *testing.T) {
		data := map[string]interface{}{"test": true}
		_, err := BatchSign(data, []string{}, false)
		assert.Equal(t, ErrNoPrivateKeys, err)
	})
}
