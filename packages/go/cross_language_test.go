package constellation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestVector struct {
	Source        string          `json:"source"`
	Type          string          `json:"type"`
	Data          json.RawMessage `json:"data"`
	CanonicalJSON string          `json:"canonical_json"`
	UTF8BytesHex  string          `json:"utf8_bytes_hex"`
	SHA256HashHex string          `json:"sha256_hash_hex"`
	SignatureHex  string          `json:"signature_hex"`
	PublicKeyHex  string          `json:"public_key_hex"`
}

func loadTestVectors(t *testing.T) []TestVector {
	// Try to find the shared test vectors file
	vectorsPath := filepath.Join("..", "..", "shared", "test_vectors.json")

	content, err := os.ReadFile(vectorsPath)
	require.NoError(t, err, "Failed to read test vectors from %s", vectorsPath)

	var vectors []TestVector
	err = json.Unmarshal(content, &vectors)
	require.NoError(t, err, "Failed to parse test vectors")

	return vectors
}

func TestCanonicalizationMatchesAllVectors(t *testing.T) {
	vectors := loadTestVectors(t)

	for _, vector := range vectors {
		var data interface{}
		err := json.Unmarshal(vector.Data, &data)
		require.NoError(t, err)

		canonical, err := Canonicalize(data)
		require.NoError(t, err)

		assert.Equal(t, vector.CanonicalJSON, canonical,
			"Canonicalization mismatch for %s vector", vector.Source)
	}
}

func TestBinaryEncodingMatchesAllVectors(t *testing.T) {
	vectors := loadTestVectors(t)

	for _, vector := range vectors {
		var data interface{}
		err := json.Unmarshal(vector.Data, &data)
		require.NoError(t, err)

		isDataUpdate := vector.Type == "TestDataUpdate"
		bytes, err := ToBytes(data, isDataUpdate)
		require.NoError(t, err)

		bytesHex := hex.EncodeToString(bytes)
		assert.Equal(t, vector.UTF8BytesHex, bytesHex,
			"Binary encoding mismatch for %s %s vector", vector.Source, vector.Type)
	}
}

func TestHashingMatchesAllVectors(t *testing.T) {
	vectors := loadTestVectors(t)

	for _, vector := range vectors {
		var data interface{}
		err := json.Unmarshal(vector.Data, &data)
		require.NoError(t, err)

		isDataUpdate := vector.Type == "TestDataUpdate"
		bytes, err := ToBytes(data, isDataUpdate)
		require.NoError(t, err)

		hash := HashBytes(bytes)
		assert.Equal(t, vector.SHA256HashHex, hash.Value,
			"Hash mismatch for %s %s vector", vector.Source, vector.Type)
	}
}

func TestVerifiesSignaturesFromAllVectors(t *testing.T) {
	vectors := loadTestVectors(t)

	for _, vector := range vectors {
		isValid, err := VerifyHash(vector.SHA256HashHex, vector.SignatureHex, vector.PublicKeyHex)
		require.NoError(t, err)
		assert.True(t, isValid, "Failed to verify %s %s signature", vector.Source, vector.Type)
	}
}

func TestRejectsTamperedSignatures(t *testing.T) {
	vectors := loadTestVectors(t)
	vector := vectors[0]

	// Tamper with the hash
	tamperedHash := strings.ReplaceAll(vector.SHA256HashHex, "0", "1")
	isValid, err := VerifyHash(tamperedHash, vector.SignatureHex, vector.PublicKeyHex)
	require.NoError(t, err)
	assert.False(t, isValid, "Should reject signature with tampered hash")
}

func TestBySourceLanguage(t *testing.T) {
	languages := []string{"python", "javascript", "rust", "go"}

	vectors := loadTestVectors(t)

	for _, language := range languages {
		t.Run(language+" vectors", func(t *testing.T) {
			langVectors := filterVectorsBySource(vectors, language)
			require.NotEmpty(t, langVectors, "No test vectors found for %s", language)

			for _, vector := range langVectors {
				var data interface{}
				err := json.Unmarshal(vector.Data, &data)
				require.NoError(t, err)

				isDataUpdate := vector.Type == "TestDataUpdate"

				// Test hashing
				bytes, err := ToBytes(data, isDataUpdate)
				require.NoError(t, err)

				hash := HashBytes(bytes)
				assert.Equal(t, vector.SHA256HashHex, hash.Value,
					"%s %s hash mismatch", language, vector.Type)

				// Test signature verification
				isValid, err := VerifyHash(vector.SHA256HashHex, vector.SignatureHex, vector.PublicKeyHex)
				require.NoError(t, err)
				assert.True(t, isValid, "%s %s signature verification failed", language, vector.Type)
			}
		})
	}
}

func filterVectorsBySource(vectors []TestVector, source string) []TestVector {
	var result []TestVector
	for _, v := range vectors {
		if v.Source == source {
			result = append(result, v)
		}
	}
	return result
}
