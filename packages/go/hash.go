package constellation

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// HashData hashes data using SHA-256
func HashData(data interface{}, isDataUpdate bool) (*Hash, error) {
	bytes, err := ToBytes(data, isDataUpdate)
	if err != nil {
		return nil, err
	}
	return HashBytes(bytes), nil
}

// HashBytes hashes raw bytes using SHA-256
func HashBytes(data []byte) *Hash {
	hashBytes := sha256.Sum256(data)
	return &Hash{
		Value: hex.EncodeToString(hashBytes[:]),
		Bytes: hashBytes[:],
	}
}

// ComputeDigest computes the full signing digest for Constellation protocol
//
// Protocol:
// 1. Serialize and hash with SHA-256
// 2. Convert hash to hex string
// 3. Treat hex string as UTF-8 bytes
// 4. SHA-512 hash
// 5. Truncate to 32 bytes
func ComputeDigest(data interface{}, isDataUpdate bool) ([]byte, error) {
	bytes, err := ToBytes(data, isDataUpdate)
	if err != nil {
		return nil, err
	}
	return ComputeDigestFromBytes(bytes), nil
}

// ComputeDigestFromBytes computes signing digest from raw bytes
func ComputeDigestFromBytes(data []byte) []byte {
	// Step 1: SHA-256
	sha256Hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(sha256Hash[:])

	// Step 2-4: Treat hex as UTF-8 bytes, SHA-512, truncate
	sha512Hash := sha512.Sum512([]byte(hashHex))

	// Step 5: Truncate to 32 bytes
	return sha512Hash[:32]
}

// ComputeDigestFromHash computes signing digest from a pre-computed SHA-256 hash hex string
func ComputeDigestFromHash(hashHex string) []byte {
	// Treat hex as UTF-8 bytes
	sha512Hash := sha512.Sum512([]byte(hashHex))

	// Truncate to 32 bytes
	return sha512Hash[:32]
}
