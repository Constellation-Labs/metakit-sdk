package constellation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ToBytes converts data to bytes for signing
func ToBytes(data interface{}, isDataUpdate bool) ([]byte, error) {
	canonicalJSON, err := CanonicalizeBytes(data)
	if err != nil {
		return nil, err
	}

	if isDataUpdate {
		// Add Constellation prefix for DataUpdate
		base64String := base64.StdEncoding.EncodeToString(canonicalJSON)
		wrappedString := fmt.Sprintf("%s%d\n%s", ConstellationPrefix, len(base64String), base64String)
		return []byte(wrappedString), nil
	}

	return canonicalJSON, nil
}

// EncodeDataUpdate encodes data as a DataUpdate (convenience wrapper)
func EncodeDataUpdate(data interface{}) ([]byte, error) {
	return ToBytes(data, true)
}

// DecodeDataUpdate decodes a DataUpdate back to the original data
func DecodeDataUpdate(data []byte, result interface{}) error {
	s := string(data)

	// Check for Constellation prefix
	if !strings.HasPrefix(s, ConstellationPrefix) {
		return fmt.Errorf("invalid DataUpdate format: missing Constellation prefix")
	}

	// Remove prefix and parse
	rest := s[len(ConstellationPrefix):]

	// Find the length line
	parts := strings.SplitN(rest, "\n", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid DataUpdate format: missing length separator")
	}

	_, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid length in DataUpdate: %w", err)
	}

	base64Data := parts[1]

	// Decode base64
	decodedBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}

	// Parse JSON
	return json.Unmarshal(decodedBytes, result)
}
