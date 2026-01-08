package constellation

import (
	"encoding/json"
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Canonicalize converts data to a canonical JSON string according to RFC 8785
func Canonicalize(data interface{}) (string, error) {
	bytes, err := CanonicalizeBytes(data)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CanonicalizeBytes converts data to canonical JSON bytes according to RFC 8785
func CanonicalizeBytes(data interface{}) ([]byte, error) {
	// First convert to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Canonicalize JSON according to RFC 8785
	canonicalJSON, err := jsoncanonicalizer.Transform(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	return canonicalJSON, nil
}
