package constellation

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// DropNullFields recursively removes null-valued object fields (server-aligned).
//
// Behavior — byte-for-byte matched to metakit's `JsonBinaryCodec.dropNulls`,
// the TypeScript SDK's `dropNullFields` and the Rust SDK's `drop_null_fields`:
//
//   - Object fields whose value is null are removed, recursively.
//   - Array elements are NEVER removed — null elements are positional and
//     preserved; nested objects inside arrays are still cleaned.
//   - Primitives (including a top-level null) pass through unchanged.
//
// The input is expected to be generic decoded JSON (map[string]interface{},
// []interface{}, json.Number/float64, string, bool, nil), as produced by
// json.Unmarshal into an interface{}.
func DropNullFields(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, element := range v {
			if element == nil {
				continue
			}
			out[key] = DropNullFields(element)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, element := range v {
			out[i] = DropNullFields(element)
		}
		return out
	default:
		return v
	}
}

// Canonicalize converts data to a canonical JSON string according to RFC 8785.
//
// Null-valued object fields are dropped before canonicalization to match the
// authoritative Scala server (see DropNullFields). This makes the bytes
// produced for signing/verification here agree with what the chain re-derives.
func Canonicalize(data interface{}) (string, error) {
	canonicalBytes, err := CanonicalizeBytes(data)
	if err != nil {
		return "", err
	}
	return string(canonicalBytes), nil
}

// CanonicalizeBytes converts data to canonical JSON bytes according to RFC 8785.
//
// Null-valued object fields are dropped before canonicalization
// (see DropNullFields).
func CanonicalizeBytes(data interface{}) ([]byte, error) {
	// First convert to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Decode into generic JSON, keeping numbers as json.Number so the original
	// literals survive the drop-nulls round trip without float64 precision loss.
	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	decoder.UseNumber()
	var generic interface{}
	if err := decoder.Decode(&generic); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	// Drop null object-fields (server-aligned content-hash rule)
	cleanedBytes, err := json.Marshal(DropNullFields(generic))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Canonicalize JSON according to RFC 8785
	canonicalJSON, err := jsoncanonicalizer.Transform(cleanedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	return canonicalJSON, nil
}
