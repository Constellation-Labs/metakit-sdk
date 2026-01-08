// Package constellation provides a complete SDK for signing and verifying
// data on Constellation Network metagraphs.
package constellation

import "errors"

// Algorithm is the supported signature algorithm identifier
const Algorithm = "SECP256K1_RFC8785_V1"

// ConstellationPrefix is the prefix for DataUpdate signing
const ConstellationPrefix = "\x19Constellation Signed Data:\n"

// SignatureProof contains the signer's public key ID and signature
type SignatureProof struct {
	// ID is the public key hex (uncompressed, without 04 prefix) - 128 characters
	ID string `json:"id"`
	// Signature is the DER-encoded ECDSA signature in hex format
	Signature string `json:"signature"`
}

// Signed wraps a value with one or more signature proofs
type Signed[T any] struct {
	// Value is the signed data
	Value T `json:"value"`
	// Proofs is the array of signature proofs
	Proofs []SignatureProof `json:"proofs"`
}

// KeyPair holds a complete key pair for signing operations
type KeyPair struct {
	// PrivateKey in hex format (64 characters)
	PrivateKey string
	// PublicKey in hex format (uncompressed, with 04 prefix - 130 characters)
	PublicKey string
	// Address is the DAG address derived from the public key
	Address string
}

// Hash holds a hash result with both hex string and raw bytes
type Hash struct {
	// Value is the SHA-256 hash as 64-character hex string
	Value string
	// Bytes is the raw 32-byte hash
	Bytes []byte
}

// VerificationResult contains the outcome of signature verification
type VerificationResult struct {
	// IsValid is true if all signatures are valid
	IsValid bool
	// ValidProofs contains proofs that passed verification
	ValidProofs []SignatureProof
	// InvalidProofs contains proofs that failed verification
	InvalidProofs []SignatureProof
}

// SigningOptions holds options for signing operations
type SigningOptions struct {
	// IsDataUpdate indicates whether to sign as a DataUpdate (with Constellation prefix)
	IsDataUpdate bool
}

// Common errors
var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrNoPrivateKeys     = errors.New("at least one private key is required")
	ErrSerializationFailed = errors.New("serialization failed")
)
