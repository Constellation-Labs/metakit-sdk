package constellation

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Sign signs data using the regular Constellation protocol (non-DataUpdate)
func Sign(data interface{}, privateKeyHex string) (*SignatureProof, error) {
	// Serialize and hash
	bytes, err := ToBytes(data, false)
	if err != nil {
		return nil, err
	}
	hash := HashBytes(bytes)

	// Sign the hash
	signature, err := SignHash(hash.Value, privateKeyHex)
	if err != nil {
		return nil, err
	}

	// Get public key ID
	id, err := GetPublicKeyID(privateKeyHex)
	if err != nil {
		return nil, err
	}

	return &SignatureProof{
		ID:        id,
		Signature: signature,
	}, nil
}

// SignDataUpdate signs data as a DataUpdate (with Constellation prefix)
func SignDataUpdate(data interface{}, privateKeyHex string) (*SignatureProof, error) {
	// Serialize with DataUpdate encoding and hash
	bytes, err := ToBytes(data, true)
	if err != nil {
		return nil, err
	}
	hash := HashBytes(bytes)

	// Sign the hash
	signature, err := SignHash(hash.Value, privateKeyHex)
	if err != nil {
		return nil, err
	}

	// Get public key ID
	id, err := GetPublicKeyID(privateKeyHex)
	if err != nil {
		return nil, err
	}

	return &SignatureProof{
		ID:        id,
		Signature: signature,
	}, nil
}

// SignHash signs a pre-computed SHA-256 hash
func SignHash(hashHex string, privateKeyHex string) (string, error) {
	// Parse private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	// Compute signing digest
	digest := ComputeDigestFromHash(hashHex)

	// Sign with ECDSA
	signature := ecdsa.Sign(privateKey, digest)

	// Return DER-encoded signature
	return hex.EncodeToString(signature.Serialize()), nil
}
