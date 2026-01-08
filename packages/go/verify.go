package constellation

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Verify verifies a signed object
func Verify[T any](signed *Signed[T], isDataUpdate bool) *VerificationResult {
	// Compute the hash that should have been signed
	bytes, err := ToBytes(signed.Value, isDataUpdate)
	if err != nil {
		return &VerificationResult{
			IsValid:       false,
			ValidProofs:   []SignatureProof{},
			InvalidProofs: signed.Proofs,
		}
	}
	hash := HashBytes(bytes)

	var validProofs []SignatureProof
	var invalidProofs []SignatureProof

	for _, proof := range signed.Proofs {
		isValid, _ := VerifyHash(hash.Value, proof.Signature, proof.ID)
		if isValid {
			validProofs = append(validProofs, proof)
		} else {
			invalidProofs = append(invalidProofs, proof)
		}
	}

	return &VerificationResult{
		IsValid:       len(invalidProofs) == 0 && len(validProofs) > 0,
		ValidProofs:   validProofs,
		InvalidProofs: invalidProofs,
	}
}

// VerifyHash verifies a signature against a SHA-256 hash
func VerifyHash(hashHex string, signatureHex string, publicKeyID string) (bool, error) {
	// Normalize and parse public key
	fullPublicKey := NormalizePublicKey(publicKeyID)
	publicKeyBytes, err := hex.DecodeString(fullPublicKey)
	if err != nil {
		return false, err
	}

	publicKey, err := btcec.ParsePubKey(publicKeyBytes)
	if err != nil {
		return false, err
	}

	// Parse signature
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, err
	}

	signature, err := ecdsa.ParseDERSignature(signatureBytes)
	if err != nil {
		return false, err
	}

	// Compute signing digest
	digest := ComputeDigestFromHash(hashHex)

	// Verify signature
	return signature.Verify(digest, publicKey), nil
}

// VerifySignature verifies a single signature proof against data
func VerifySignature(data interface{}, proof *SignatureProof, isDataUpdate bool) (bool, error) {
	bytes, err := ToBytes(data, isDataUpdate)
	if err != nil {
		return false, err
	}
	hash := HashBytes(bytes)
	return VerifyHash(hash.Value, proof.Signature, proof.ID)
}
