package constellation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// GenerateKeyPair creates a new random key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	privateKeyHex := hex.EncodeToString(privateKey.Serialize())
	publicKeyHex := hex.EncodeToString(privateKey.PubKey().SerializeUncompressed())
	address := GetAddress(publicKeyHex)

	return &KeyPair{
		PrivateKey: privateKeyHex,
		PublicKey:  publicKeyHex,
		Address:    address,
	}, nil
}

// KeyPairFromPrivateKey derives a key pair from an existing private key
func KeyPairFromPrivateKey(privateKeyHex string) (*KeyPair, error) {
	if !IsValidPrivateKey(privateKeyHex) {
		return nil, ErrInvalidPrivateKey
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	publicKeyHex := hex.EncodeToString(privateKey.PubKey().SerializeUncompressed())
	address := GetAddress(publicKeyHex)

	return &KeyPair{
		PrivateKey: privateKeyHex,
		PublicKey:  publicKeyHex,
		Address:    address,
	}, nil
}

// GetPublicKeyHex returns the public key hex from a private key
func GetPublicKeyHex(privateKeyHex string, compressed bool) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex string: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	if compressed {
		return hex.EncodeToString(privateKey.PubKey().SerializeCompressed()), nil
	}
	return hex.EncodeToString(privateKey.PubKey().SerializeUncompressed()), nil
}

// GetPublicKeyID returns the public key ID (without 04 prefix) from a private key
// This format is used in SignatureProof.ID
func GetPublicKeyID(privateKeyHex string) (string, error) {
	publicKey, err := GetPublicKeyHex(privateKeyHex, false)
	if err != nil {
		return "", err
	}
	return NormalizePublicKeyToID(publicKey), nil
}

// GetAddress derives a DAG address from a public key
func GetAddress(publicKeyHex string) string {
	normalizedKey := NormalizePublicKey(publicKeyHex)
	publicKeyBytes, _ := hex.DecodeString(normalizedKey)

	// SHA-256 hash of public key
	hash := sha256.Sum256(publicKeyBytes)

	// Base58 encode and prepend DAG
	encoded := base58Encode(hash[:])
	return "DAG" + encoded
}

// IsValidPrivateKey validates that a private key is correctly formatted
func IsValidPrivateKey(privateKeyHex string) bool {
	if len(privateKeyHex) != 64 {
		return false
	}
	for _, c := range privateKeyHex {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// IsValidPublicKey validates that a public key is correctly formatted
func IsValidPublicKey(publicKeyHex string) bool {
	// With 04 prefix: 130 chars, without: 128 chars
	if len(publicKeyHex) != 128 && len(publicKeyHex) != 130 {
		return false
	}
	for _, c := range publicKeyHex {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// NormalizePublicKey ensures the public key has the 04 prefix
func NormalizePublicKey(publicKeyHex string) string {
	if len(publicKeyHex) == 128 {
		return "04" + publicKeyHex
	}
	return publicKeyHex
}

// NormalizePublicKeyToID returns the public key without the 04 prefix
func NormalizePublicKeyToID(publicKeyHex string) string {
	if len(publicKeyHex) == 130 && strings.HasPrefix(publicKeyHex, "04") {
		return publicKeyHex[2:]
	}
	return publicKeyHex
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// base58Encode encodes bytes using Bitcoin/Constellation alphabet
func base58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Count leading zeros
	leadingZeros := 0
	for _, b := range data {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert to big integer representation
	var digits []byte
	for _, b := range data {
		carry := int(b)
		for i := range digits {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}

	// Build result string
	result := make([]byte, 0, leadingZeros+len(digits))

	// Add '1' for each leading zero byte
	for i := 0; i < leadingZeros; i++ {
		result = append(result, '1')
	}

	// Convert digits to characters (in reverse order)
	for i := len(digits) - 1; i >= 0; i-- {
		result = append(result, base58Alphabet[digits[i]])
	}

	return string(result)
}
