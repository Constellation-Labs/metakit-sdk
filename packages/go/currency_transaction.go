package constellation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/Constellation-Labs/metakit-sdk/packages/go/core"
)

// Minimum salt complexity (from dag4.js)
const minSalt = (1 << 53) - (1 << 48) // Number.MAX_SAFE_INTEGER - 2^48

var (
	// ErrInvalidAmount indicates the transfer amount is too small
	ErrInvalidAmount = errors.New("transfer amount must be greater than 1e-8")
	// ErrInvalidFee indicates the fee is negative
	ErrInvalidFee = errors.New("fee must be greater than or equal to zero")
	// ErrSameAddress indicates source and destination are the same
	ErrSameAddress = errors.New("source and destination addresses cannot be the same")
	// ErrInvalidAddress indicates an invalid DAG address
	ErrInvalidAddress = errors.New("invalid DAG address")
)

// TokenToUnits converts token amount to smallest units
func TokenToUnits(amount float64) int64 {
	return int64(math.Floor(amount * 1e8))
}

// UnitsToToken converts smallest units to token amount
func UnitsToToken(units int64) float64 {
	return float64(units) * TokenDecimals
}

// IsValidDAGAddress validates a DAG address format
func IsValidDAGAddress(address string) bool {
	// DAG addresses: DAG + parity digit (0-8) + 36 base58 chars = 40 chars total
	if !strings.HasPrefix(address, "DAG") {
		return false
	}
	// Exact length check
	if len(address) != 40 {
		return false
	}
	// Position 3 (after DAG) must be parity digit 0-8
	if address[3] < '0' || address[3] > '8' {
		return false
	}
	// Remaining 36 characters must be base58 (no 0, O, I, l)
	pattern := regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{36}$`)
	return pattern.MatchString(address[4:])
}

// generateSalt generates a random salt for transaction uniqueness
func generateSalt() string {
	// Generate 6 random bytes (48 bits)
	randomBytes := make([]byte, 6)
	rand.Read(randomBytes)

	randomInt := new(big.Int).SetBytes(randomBytes)
	salt := new(big.Int).Add(big.NewInt(minSalt), randomInt)

	return salt.String()
}

// encodeTransaction encodes a currency transaction for hashing
// Matches TransactionV2.getEncoded() from dag4.js
func encodeTransaction(tx *CurrencyTransaction) string {
	parentCount := "2" // Always 2 parents for v2
	source := tx.Value.Source
	destination := tx.Value.Destination
	amountHex := strconv.FormatInt(tx.Value.Amount, 16)
	parentHash := tx.Value.Parent.Hash
	ordinal := strconv.Itoa(tx.Value.Parent.Ordinal)
	fee := strconv.FormatInt(tx.Value.Fee, 10)

	// Convert salt to hex
	saltInt, _ := new(big.Int).SetString(tx.Value.Salt, 10)
	saltHex := fmt.Sprintf("%x", saltInt)

	// Build encoded string (length-prefixed format)
	parts := []string{
		parentCount,
		strconv.Itoa(len(source)),
		source,
		strconv.Itoa(len(destination)),
		destination,
		strconv.Itoa(len(amountHex)),
		amountHex,
		strconv.Itoa(len(parentHash)),
		parentHash,
		strconv.Itoa(len(ordinal)),
		ordinal,
		strconv.Itoa(len(fee)),
		fee,
		strconv.Itoa(len(saltHex)),
		saltHex,
	}

	return strings.Join(parts, "")
}

// kryoSerialize performs Kryo serialization for transaction encoding
// Matches txEncode.kryoSerialize() from dag4.js
func kryoSerialize(msg string, setReferences bool) []byte {
	// UTF-8 length encoding
	utf8Length := func(value int) []byte {
		if value>>6 == 0 {
			return []byte{byte(value | 0x80)}
		} else if value>>13 == 0 {
			return []byte{byte(value | 0x40 | 0x80), byte(value >> 6)}
		} else if value>>20 == 0 {
			return []byte{
				byte(value | 0x40 | 0x80),
				byte((value >> 6) | 0x80),
				byte(value >> 13),
			}
		} else if value>>27 == 0 {
			return []byte{
				byte(value | 0x40 | 0x80),
				byte((value >> 6) | 0x80),
				byte((value >> 13) | 0x80),
				byte(value >> 20),
			}
		} else {
			return []byte{
				byte(value | 0x40 | 0x80),
				byte((value >> 6) | 0x80),
				byte((value >> 13) | 0x80),
				byte((value >> 20) | 0x80),
				byte(value >> 27),
			}
		}
	}

	// Build serialized message
	var result []byte
	result = append(result, 0x03)
	if setReferences {
		result = append(result, 0x01)
	}

	length := len(msg) + 1
	result = append(result, utf8Length(length)...)
	result = append(result, []byte(msg)...)

	return result
}

// CreateCurrencyTransaction creates a metagraph token transaction
func CreateCurrencyTransaction(params TransferParams, privateKeyHex string, lastRef TransactionReference) (*CurrencyTransaction, error) {
	// Get source address from private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	publicKeyHex := hex.EncodeToString(privateKey.PubKey().SerializeUncompressed())
	source := core.GetAddress(publicKeyHex)

	// Validate addresses
	if !IsValidDAGAddress(source) {
		return nil, ErrInvalidAddress
	}
	if !IsValidDAGAddress(params.Destination) {
		return nil, ErrInvalidAddress
	}
	if source == params.Destination {
		return nil, ErrSameAddress
	}

	// Convert amounts to smallest units
	amount := TokenToUnits(params.Amount)
	fee := TokenToUnits(params.Fee)

	// Validate amounts
	if amount < 1 {
		return nil, ErrInvalidAmount
	}
	if fee < 0 {
		return nil, ErrInvalidFee
	}

	// Generate salt
	salt := generateSalt()

	// Create transaction
	tx := &CurrencyTransaction{
		Value: CurrencyTransactionValue{
			Source:      source,
			Destination: params.Destination,
			Amount:      amount,
			Fee:         fee,
			Parent:      lastRef,
			Salt:        salt,
		},
		Proofs: []core.SignatureProof{},
	}

	// Encode and hash
	encoded := encodeTransaction(tx)
	serialized := kryoSerialize(encoded, false)
	hashBytes := sha256.Sum256(serialized)
	hashHex := hex.EncodeToString(hashBytes[:])

	// Sign
	signature, err := signHashInternal(hashHex, privateKeyHex)
	if err != nil {
		return nil, err
	}

	// Create proof
	publicKeyID := publicKeyHex[2:] // Remove '04' prefix
	proof := core.SignatureProof{
		ID:        publicKeyID,
		Signature: signature,
	}

	// Add proof to transaction
	tx.Proofs = append(tx.Proofs, proof)

	return tx, nil
}

// CreateCurrencyTransactionBatch creates multiple metagraph token transactions (batch)
func CreateCurrencyTransactionBatch(transfers []TransferParams, privateKeyHex string, lastRef TransactionReference) ([]*CurrencyTransaction, error) {
	transactions := make([]*CurrencyTransaction, 0, len(transfers))
	currentRef := TransactionReference{
		Hash:    lastRef.Hash,
		Ordinal: lastRef.Ordinal,
	}

	for _, transfer := range transfers {
		tx, err := CreateCurrencyTransaction(transfer, privateKeyHex, currentRef)
		if err != nil {
			return nil, err
		}

		// Calculate hash for next transaction's parent reference
		hashResult := HashCurrencyTransaction(tx)

		// Update reference for next transaction
		currentRef = TransactionReference{
			Hash:    hashResult.Value,
			Ordinal: currentRef.Ordinal + 1,
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// SignCurrencyTransaction adds a signature to an existing currency transaction (for multi-sig)
func SignCurrencyTransaction(tx *CurrencyTransaction, privateKeyHex string) (*CurrencyTransaction, error) {
	// Encode and hash
	encoded := encodeTransaction(tx)
	serialized := kryoSerialize(encoded, false)
	hashBytes := sha256.Sum256(serialized)
	hashHex := hex.EncodeToString(hashBytes[:])

	// Sign
	signature, err := signHashInternal(hashHex, privateKeyHex)
	if err != nil {
		return nil, err
	}

	// Get public key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	publicKeyHex := hex.EncodeToString(privateKey.PubKey().SerializeUncompressed())

	// Verify signature
	if !verifyHashInternal(publicKeyHex, hashHex, signature) {
		return nil, errors.New("sign-verify failed")
	}

	// Create proof
	publicKeyID := publicKeyHex[2:] // Remove '04' prefix
	proof := core.SignatureProof{
		ID:        publicKeyID,
		Signature: signature,
	}

	// Create new transaction with updated proofs
	newTx := &CurrencyTransaction{
		Value:  tx.Value,
		Proofs: append([]core.SignatureProof{}, tx.Proofs...),
	}
	newTx.Proofs = append(newTx.Proofs, proof)

	return newTx, nil
}

// VerifyCurrencyTransaction verifies all signatures on a currency transaction
func VerifyCurrencyTransaction(tx *CurrencyTransaction) *core.VerificationResult {
	// Encode and hash
	encoded := encodeTransaction(tx)
	serialized := kryoSerialize(encoded, false)
	hashBytes := sha256.Sum256(serialized)
	hashHex := hex.EncodeToString(hashBytes[:])

	validProofs := []core.SignatureProof{}
	invalidProofs := []core.SignatureProof{}

	// Verify each proof
	for _, proof := range tx.Proofs {
		publicKey := "04" + proof.ID // Add back '04' prefix
		isValid := verifyHashInternal(publicKey, hashHex, proof.Signature)

		if isValid {
			validProofs = append(validProofs, proof)
		} else {
			invalidProofs = append(invalidProofs, proof)
		}
	}

	return &core.VerificationResult{
		IsValid:       len(invalidProofs) == 0 && len(validProofs) > 0,
		ValidProofs:   validProofs,
		InvalidProofs: invalidProofs,
	}
}

// EncodeCurrencyTransaction encodes a currency transaction for hashing
func EncodeCurrencyTransaction(tx *CurrencyTransaction) string {
	return encodeTransaction(tx)
}

// HashCurrencyTransaction hashes a currency transaction
func HashCurrencyTransaction(tx *CurrencyTransaction) *core.Hash {
	encoded := encodeTransaction(tx)
	serialized := kryoSerialize(encoded, false)
	hashBytes := sha256.Sum256(serialized)

	return &core.Hash{
		Value: hex.EncodeToString(hashBytes[:]),
		Bytes: hashBytes[:],
	}
}

// GetTransactionReference gets a transaction reference from a currency transaction
// Useful for chaining transactions
func GetTransactionReference(tx *CurrencyTransaction, ordinal int) *TransactionReference {
	hashResult := HashCurrencyTransaction(tx)
	return &TransactionReference{
		Hash:    hashResult.Value,
		Ordinal: ordinal,
	}
}

// signHashInternal signs a hash using Constellation signing protocol
func signHashInternal(hashHex string, privateKeyHex string) (string, error) {
	// Parse private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	// Compute signing digest
	digest := core.ComputeDigestFromHash(hashHex)

	// Sign with ECDSA
	signature := ecdsa.Sign(privateKey, digest)

	// Serialize to DER format
	signatureBytes := signature.Serialize()

	return hex.EncodeToString(signatureBytes), nil
}

// verifyHashInternal verifies a signature on a hash
func verifyHashInternal(publicKeyHex string, hashHex string, signatureHex string) bool {
	// Parse public key
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false
	}

	publicKey, err := btcec.ParsePubKey(publicKeyBytes)
	if err != nil {
		return false
	}

	// Compute digest
	digest := core.ComputeDigestFromHash(hashHex)

	// Parse signature
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}

	signature, err := ecdsa.ParseDERSignature(signatureBytes)
	if err != nil {
		return false
	}

	// Verify
	return signature.Verify(digest, publicKey)
}
