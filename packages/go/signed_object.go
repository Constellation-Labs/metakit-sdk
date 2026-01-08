package constellation

// CreateSignedObject creates a signed object with a single signature
func CreateSignedObject[T any](value T, privateKeyHex string, isDataUpdate bool) (*Signed[T], error) {
	var proof *SignatureProof
	var err error

	if isDataUpdate {
		proof, err = SignDataUpdate(value, privateKeyHex)
	} else {
		proof, err = Sign(value, privateKeyHex)
	}

	if err != nil {
		return nil, err
	}

	return &Signed[T]{
		Value:  value,
		Proofs: []SignatureProof{*proof},
	}, nil
}

// AddSignature adds an additional signature to an existing signed object
func AddSignature[T any](signed *Signed[T], privateKeyHex string, isDataUpdate bool) (*Signed[T], error) {
	var newProof *SignatureProof
	var err error

	if isDataUpdate {
		newProof, err = SignDataUpdate(signed.Value, privateKeyHex)
	} else {
		newProof, err = Sign(signed.Value, privateKeyHex)
	}

	if err != nil {
		return nil, err
	}

	proofs := append(signed.Proofs, *newProof)

	return &Signed[T]{
		Value:  signed.Value,
		Proofs: proofs,
	}, nil
}

// BatchSign creates a signed object with multiple signatures at once
func BatchSign[T any](value T, privateKeys []string, isDataUpdate bool) (*Signed[T], error) {
	if len(privateKeys) == 0 {
		return nil, ErrNoPrivateKeys
	}

	proofs := make([]SignatureProof, 0, len(privateKeys))

	for _, key := range privateKeys {
		var proof *SignatureProof
		var err error

		if isDataUpdate {
			proof, err = SignDataUpdate(value, key)
		} else {
			proof, err = Sign(value, key)
		}

		if err != nil {
			return nil, err
		}

		proofs = append(proofs, *proof)
	}

	return &Signed[T]{
		Value:  value,
		Proofs: proofs,
	}, nil
}
