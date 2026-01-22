package kdf

import (
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

func DeriveKey(kmsKey string, pqcKey []byte) (string, error) {
	qkdKey, err := base64.StdEncoding.DecodeString(kmsKey)
	if err != nil {
		return "", fmt.Errorf("[ERROR] failed decoding QKD key: %w", err)
	}

	// Create a new HKDF instance with SHA3-256 as the hash function
	hkdf := hkdf.New(sha3.New256, append(qkdKey, pqcKey...), nil, nil)

	// Generate a derived key using HKDF
	derivedKey := make([]byte, 32) // Output key length
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return "", fmt.Errorf("[ERROR] failed generating derived key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(derivedKey), nil
}
