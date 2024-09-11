package kdf

import (
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

func DeriveKey(kmsKey, pqcKey string) (string, error) {
	key1, err := base64.StdEncoding.DecodeString(kmsKey)
	if err != nil {
		return "", fmt.Errorf("error decoding base64 string: %w", err)
	}

	key2, err := base64.StdEncoding.DecodeString(pqcKey)
	if err != nil {
		return "", fmt.Errorf("error decoding base64 string: %w", err)
	}

	// Create a new HKDF instance with SHA3-256 as the hash function
	hkdf := hkdf.New(sha3.New256, append(key1, key2...), nil, nil)

	// Generate a derived key using HKDF
	derivedKey := make([]byte, 32) // Output key length
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return "", fmt.Errorf("error generating derived key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(derivedKey), nil
}
