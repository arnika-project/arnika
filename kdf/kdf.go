// Package kdf provides HKDF-based key derivation functions using SHA3-256.
package kdf

import (
	"fmt"
	"io"
	"runtime/secret"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// DeriveKey leaves both inputs untouched; clearing them stays with the caller.
func DeriveKey(qkdKey, pqcKey []byte) ([]byte, error) {
	var result []byte
	var deriveErr error
	secret.Do(func() {
		combined := make([]byte, 0, len(qkdKey)+len(pqcKey))
		combined = append(combined, qkdKey...)
		combined = append(combined, pqcKey...)
		defer clear(combined)

		hkdfReader := hkdf.New(sha3.New256, combined, nil, nil)

		derivedKey := make([]byte, 32)
		if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
			deriveErr = fmt.Errorf("[ERROR] failed generating derived key: %w", err)
			return
		}
		result = derivedKey
	})
	return result, deriveErr
}
