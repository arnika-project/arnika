// Package kdf provides HKDF-based key derivation functions using SHA3-256.
package kdf

import (
	"fmt"
	"io"
	"runtime/secret"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// DeriveKey combines a QKD key and a PQC key via HKDF-SHA3-256 and returns
// the raw 32-byte derived key. Both input slices are left untouched (caller
// is responsible for clearing them). Intermediate keying material is zeroed
// inside a runtime/secret block.
func DeriveKey(qkdKey, pqcKey []byte) ([]byte, error) {
	var result []byte
	var deriveErr error
	secret.Do(func() {
		// Build a combined input without mutating the caller's slices.
		combined := make([]byte, 0, len(qkdKey)+len(pqcKey))
		combined = append(combined, qkdKey...)
		combined = append(combined, pqcKey...)
		defer clear(combined)

		// Create a new HKDF instance with SHA3-256 as the hash function
		hkdf := hkdf.New(sha3.New256, combined, nil, nil)

		// Generate a derived key using HKDF
		derivedKey := make([]byte, 32) // Output key length
		if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
			deriveErr = fmt.Errorf("[ERROR] failed generating derived key: %w", err)
			return
		}
		result = derivedKey
	})
	return result, deriveErr
}
