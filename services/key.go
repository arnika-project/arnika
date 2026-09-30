// Package services implements business logic for key management operations.
package services

type Key struct {
	ID  string // empty when the source issues no identifiers
	Key []byte
}

func (k *Key) Zero() {
	clear(k.Key)
	k.Key = nil
}
