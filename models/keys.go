// Package models defines shared data types used across the application.
package models

// Key is one piece of key material, with the identifier a peer needs to obtain
// the same key from its own key management system.
type Key struct {
	// ID is empty when the source issues no identifiers, because both peers
	// derive that key independently and have nothing to exchange.
	ID  string
	Key []byte
}

// Zero securely wipes the key material from memory.
func (k *Key) Zero() {
	clear(k.Key)
	k.Key = nil
}
