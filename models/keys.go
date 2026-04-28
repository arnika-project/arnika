// Package models defines shared data types used across the application.
package models

type keyType string

const (
	KeyTypeManaged   keyType = "managed"
	KeyTypeUnmanaged keyType = "unmanaged"
)

type Key struct {
	ID   *string `json:"id"`
	Key  []byte  `json:"key"`
	Type keyType `json:"type,omitempty"`
}

func (k *Key) IsManaged() bool {
	return k.Type == KeyTypeManaged
}

// Zero securely wipes the key material from memory.
func (k *Key) Zero() {
	clear(k.Key)
	k.Key = nil
}
