package services

import (
	"crypto/rand"
	"fmt"
	"sync"
)

const pskLen = 32

// keyWriterRepository takes bytes, not a string, because an immutable string PSK can never be cleared.
type keyWriterRepository interface {
	SetPSK(psk []byte) error
}

type KeyWriterService struct {
	mu   sync.Mutex
	repo keyWriterRepository
}

func NewKeyWriterService(repo keyWriterRepository) *KeyWriterService {
	return &KeyWriterService{repo: repo}
}

func (s *KeyWriterService) InvalidateTunnel() error {
	var psk [pskLen]byte
	defer clear(psk[:])
	if _, err := rand.Read(psk[:]); err != nil {
		return fmt.Errorf("failed to generate random PSK: %w", err)
	}
	return s.SetPSK(psk[:])
}

// SetPSK is serialised because the QKD rotation loop and the wall-clock fallback timer call it concurrently.
func (s *KeyWriterService) SetPSK(psk []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repo.SetPSK(psk)
}
