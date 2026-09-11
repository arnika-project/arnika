package services

import (
	"crypto/rand"
	"fmt"
	"sync"
)

// pskLen is the WireGuard pre-shared key size, and the size of both the QKD and
// the PQC key that combine into it.
const pskLen = 32

// keyWriterRepository is the port every key writer implements: install these
// bytes as the peer's pre-shared key. One method, because everything else a key
// writer has to do is the same for all of them and lives in the service.
//
// It takes bytes and not a base64 string. Go strings are immutable, so a PSK
// that becomes one can never be overwritten and stays on the heap until the
// collector reuses the memory. Encoding at the caller put that unclearable copy
// there for every adapter, including the ones whose transport takes the key as
// bytes anyway; an adapter that genuinely needs a string now makes it at its own
// boundary, where the cost is unavoidable and visible.
type keyWriterRepository interface {
	SetPSK(psk []byte) error
}

// KeyWriterService owns what holds for every key writer regardless of how it
// reaches the interface: that invalidating the tunnel means a fresh random key,
// and that only one write is ever in flight.
type KeyWriterService struct {
	// mu serialises writes. Not in the adapters: they would each need their own
	// copy of it, and an adapter author has no reason to suspect concurrency
	// from reading the port.
	mu   sync.Mutex
	repo keyWriterRepository
}

func NewKeyWriterService(repo keyWriterRepository) *KeyWriterService {
	return &KeyWriterService{repo: repo}
}

// InvalidateTunnel installs a key no peer can hold, which tears down the current
// WireGuard session. It is the fail-safe for a rotation that cannot produce
// valid key material, so that a failed rotation never leaves the superseded key
// installed.
//
// Here rather than in each adapter: "a fresh random 32-byte key" is the same
// rule for every writer, and the three copies of it had already drifted onto two
// different random sources. A new adapter cannot get this wrong if it cannot
// implement it.
func (s *KeyWriterService) InvalidateTunnel() error {
	var psk [pskLen]byte
	defer clear(psk[:])
	if _, err := rand.Read(psk[:]); err != nil {
		return fmt.Errorf("failed to generate random PSK: %w", err)
	}
	return s.SetPSK(psk[:])
}

// SetPSK installs the key on the WireGuard interface.
//
// Serialised, because the QKD rotation loop and the wall-clock fallback timer
// both reach this from their own goroutines. Two interleaved writes would leave
// which key ends up installed undecided, and an adapter that needs more than one
// request to get there - the RouterOS one resolves the peer, then patches it -
// could resolve for one call and write for the other.
func (s *KeyWriterService) SetPSK(psk []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repo.SetPSK(psk)
}
