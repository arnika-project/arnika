//go:build !linux

package keyhandler

import "fmt"

func NewWolfGuard(interfaceName, peerPublicKey string) (*WolfGuard, error) {
	return nil, fmt.Errorf("wolfguard is only supported on Linux")
}

// WolfGuard is a stub for non-Linux platforms.
type WolfGuard struct{}

func (w *WolfGuard) SetKey(psk string) error { return fmt.Errorf("wolfguard: not supported") }
func (w *WolfGuard) Invalidate() error       { return fmt.Errorf("wolfguard: not supported") }
