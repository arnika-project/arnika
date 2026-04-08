//go:build !linux

package keyhandler

import "fmt"

type MACsec struct{}

func NewMACsec(interfaceName, rxSCI string) (*MACsec, error) {
	return nil, fmt.Errorf("macsec is only supported on Linux")
}

func (m *MACsec) SetKey(psk string) error { return fmt.Errorf("macsec: not supported") }
func (m *MACsec) Invalidate() error       { return fmt.Errorf("macsec: not supported") }
