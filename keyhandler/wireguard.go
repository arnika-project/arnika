package keyhandler

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuard injects PSKs into a standard WireGuard interface via wgctrl (netlink).
type WireGuard struct {
	conn          *wgctrl.Client
	interfaceName string
	peerPublicKey string
}

func NewWireGuard(interfaceName, peerPublicKey string) (*WireGuard, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &WireGuard{
		conn:          client,
		interfaceName: interfaceName,
		peerPublicKey: peerPublicKey,
	}, nil
}

func (w *WireGuard) SetKey(psk string) error {
	device, err := w.conn.Device(w.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", w.interfaceName, err)
	}
	found := false
	for _, peer := range device.Peers {
		if peer.PublicKey.String() == w.peerPublicKey {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("peer with public key %s not found on interface %s", w.peerPublicKey, w.interfaceName)
	}

	pskKey, err := wgtypes.ParseKey(psk)
	if err != nil {
		return fmt.Errorf("failed to parse PSK: %w", err)
	}
	publicKey, err := wgtypes.ParseKey(w.peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	return w.conn.ConfigureDevice(w.interfaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:    publicKey,
			UpdateOnly:   true,
			PresharedKey: &pskKey,
		}},
	})
}

func (w *WireGuard) Invalidate() error {
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}
	return w.SetKey(psk.String())
}
