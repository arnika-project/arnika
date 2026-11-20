// Package wgnetlink writes the WireGuard PSK through netlink, optionally inside a network namespace.
package wgnetlink

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Repository struct {
	InterfaceName string
	PeerPublicKey string
	conn          *wgctrl.Client
}

func NewRepository(interfaceName, peerPublicKey string) (*Repository, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
	}
	return &Repository{
		InterfaceName: interfaceName,
		PeerPublicKey: peerPublicKey,
		conn:          client,
	}, nil
}

func (r *Repository) SetPSK(psk []byte) error {
	peers, err := r.conn.Device(r.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", r.InterfaceName, err)
	}
	found := false
	for _, peer := range peers.Peers {
		if peer.PublicKey.String() == r.PeerPublicKey {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("peer with public key %s not found on interface %s", r.PeerPublicKey, r.InterfaceName)
	}
	validPSK, err := wgtypes.NewKey(psk)
	if err != nil {
		return err
	}
	validPeerPublicKey, err := wgtypes.ParseKey(r.PeerPublicKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:    validPeerPublicKey,
		UpdateOnly:   true,
		PresharedKey: &validPSK,
	}
	return r.conn.ConfigureDevice(r.InterfaceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
}

func (r *Repository) Close() error {
	return r.conn.Close()
}
