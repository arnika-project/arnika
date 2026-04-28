package repositories

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireguardNetlinkRepository struct {
	InterfaceName string
	PeerPublicKey string
	conn          *wgctrl.Client
}

func NewWireguardNetlinkRepository(interfaceName, peerPublicKey string) (*WireguardNetlinkRepository, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
	}
	return &WireguardNetlinkRepository{
		InterfaceName: interfaceName,
		PeerPublicKey: peerPublicKey,
		conn:          client,
	}, nil
}

func (r *WireguardNetlinkRepository) InvalidateTunnel() error {
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}
	return r.SetPSK(psk.String())
}

func (r *WireguardNetlinkRepository) SetPSK(psk string) error {
	// Verify the specified interface exists
	peers, err := r.conn.Device(r.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", r.InterfaceName, err)
	}
	// verify that the peer public key exists
	for _, peer := range peers.Peers {
		if peer.PublicKey.String() != r.PeerPublicKey {
			return fmt.Errorf("peer with public key %s not found on interface %s", r.PeerPublicKey, r.InterfaceName)
		}
	}
	validPSK, err := wgtypes.ParseKey(psk)
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
