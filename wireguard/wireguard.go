package wg

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardHandler provides an interface to the WireGuard client.
type WireGuardHandler struct {
	// conn is the WireGuard client connection.
	conn *wgctrl.Client
}

// New initializes a new WireGuardHandler.
//
// No parameters.
// Returns a pointer to a WireGuardHandler and an error.
func NewWireGuardHandler() (*WireGuardHandler, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &WireGuardHandler{conn: client}, nil
}

// SetKey sets the preshared key for a WireGuard device.
//
// Parameters:
// - interfaceName: the name of the WireGuard interface.
// - peerPublicKey: the public key of the peer.
// - pskString: the preshared key as a string.
//
// Returns:
// - error: an error if any occurred during the process.
func (wg *WireGuardHandler) SetKey(interfaceName, peerPublicKey, pskString string) error {
	devices, err := wg.conn.Devices()
	if err != nil {
		return err
	}
	if len(devices) != 1 {
		return fmt.Errorf("expected 1 wireguard device, found %d", len(devices))
	}
	psk, err := wgtypes.ParseKey(pskString)
	if err != nil {
		return err
	}
	publicKey, err := wgtypes.ParseKey(peerPublicKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:    publicKey,
		UpdateOnly:   true,
		PresharedKey: &psk,
	}
	return wg.conn.ConfigureDevice(interfaceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
}
