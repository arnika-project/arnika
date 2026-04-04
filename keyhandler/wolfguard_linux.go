//go:build linux

package keyhandler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

const wolfGuardGenlName = "wolfguard"

// WolfGuard injects PSKs into a wolfGuard interface via generic netlink.
// wolfGuard uses the same netlink attribute IDs as WireGuard but with a
// different family name ("wolfguard") and larger ECC public keys (65-byte
// uncompressed SECP256R1 instead of 32-byte Curve25519).
type WolfGuard struct {
	c             *genetlink.Conn
	family        genetlink.Family
	interfaceName string
	peerPublicKey string // base64-encoded
}

func NewWolfGuard(interfaceName, peerPublicKey string) (*WolfGuard, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open genetlink: %w", err)
	}

	f, err := c.GetFamily(wolfGuardGenlName)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("wolfguard netlink family not found (is the kernel module loaded?): %w", err)
	}

	return &WolfGuard{
		c:             c,
		family:        f,
		interfaceName: interfaceName,
		peerPublicKey: peerPublicKey,
	}, nil
}

func (w *WolfGuard) SetKey(psk string) error {
	peerPubKeyBytes, err := base64.StdEncoding.DecodeString(w.peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode peer public key: %w", err)
	}

	// Verify the peer exists on the interface.
	peers, err := w.getPeerPublicKeys()
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", w.interfaceName, err)
	}
	found := false
	for _, p := range peers {
		if base64.StdEncoding.EncodeToString(p) == w.peerPublicKey {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("peer with public key %s not found on interface %s", w.peerPublicKey, w.interfaceName)
	}

	pskBytes, err := base64.StdEncoding.DecodeString(psk)
	if err != nil {
		return fmt.Errorf("failed to decode PSK: %w", err)
	}
	if len(pskBytes) != 32 {
		return fmt.Errorf("PSK must be 32 bytes, got %d", len(pskBytes))
	}

	return w.configurePSK(peerPubKeyBytes, pskBytes)
}

func (w *WolfGuard) Invalidate() error {
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return fmt.Errorf("failed to generate random PSK: %w", err)
	}
	return w.SetKey(base64.StdEncoding.EncodeToString(psk[:]))
}

// getPeerPublicKeys queries the wolfguard device and returns the raw public
// key bytes for each configured peer.
func (w *WolfGuard) getPeerPublicKeys() ([][]byte, error) {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(w.interfaceName),
	}})
	if err != nil {
		return nil, err
	}

	msgs, err := w.execute(unix.WG_CMD_GET_DEVICE, netlink.Request|netlink.Dump, b)
	if err != nil {
		return nil, err
	}

	var keys [][]byte
	for _, m := range msgs {
		parsed, err := parseWolfGuardPeerKeys(m)
		if err != nil {
			return nil, err
		}
		keys = append(keys, parsed...)
	}
	return keys, nil
}

func parseWolfGuardPeerKeys(m genetlink.Message) ([][]byte, error) {
	ad, err := netlink.NewAttributeDecoder(m.Data)
	if err != nil {
		return nil, err
	}

	var keys [][]byte
	for ad.Next() {
		if ad.Type() != unix.WGDEVICE_A_PEERS {
			continue
		}
		ad.Nested(func(nad *netlink.AttributeDecoder) error {
			for nad.Next() {
				nad.Nested(func(nnad *netlink.AttributeDecoder) error {
					for nnad.Next() {
						if nnad.Type() == unix.WGPEER_A_PUBLIC_KEY {
							key := make([]byte, len(nnad.Bytes()))
							copy(key, nnad.Bytes())
							keys = append(keys, key)
						}
					}
					return nil
				})
			}
			return nil
		})
	}

	if err := ad.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func (w *WolfGuard) configurePSK(peerPubKey, psk []byte) error {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, w.interfaceName)
	ae.Nested(unix.WGDEVICE_A_PEERS, func(nae *netlink.AttributeEncoder) error {
		nae.Nested(0, func(pae *netlink.AttributeEncoder) error {
			pae.Bytes(unix.WGPEER_A_PUBLIC_KEY, peerPubKey)
			pae.Uint32(unix.WGPEER_A_FLAGS, unix.WGPEER_F_UPDATE_ONLY)
			pae.Bytes(unix.WGPEER_A_PRESHARED_KEY, psk)
			return nil
		})
		return nil
	})

	attrs, err := ae.Encode()
	if err != nil {
		return err
	}

	_, err = w.execute(unix.WG_CMD_SET_DEVICE, netlink.Request|netlink.Acknowledge, attrs)
	return err
}

func (w *WolfGuard) execute(command uint8, flags netlink.HeaderFlags, attrb []byte) ([]genetlink.Message, error) {
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: 1,
		},
		Data: attrb,
	}
	return w.c.Execute(msg, w.family.ID, flags)
}
