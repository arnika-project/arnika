//go:build linux

package keyhandler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// MACsec genetlink constants from linux/if_macsec.h.
const (
	macsecGenlName = "macsec"

	macsecCmdAddRxsc = 1
	macsecCmdAddTxsa = 4
	macsecCmdDelTxsa = 5
	macsecCmdAddRxsa = 7
	macsecCmdDelRxsa = 8

	macsecAttrIfindex    = 1
	macsecAttrRxscConfig = 3
	macsecAttrSaConfig   = 4

	macsecRxscAttrSci    = 1
	macsecRxscAttrActive = 2

	macsecSaAttrAn     = 1
	macsecSaAttrActive = 2
	macsecSaAttrPn     = 3
	macsecSaAttrKey    = 4
	macsecSaAttrKeyid  = 5

	// rtnetlink: IFLA_MACSEC_ENCODING_SA from linux/if_link.h.
	iflaMacsecEncodingSA = 6
)

// MACsec injects keys into a MACsec interface via genetlink with hitless
// SA rotation. It maintains a sliding window of 2 active SAs (current +
// previous), cycling through association numbers 0-3.
//
// Rotation sequence:
//
//	Step 1: inject AN 0                → active: {0}
//	Step 2: inject AN 1                → active: {0, 1}
//	Step 3: inject AN 2, delete AN 0   → active: {1, 2}
//	Step 4: inject AN 3, delete AN 1   → active: {2, 3}
//	Step 5: inject AN 0, delete AN 2   → active: {3, 0}
type MACsec struct {
	gc      *genetlink.Conn
	family  genetlink.Family
	ifIndex int
	rxSCI   uint64
	calls   int // number of SetKey calls so far
}

func NewMACsec(interfaceName, rxSCI string) (*MACsec, error) {
	gc, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open genetlink: %w", err)
	}

	f, err := gc.GetFamily(macsecGenlName)
	if err != nil {
		_ = gc.Close()
		return nil, fmt.Errorf("macsec netlink family not found: %w", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		_ = gc.Close()
		return nil, fmt.Errorf("interface %s not found: %w", interfaceName, err)
	}

	sciBytes, err := hex.DecodeString(rxSCI)
	if err != nil || len(sciBytes) != 8 {
		_ = gc.Close()
		return nil, fmt.Errorf("MACSEC_RX_SCI must be 16 hex characters (8 bytes), got %q", rxSCI)
	}

	return &MACsec{
		gc:      gc,
		family:  f,
		ifIndex: iface.Index,
		rxSCI:   binary.BigEndian.Uint64(sciBytes),
	}, nil
}

func (m *MACsec) SetKey(psk string) error {
	keyBytes, err := base64.StdEncoding.DecodeString(psk)
	if err != nil {
		return fmt.Errorf("failed to decode PSK: %w", err)
	}
	if len(keyBytes) != 32 {
		return fmt.Errorf("PSK must be 32 bytes, got %d", len(keyBytes))
	}

	keyIDFull := sha256.Sum256(keyBytes)
	keyID := keyIDFull[:16]

	nextAN := uint8(m.calls % 4)

	// From the 3rd call onward, delete the SA two steps behind.
	if m.calls >= 2 {
		staleAN := uint8((m.calls - 2) % 4)
		_ = m.deleteTxSA(staleAN)
		_ = m.deleteRxSA(staleAN)
	}

	if err := m.ensureRxSC(); err != nil {
		return fmt.Errorf("failed to ensure RX SC: %w", err)
	}

	if err := m.addTxSA(nextAN, keyBytes, keyID); err != nil {
		return fmt.Errorf("failed to add TX SA %d: %w", nextAN, err)
	}
	if err := m.addRxSA(nextAN, keyBytes, keyID); err != nil {
		return fmt.Errorf("failed to add RX SA %d: %w", nextAN, err)
	}

	if err := m.setEncodingSA(nextAN); err != nil {
		return fmt.Errorf("failed to set encoding SA to %d: %w", nextAN, err)
	}

	m.calls++
	return nil
}

func (m *MACsec) Invalidate() error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}
	return m.SetKey(base64.StdEncoding.EncodeToString(key[:]))
}

// SA management via macsec genetlink.

func (m *MACsec) addTxSA(an uint8, key, keyID []byte) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, uint32(m.ifIndex))
	ae.Nested(macsecAttrSaConfig, encodeSAConfig(an, key, keyID))
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = m.execute(macsecCmdAddTxsa, netlink.Request|netlink.Acknowledge, attrs)
	return err
}

func (m *MACsec) addRxSA(an uint8, key, keyID []byte) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, uint32(m.ifIndex))
	ae.Nested(macsecAttrSaConfig, encodeSAConfig(an, key, keyID))
	ae.Nested(macsecAttrRxscConfig, func(nae *netlink.AttributeEncoder) error {
		nae.Uint64(macsecRxscAttrSci, m.rxSCI)
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = m.execute(macsecCmdAddRxsa, netlink.Request|netlink.Acknowledge, attrs)
	return err
}

func (m *MACsec) deleteTxSA(an uint8) error {
	return m.deleteSA(macsecCmdDelTxsa, an)
}

func (m *MACsec) deleteRxSA(an uint8) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, uint32(m.ifIndex))
	ae.Nested(macsecAttrSaConfig, func(nae *netlink.AttributeEncoder) error {
		nae.Uint8(macsecSaAttrAn, an)
		return nil
	})
	ae.Nested(macsecAttrRxscConfig, func(nae *netlink.AttributeEncoder) error {
		nae.Uint64(macsecRxscAttrSci, m.rxSCI)
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = m.execute(macsecCmdDelRxsa, netlink.Request|netlink.Acknowledge, attrs)
	return err
}

func (m *MACsec) deleteSA(command uint8, an uint8) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, uint32(m.ifIndex))
	ae.Nested(macsecAttrSaConfig, func(nae *netlink.AttributeEncoder) error {
		nae.Uint8(macsecSaAttrAn, an)
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = m.execute(command, netlink.Request|netlink.Acknowledge, attrs)
	return err
}

func (m *MACsec) ensureRxSC() error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, uint32(m.ifIndex))
	ae.Nested(macsecAttrRxscConfig, func(nae *netlink.AttributeEncoder) error {
		nae.Uint64(macsecRxscAttrSci, m.rxSCI)
		nae.Uint8(macsecRxscAttrActive, 1)
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = m.execute(macsecCmdAddRxsc, netlink.Request|netlink.Acknowledge, attrs)
	if isErrExist(err) {
		return nil
	}
	return err
}

// encoding SA via rtnetlink.

func (m *MACsec) setEncodingSA(an uint8) error {
	rc, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return err
	}
	defer rc.Close()

	ae := netlink.NewAttributeEncoder()
	ae.Nested(unix.IFLA_LINKINFO, func(nae *netlink.AttributeEncoder) error {
		nae.String(unix.IFLA_INFO_KIND, "macsec")
		nae.Nested(unix.IFLA_INFO_DATA, func(nnae *netlink.AttributeEncoder) error {
			nnae.Uint8(iflaMacsecEncodingSA, an)
			return nil
		})
		return nil
	})
	attrBytes, err := ae.Encode()
	if err != nil {
		return err
	}

	ifinfo := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(ifinfo[4:8], uint32(m.ifIndex))

	_, err = rc.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_SETLINK,
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(ifinfo, attrBytes...),
	})
	return err
}

// helpers.

func encodeSAConfig(an uint8, key, keyID []byte) func(*netlink.AttributeEncoder) error {
	return func(nae *netlink.AttributeEncoder) error {
		nae.Uint8(macsecSaAttrAn, an)
		nae.Uint32(macsecSaAttrPn, 1)
		nae.Bytes(macsecSaAttrKey, key)
		nae.Bytes(macsecSaAttrKeyid, keyID)
		nae.Uint8(macsecSaAttrActive, 1)
		return nil
	}
}

func (m *MACsec) execute(command uint8, flags netlink.HeaderFlags, attrb []byte) ([]genetlink.Message, error) {
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: 1,
		},
		Data: attrb,
	}
	return m.gc.Execute(msg, m.family.ID, flags)
}

func isErrExist(err error) bool {
	if err == nil {
		return false
	}
	oerr, ok := err.(*netlink.OpError)
	if !ok {
		return false
	}
	return oerr.Err == unix.EEXIST
}
