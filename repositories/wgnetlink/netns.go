//go:build linux

// containernetworking/plugins/pkg/ns is Linux-only, hence we restrict the build.

package wgnetlink

import (
	"errors"
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireguardNetlinkNetnsRepository struct {
	ifaceName     string
	peerPublicKey string
	netnsPath     string
}

func NewWireguardNetlinkNetnsRepository(interfaceName, peerPublicKey, netnsPath string) (*WireguardNetlinkNetnsRepository, error) {
	if netnsPath == "" {
		return nil, errors.New("WIREGUARD_NETNS_PATH must be set")
	}
	return &WireguardNetlinkNetnsRepository{
		ifaceName:     interfaceName,
		peerPublicKey: peerPublicKey,
		netnsPath:     netnsPath,
	}, nil
}

func (r *WireguardNetlinkNetnsRepository) InvalidateTunnel() error {
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}
	return r.SetPSK(psk.String())
}

func (r *WireguardNetlinkNetnsRepository) SetPSK(psk string) (err error) {
	targetNS, err := ns.GetNS(r.netnsPath)
	if err != nil {
		return fmt.Errorf("failed to open network namespace %s: %w", r.netnsPath, err)
	}
	defer func() {
		if closeErr := targetNS.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to close network namespace %s: %w", r.netnsPath, closeErr))
		}
	}()

	return targetNS.Do(func(_ ns.NetNS) error {
		delegateRepo, err := NewWireguardNetlinkRepository(r.ifaceName, r.peerPublicKey)
		if err != nil {
			return fmt.Errorf("failed to create netlink repository in namespace %s: %w", r.netnsPath, err)
		}
		defer func() { _ = delegateRepo.Close() }()
		return delegateRepo.SetPSK(psk)
	})
}
