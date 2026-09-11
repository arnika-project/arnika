//go:build wireguard_netlink_netns

package main

import (
	"os"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/wgnetlink"
	"github.com/arnika-project/arnika/services"
)

func getKeyWriterService(cfg *config.Config) (*services.KeyWriterService, error) {
	netnsPath := os.Getenv("WIREGUARD_NETNS_PATH")
	wireguardRepo, err := wgnetlink.NewWireguardNetlinkNetnsRepository(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey, netnsPath)
	if err != nil {
		return nil, err
	}
	return services.NewKeyWriterService(wireguardRepo), nil
}
