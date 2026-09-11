//go:build wireguard_mikrotik

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/wgmikrotik"
	"github.com/arnika-project/arnika/services"
)

// getKeyWriterService wires the MikroTik RouterOS REST key writer. It is the
// wireguard_mikrotik counterpart of the netlink implementation in
// wireguardnetlink.go; exactly one of the two is compiled per binary, selected
// by build tag. MikroTik-specific transport configuration is read here (behind
// the build tag) so the shared config.Config stays transport-agnostic, while
// the WireGuard interface and peer public key are reused from the shared config.
func getKeyWriterService(cfg *config.Config) (*services.KeyWriterService, error) {
	baseURL := os.Getenv("MIKROTIK_URL")
	if baseURL == "" {
		return nil, fmt.Errorf("[ERROR] MIKROTIK_URL is required for the wireguard_mikrotik build")
	}
	username := os.Getenv("MIKROTIK_USERNAME")
	password := os.Getenv("MIKROTIK_PASSWORD")
	if username == "" || password == "" {
		return nil, fmt.Errorf("[ERROR] MIKROTIK_USERNAME and MIKROTIK_PASSWORD are required for the wireguard_mikrotik build")
	}

	timeout := 10 * time.Second
	if v := os.Getenv("MIKROTIK_HTTP_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("[ERROR] failed to parse MIKROTIK_HTTP_TIMEOUT: %w", err)
		}
		timeout = d
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case os.Getenv("MIKROTIK_TLS_INSECURE") == "true":
		// Explicit opt-in: skip certificate verification. Intended for lab use
		// with RouterOS self-signed certificates only. Never use in production;
		// prefer MIKROTIK_CA_CERTIFICATE to pin the router's CA instead.
		tlsCfg.InsecureSkipVerify = true
	case os.Getenv("MIKROTIK_CA_CERTIFICATE") != "":
		caCert, err := os.ReadFile(os.Getenv("MIKROTIK_CA_CERTIFICATE"))
		if err != nil {
			return nil, fmt.Errorf("[ERROR] failed to read MIKROTIK_CA_CERTIFICATE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("[ERROR] MIKROTIK_CA_CERTIFICATE contains no valid PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			Proxy:           http.ProxyFromEnvironment,
		},
	}

	repo := wgmikrotik.NewWireguardMikrotikRepository(
		baseURL,
		username,
		password,
		cfg.WireGuardInterface,
		cfg.WireguardPeerPublicKey,
		client,
	)
	return services.NewKeyWriterService(repo), nil
}
