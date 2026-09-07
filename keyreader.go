package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/arnika-project/arnika/auth"
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
	"github.com/arnika-project/arnika/services"
)

func getQKDService(cfg *config.Config) *services.KeyReaderService {
	kmsAuth := repositories.NewKMSClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsRepo := repositories.NewHTTPKMSRepository(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	var managed services.KeyReaderManaged = kmsRepo
	return services.NewKeyReaderService(&managed)
}

// pqcSender seals a plaintext PQC frame in the Arnika envelope and sends it to
// the peer.
//
// The destination is pinned to SERVER_ADDRESS and never taken from an observed
// source address, so this cannot be used as a reflection primitive. The socket
// is dialled, not bound: it takes an ephemeral source port and adds no
// listener, leaving LISTEN_ADDRESS the only one Arnika serves.
func pqcSender(cfg *config.Config, dirOut auth.Direction) (func([]byte) error, error) {
	raddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve peer address %s: %w", cfg.ServerAddress, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer %s: %w", cfg.ServerAddress, err)
	}
	psk := cfg.ArnikaPSK

	return func(frame []byte) error {
		encrypted, err := auth.Encrypt(psk, frame)
		if err != nil {
			return fmt.Errorf("failed to encrypt PQC frame: %w", err)
		}
		pkt := &auth.Packet{
			Type:      auth.PacketPQC,
			Timestamp: time.Now().Unix(),
			Payload:   encrypted,
		}
		wire := base64.StdEncoding.EncodeToString(pkt.Marshal(psk, dirOut))
		if _, err := conn.Write([]byte(wire)); err != nil {
			return fmt.Errorf("failed to send PQC frame: %w", err)
		}
		return nil
	}, nil
}

// getPQCService wires the pqc-hpke key reader. It returns the reader service
// used by setPSK and the repository whose Run drives the agreement rounds.
func getPQCService(cfg *config.Config, inbound <-chan []byte, dirOut auth.Direction) (*services.KeyReaderService, *repositories.PQCHPKERepository, error) {
	send, err := pqcSender(cfg, dirOut)
	if err != nil {
		return nil, nil, err
	}

	// The role is pinned per round from the round index, using the same
	// derivation that decides PRIMARY/BACKUP for an interval.
	isInitiator := func(round uint32) bool {
		return cfg.IsPrimary(uint64(round))
	}

	pqcRepo, err := repositories.NewPQCHPKERepository(
		inbound, send, isInitiator,
		cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge,
	)
	if err != nil {
		return nil, nil, err
	}

	var unmanaged services.KeyReaderUnmanaged = pqcRepo
	return services.NewKeyReaderService(&unmanaged), pqcRepo, nil
}
