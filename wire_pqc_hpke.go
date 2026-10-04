package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/arnika-project/arnika/auth"
	"log/slog"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/pqchpke"
	"github.com/arnika-project/arnika/services"
	"github.com/arnika-project/arnika/transport"
)

// pqcDial gives the initiator its own socket connected to SERVER_ADDRESS, so the responder's reply arrives here and not on the listener.
func pqcDial(cfg *config.Config, dirOut, dirIn auth.Direction) (
	send func(frame []byte) error,
	recv func(deadline time.Time) ([]byte, error),
	err error,
) {
	raddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve peer address %s: %w", cfg.ServerAddress, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial peer %s: %w", cfg.ServerAddress, err)
	}
	psk := cfg.ArnikaPSK
	maxClockSkew := cfg.MaxClockSkew

	send = func(frame []byte) error {
		encrypted, err := auth.Encrypt(psk, frame)
		if err != nil {
			return fmt.Errorf("failed to encrypt PQC frame: %w", err)
		}
		pkt := &auth.Packet{
			Type:      auth.PacketPQC,
			Timestamp: time.Now().Unix(),
			Payload:   encrypted,
		}
		if _, err := conn.Write(pkt.Marshal(psk, dirOut)); err != nil {
			return fmt.Errorf("failed to send PQC frame: %w", err)
		}
		return nil
	}

	buf := make([]byte, 2048)
	recv = func(deadline time.Time) ([]byte, error) {
		for {
			if err := conn.SetReadDeadline(deadline); err != nil {
				return nil, err
			}
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			pkt, err := auth.UnmarshalPacket(psk, buf[:n], dirIn)
			if err != nil || pkt.Type != auth.PacketPQC {
				continue
			}
			if !auth.WithinSkew(pkt.Timestamp, maxClockSkew) {
				continue
			}
			frame, err := auth.Decrypt(psk, pkt.Payload)
			if err != nil {
				continue
			}
			return frame, nil
		}
	}
	return send, recv, nil
}

func getPQCService(cfg *config.Config, logger *slog.Logger, dirOut, dirIn auth.Direction) (
	*services.KeyReaderService, func(context.Context), transport.PQCHandler, error,
) {
	send, recv, err := pqcDial(cfg, dirOut, dirIn)
	if err != nil {
		return nil, nil, nil, err
	}

	isInitiator := func(round uint32) bool {
		return cfg.IsPrimary(uint64(round))
	}

	pqcRepo, err := pqchpke.NewRepository(
		logger, send, recv, isInitiator,
		cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return services.NewKeyReaderService(pqcReader{pqcRepo}), pqcRepo.Run, pqcRepo.HandleFrame, nil
}

// pqcReader lacks GetKeyByID on purpose: that is how services.KeyReaderService learns there is no key id to resolve.
type pqcReader struct{ repo *pqchpke.Repository }

func (r pqcReader) GetNewKey() (string, []byte, error) {
	key, err := r.repo.GetNewKey()
	return "", key, err
}
