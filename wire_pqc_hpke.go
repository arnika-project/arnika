package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/arnika-project/arnika/auth"
	"log/slog"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/pqchpke"
	"github.com/arnika-project/arnika/services"
	"github.com/arnika-project/arnika/transport"
)

// pqcDial gives the primary an unconnected socket: it reports no spoofable ICMP errors, and the backup's reply to its source address also finds it behind NAT.
func pqcDial(cfg *config.Config, dirOut, dirIn auth.Direction) (
	send func(frame []byte) error,
	recv func(deadline time.Time) ([]byte, error),
	err error,
) {
	raddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve peer address %s: %w", cfg.ServerAddress, err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open a UDP socket for peer %s: %w", cfg.ServerAddress, err)
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
		if _, err := conn.WriteToUDP(pkt.Marshal(psk, dirOut), raddr); err != nil {
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
			n, _, err := conn.ReadFromUDP(buf)
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

// pqcLink gives the primary, which initiates every round, its socket to the backup; the backup only answers through Serve's reply.
func pqcLink(cfg *config.Config, dirOut, dirIn auth.Direction) (
	send func(frame []byte) error,
	recv func(deadline time.Time) ([]byte, error),
	err error,
) {
	if cfg.IsPrimary() {
		return pqcDial(cfg, dirOut, dirIn)
	}
	errBackup := errors.New("the backup never starts a PQC round")
	return func([]byte) error { return errBackup }, func(time.Time) ([]byte, error) { return nil, errBackup }, nil
}

func getPQCService(cfg *config.Config, logger *slog.Logger, dirOut, dirIn auth.Direction) (
	*services.KeyReaderService, func(context.Context), transport.PQCHandler, error,
) {
	send, recv, err := pqcLink(cfg, dirOut, dirIn)
	if err != nil {
		return nil, nil, nil, err
	}
	isInitiator := func(uint32) bool { return cfg.IsPrimary() }

	pqcRepo, err := pqchpke.NewRepository(
		logger, send, recv, isInitiator,
		cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return services.NewKeyReaderService(pqcReader{pqcRepo}), pqcRepo.Run, pqcRepo.HandleFrame, nil
}

// pqcReader names each key by its round, so the backup can tell the primary which round its PSK was derived from.
type pqcReader struct{ repo *pqchpke.Repository }

func (r pqcReader) GetNewKey() (string, []byte, error) {
	round, key, err := r.repo.Latest()
	if err != nil {
		return "", nil, err
	}
	return strconv.FormatUint(uint64(round), 10), key, nil
}

func (r pqcReader) GetKeyByID(id string) ([]byte, error) {
	round, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("pqc-hpke: %q names no round: %w", id, err)
	}
	return r.repo.KeyForRound(uint32(round))
}
