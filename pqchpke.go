// Wiring for the pqc-hpke key reader (PQC, unmanaged). The only PQC backend, so
// it carries no build tag yet: a second one gets its own file plus the family
// constraint `pqc_hpke || !pqc_<other>` here. See KEYCONTROL.md.

package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/arnika-project/arnika/auth"
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
	"github.com/arnika-project/arnika/services"
)

// pqcDial opens the initiator's request/response channel to the peer: a
// connected UDP socket, the same shape udpClient uses for the QKD key id. The
// peer answers the source address, so the reply arrives here rather than on the
// listening socket, which is what keeps the exchange synchronous.
//
// The destination is pinned to SERVER_ADDRESS and never taken from an observed
// source address, so this cannot be used as a reflection primitive. The socket
// is dialled, not bound: it takes an ephemeral source port and adds no
// listener, leaving LISTEN_ADDRESS the only one Arnika serves.
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

	// The same checks the UDP server applies, minus the rate limit: a connected
	// socket already drops anything not coming from SERVER_ADDRESS. Rejected
	// datagrams are skipped rather than returned, so a peer spraying junk costs
	// a loop iteration and not the round; the read deadline bounds the loop.
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

// getPQCService wires the pqc-hpke key reader. It returns the reader service
// used by setPSK, the round driver main.go runs in its own goroutine, and the
// responder handler the UDP server calls for inbound PQC frames. The last two
// are returned as functions, not as the concrete repository, so that a second
// PQC backend can be wired behind its own build tag without touching main.go.
func getPQCService(cfg *config.Config, dirOut, dirIn auth.Direction) (
	*services.KeyReaderService, func(context.Context), pqcHandler, error,
) {
	send, recv, err := pqcDial(cfg, dirOut, dirIn)
	if err != nil {
		return nil, nil, nil, err
	}

	// Both peers derive this from the same PSK and the same clock-derived round
	// index, using the same derivation that decides PRIMARY/BACKUP for an
	// interval, so exactly one of them initiates a given round.
	isInitiator := func(round uint32) bool {
		return cfg.IsPrimary(uint64(round))
	}

	pqcRepo, err := repositories.NewPQCHPKERepository(
		PQCHPKELOGPREFIX, send, recv, isInitiator,
		cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	var unmanaged services.KeyReaderUnmanaged = pqcRepo
	return services.NewKeyReaderService(&unmanaged), pqcRepo.Run, pqcRepo.HandleFrame, nil
}
