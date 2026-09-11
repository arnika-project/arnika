// Package transport carries Arnika's peer protocol: the authenticated UDP
// listener that both the QKD key identifier and the PQC key-agreement frames
// travel over, the client that sends one identifier and waits for its
// acknowledgement, and the per-IP rate limit that bounds all of it.
package transport

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/auth"
)

// QKDQueueDepth bounds the hand-off between the UDP read loop and the QKD
// worker. It is deliberately small: the worker performs one KMS request and one
// key-writer operation per identifier, so a deeper queue would only accumulate
// identifiers whose keys are superseded by the time they are served. Eight
// absorbs a burst of sender retries; past that the sender's own retry policy is
// the right backpressure, not more memory here.
//
// Not externally configurable: an operator has no information with which to
// size this better than the protocol does.
const QKDQueueDepth = 8

// qkdQueueWarnEvery throttles the queue-full warning. It is emitted from a
// packet path, so an unthrottled one would let flood traffic turn logging into
// a denial of service.
const qkdQueueWarnEvery = 10 * time.Second

// PQCHandler consumes one verified, decrypted PQC frame and may answer the
// sender through reply, which sends one plaintext frame back. Implemented by
// pqchpke.Repository.HandleFrame. Neither the handler nor reply may
// block: both run on the UDP read loop, which also carries the QKD path.
type PQCHandler func(frame []byte, reply func(frame []byte) error) error

// Serve listens for incoming UDP packets using the security-hardened protocol:
//   - HMAC-SHA256 signature verification (authentication)
//   - Timestamp validation (replay protection)
//   - Per-IP rate limiting (flood protection)
//   - Constant-time checks, uniform error messages (side-channel resistance)
//
// Protocol flow:
//  1. Client sends DATA packet (signed + encrypted payload) -> Server enqueues
//     the key id on the bounded QKD queue and replies with ACK
//  2. Peer sends PQC packets (key agreement frames) -> handed to pqcHandle, which
//     answers on this socket when the exchange calls for a reply
//
// dirIn is the direction the peer signs with; dirOut is this node's own.
// pqcHandle is nil when no PQC key reader is wired, and PQC packets are dropped.
//
// logger is passed in rather than taken from a package variable: three of those
// used to hold preformatted role prefixes, assigned inside main() after the
// configuration was parsed, so anything logging before that point silently
// emitted an empty prefix.
func Serve(address string, psk []byte, dirOut, dirIn auth.Direction, result chan string, done chan bool, pqcHandle PQCHandler, rateLimit int, rateWindow, maxClockSkew time.Duration, logger *slog.Logger) error {
	// Receiving is the BACKUP side of an interval by definition: the peer only
	// sends a key_id when it is PRIMARY.
	backupLog := logger.With("role", "backup")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("failed to resolve the UDP listen address %s: %w", address, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", address, err)
	}
	logger.Info("UDP server started", "address", address)

	// Rate limiter: configurable requests per IP per window
	limiter := newRateLimiter(rateLimit, rateWindow)
	// Local to this loop, which is a single goroutine, so it needs no lock.
	queueFullWarn := logThrottle{interval: qkdQueueWarnEvery}

	go func() {
		<-quit
		logger.Info("UDP server shutdown triggered", "address", address)
		close(done)
		_ = conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-done:
				return nil
			default:
				logger.Error("UDP read error", "err", err)
				continue
			}
		}

		clientIP := remoteAddr.IP.String()

		// 1. Rate limit check (cheapest, no crypto)
		if !limiter.Allow(clientIP) {
			backupLog.Debug("rate limited", "peer", remoteAddr)
			continue
		}

		// 2. Unmarshal + HMAC verify (cheap, before any decryption)
		pkt, err := auth.UnmarshalPacket(psk, buf[:n], dirIn)
		if err != nil {
			backupLog.Warn("packet rejected", "peer", remoteAddr, "reason", "authentication")
			continue
		}

		// 3. Timestamp check (replay protection)
		if !auth.WithinSkew(pkt.Timestamp, maxClockSkew) {
			backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "timestamp")
			continue
		}

		// 4. Dispatch by type, decrypting only after all cheap checks pass
		switch pkt.Type {
		case auth.PacketData:
			decrypted, err := auth.Decrypt(psk, pkt.Payload)
			if err != nil {
				backupLog.Error("packet rejected, ARNIKA_PSK mismatch or the message is corrupted",
					"peer", remoteAddr, "reason", "decryption")
				continue
			}

			// 5. Hand the identifier to the bounded QKD queue, without
			// blocking. Its worker performs the KMS request and the key-writer
			// operation synchronously, so a blocking send stalled this read
			// loop - and with it every PQC frame arriving on the same socket -
			// for the length of a KMS outage.
			//
			// Enqueued before the ACK, never after: the ACK is the sender's
			// only signal that it need not retry, so it has to reflect
			// in-process acceptance rather than a successful decryption. A full
			// queue therefore stays unacknowledged and the sender retries.
			select {
			case result <- string(decrypted):
			default:
				if queueFullWarn.allow() {
					backupLog.Warn("QKD queue full, key_id not acknowledged; the sender will retry",
						"slots", cap(result), "peer", remoteAddr)
				}
				continue
			}

			// 6. Send ACK
			ack := &auth.Packet{
				Type:      auth.PacketAck,
				Timestamp: time.Now().Unix(),
			}
			_, _ = conn.WriteToUDP(ack.Marshal(psk, dirOut), remoteAddr)

			backupLog.Info("received a key_id from the peer", "key_id", string(decrypted), "peer", remoteAddr)

		case auth.PacketPQC:
			if pqcHandle == nil {
				backupLog.Debug("PQC frame dropped, no PQC key reader wired", "peer", remoteAddr)
				continue
			}
			decrypted, err := auth.Decrypt(psk, pkt.Payload)
			if err != nil {
				backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "decryption")
				continue
			}
			// The PQC responder answers on this socket, back to the sender,
			// exactly as the ACK above does. A reply goes out only after the
			// rate limit, the HMAC and the timestamp have passed, so eliciting
			// one requires the PSK: this is not a reflection primitive.
			reply := func(frame []byte) error {
				encrypted, err := auth.Encrypt(psk, frame)
				if err != nil {
					return err
				}
				out := &auth.Packet{
					Type:      auth.PacketPQC,
					Timestamp: time.Now().Unix(),
					Payload:   encrypted,
				}
				_, err = conn.WriteToUDP(out.Marshal(psk, dirOut), remoteAddr)
				return err
			}
			if err := pqcHandle(decrypted, reply); err != nil {
				backupLog.Warn("PQC frame not accepted", "peer", remoteAddr, "err", err)
			}

		default:
			backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "unknown type")
			continue
		}
	}
}

// udpClientMaxAttempts is how many times SendKeyID sends one key id while
// waiting for an ACK, so it is also how many DATA packets one QKD interval can
// legitimately deliver to the peer's listening socket. Shared with the
// rate-limit budget so the two cannot drift.
const udpClientMaxAttempts = 3

// SendKeyID sends an encrypted, HMAC-signed key ID to the peer via the security-hardened
// UDP protocol. Retries up to udpClientMaxAttempts times on timeout.
//
// Protocol flow:
//  1. Send DATA (signed + encrypted keyID) -> Receive ACK
func SendKeyID(address string, psk []byte, dirOut, dirIn auth.Direction, keyID string, timeout time.Duration, maxClockSkew time.Duration, logger *slog.Logger) error {
	if address == "" {
		return fmt.Errorf("address is empty")
	}
	if keyID == "" {
		return fmt.Errorf("keyID is empty")
	}

	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer func() { _ = conn.Close() }()

	for attempt := 1; attempt <= udpClientMaxAttempts; attempt++ {
		// Step 1: Encrypt keyID and send DATA packet
		encrypted, err := auth.Encrypt(psk, []byte(keyID))
		if err != nil {
			return fmt.Errorf("failed to encrypt key_id: %w", err)
		}
		dataPkt := &auth.Packet{
			Type:      auth.PacketData,
			Timestamp: time.Now().Unix(),
			Payload:   encrypted,
		}
		_, err = conn.Write(dataPkt.Marshal(psk, dirOut))
		if err != nil {
			return fmt.Errorf("failed to write DATA packet: %w", err)
		}

		// Step 2: Wait for ACK
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}
		ackBuf := make([]byte, 1024)
		n, err := conn.Read(ackBuf)
		if err != nil {
			if attempt < udpClientMaxAttempts {
				logger.Debug("ACK timeout, retrying", "attempt", attempt, "of", udpClientMaxAttempts)
				continue
			}
			return fmt.Errorf("no ACK after %d attempts: %w", udpClientMaxAttempts, err)
		}

		ackPkt, err := auth.UnmarshalPacket(psk, ackBuf[:n], dirIn)
		if err != nil {
			return fmt.Errorf("authentication failed")
		}
		if ackPkt.Type != auth.PacketAck {
			return fmt.Errorf("authentication failed")
		}
		if !auth.WithinSkew(ackPkt.Timestamp, maxClockSkew) {
			return fmt.Errorf("authentication failed")
		}

		return nil // success
	}
	return fmt.Errorf("unreachable")
}

// RunKeyIDWorker services the bounded QKD queue until done is closed.
//
// One worker, not a pool: handle performs the KMS request and the key-writer
// operation, so two of them running concurrently could install PSKs in the
// reverse of the order the peer sent the identifiers. A channel is FIFO, so a
// single consumer is what preserves that order.
//
// It returns on done rather than looping forever, so the worker cannot outlive
// the UDP server that feeds it.
func RunKeyIDWorker(done <-chan bool, queue <-chan string, handle func(keyID string)) {
	for {
		select {
		case <-done:
			return
		case keyID := <-queue:
			handle(keyID)
		}
	}
}
