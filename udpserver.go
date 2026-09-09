package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/auth"
)

// qkdQueueDepth bounds the hand-off between the UDP read loop and the QKD
// worker. It is deliberately small: the worker performs one KMS request and one
// key-writer operation per identifier, so a deeper queue would only accumulate
// identifiers whose keys are superseded by the time they are served. Eight
// absorbs a burst of sender retries; past that the sender's own retry policy is
// the right backpressure, not more memory here.
//
// Not externally configurable: an operator has no information with which to
// size this better than the protocol does.
const qkdQueueDepth = 8

// qkdQueueWarnEvery throttles the queue-full warning. It is emitted from a
// packet path, so an unthrottled one would let flood traffic turn logging into
// a denial of service.
const qkdQueueWarnEvery = 10 * time.Second

// pqcHandler consumes one verified, decrypted PQC frame and may answer the
// sender through reply, which sends one plaintext frame back. Implemented by
// repositories.PQCHPKERepository.HandleFrame. Neither the handler nor reply may
// block: both run on the UDP read loop, which also carries the QKD path.
type pqcHandler func(frame []byte, reply func(frame []byte) error) error

// udpServer listens for incoming UDP packets using the security-hardened protocol:
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
func udpServer(address string, psk []byte, dirOut, dirIn auth.Direction, result chan string, done chan bool, pqcHandle pqcHandler, rateLimit int, rateWindow, maxClockSkew time.Duration) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		log.Panicf("[ERROR] failed to resolve UDP address %s: %v", address, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Panicf("[ERROR] failed to listen on UDP %s: %v", address, err)
	}
	log.Printf("[INFO] %s UDP server started on %s\n", ARNIKALOGPREFIX, address)

	// Rate limiter: configurable requests per IP per window
	limiter := newRateLimiter(rateLimit, rateWindow)
	// Local to this loop, which is a single goroutine, so it needs no lock.
	queueFullWarn := logThrottle{interval: qkdQueueWarnEvery}

	go func() {
		<-quit
		log.Printf("[INFO] %s UDP server shutdown triggered on %s", ARNIKALOGPREFIX, address)
		close(done)
		_ = conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-done:
				return
			default:
				log.Printf("[ERROR] %s UDP read error: %v", ARNIKALOGPREFIX, err)
				continue
			}
		}

		clientIP := remoteAddr.IP.String()

		// 1. Rate limit check (cheapest, no crypto)
		if !limiter.Allow(clientIP) {
			log.Printf("[DEBUG] %s rate limited %s", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		// 2. Unmarshal + HMAC verify (cheap, before any decryption)
		pkt, err := auth.UnmarshalPacket(psk, buf[:n], dirIn)
		if err != nil {
			log.Printf("[WARNING] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		// 3. Timestamp check (replay protection)
		if !auth.WithinSkew(pkt.Timestamp, maxClockSkew) {
			log.Printf("[DEBUG] %s packet rejected from %s (timestamp)", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		// 4. Dispatch by type, decrypting only after all cheap checks pass
		switch pkt.Type {
		case auth.PacketData:
			decrypted, err := auth.Decrypt(psk, pkt.Payload)
			if err != nil {
				log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
				log.Printf("[ERROR] %s authentication failed, psk mismatch or message corrupted", BACKUPLOGPREFIX)
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
					log.Printf("[WARNING] %s QKD queue full (%d slots), key_id from %s not acknowledged; the sender will retry",
						BACKUPLOGPREFIX, cap(result), remoteAddr)
				}
				continue
			}

			// 6. Send ACK
			ack := &auth.Packet{
				Type:      auth.PacketAck,
				Timestamp: time.Now().Unix(),
			}
			_, _ = conn.WriteToUDP(ack.Marshal(psk, dirOut), remoteAddr)

			log.Printf("[INFO] %s [RCV] received key_id %s from %s", BACKUPLOGPREFIX, string(decrypted), remoteAddr)

		case auth.PacketPQC:
			if pqcHandle == nil {
				log.Printf("[DEBUG] %s pqc frame dropped, no PQC key reader wired", BACKUPLOGPREFIX)
				continue
			}
			decrypted, err := auth.Decrypt(psk, pkt.Payload)
			if err != nil {
				log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
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
				log.Printf("[WARNING] %s pqc frame from %s: %v", BACKUPLOGPREFIX, remoteAddr, err)
			}

		default:
			log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
			continue
		}
	}
}

// udpClient sends an encrypted, HMAC-signed key ID to the peer via the security-hardened
// UDP protocol. Retries up to 3 times on timeout.
//
// Protocol flow:
//  1. Send DATA (signed + encrypted keyID) -> Receive ACK
func udpClient(address string, psk []byte, dirOut, dirIn auth.Direction, keyID string, timeout time.Duration, maxClockSkew time.Duration) error {
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

	const maxRetries = 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
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
			if attempt < maxRetries {
				log.Printf("[DEBUG] %s ACK timeout (attempt %d/%d), retrying...", PRIMARYLOGPREFIX, attempt, maxRetries)
				continue
			}
			return fmt.Errorf("no ACK after %d attempts: %w", maxRetries, err)
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

// runQKDWorker services the bounded QKD queue until done is closed.
//
// One worker, not a pool: handle performs the KMS request and the key-writer
// operation, so two of them running concurrently could install PSKs in the
// reverse of the order the peer sent the identifiers. A channel is FIFO, so a
// single consumer is what preserves that order.
//
// It returns on done rather than looping forever, so the worker cannot outlive
// the UDP server that feeds it.
func runQKDWorker(done <-chan bool, queue <-chan string, handle func(keyID string)) {
	for {
		select {
		case <-done:
			return
		case keyID := <-queue:
			handle(keyID)
		}
	}
}
