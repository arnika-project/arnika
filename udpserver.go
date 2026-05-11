package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/auth"
)

// udpServer listens for incoming UDP packets using the security-hardened protocol:
//   - HMAC-SHA256 signature verification (authentication)
//   - Timestamp validation (replay protection)
//   - Per-IP rate limiting (flood protection)
//   - Constant-time checks, uniform error messages (side-channel resistance)
//
// Protocol flow:
//  1. Client sends DATA packet (signed + encrypted payload) -> Server replies with ACK
func udpServer(address string, psk []byte, result chan string, done chan bool, rateLimit int, rateWindow, maxClockSkew time.Duration) {
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

		// 2. Base64 decode
		raw, err := base64.StdEncoding.DecodeString(string(buf[:n]))
		if err != nil {
			log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		// 3. Unmarshal + HMAC verify (cheap, before any decryption)
		pkt, err := auth.UnmarshalPacket(psk, raw)
		if err != nil {
			log.Printf("[WARNING] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		// 4. Timestamp check (replay protection)
		now := time.Now().Unix()
		diff := now - pkt.Timestamp
		if diff < 0 {
			diff = -diff
		}
		if diff > int64(maxClockSkew.Seconds()) {
			log.Printf("[DEBUG] %s packet rejected from %s (timestamp)", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		if pkt.Type != auth.PacketData {
			log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		// 5. Decrypt payload (expensive, only after all cheap checks pass)
		decrypted, err := auth.Decrypt(psk, pkt.Payload)
		if err != nil {
			log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
			log.Printf("[ERROR] %s authentication failed, psk mismatch or message corrupted", BACKUPLOGPREFIX)
			continue
		}

		// 6. Send ACK
		ack := &auth.Packet{
			Type:      auth.PacketAck,
			Timestamp: time.Now().Unix(),
		}
		ackB64 := base64.StdEncoding.EncodeToString(ack.Marshal(psk))
		_, _ = conn.WriteToUDP([]byte(ackB64), remoteAddr)

		log.Printf("[INFO] %s [RCV] received key_id %s from %s", BACKUPLOGPREFIX, string(decrypted), remoteAddr)
		result <- string(decrypted)
	}
}

// udpClient sends an encrypted, HMAC-signed key ID to the peer via the security-hardened
// UDP protocol. Retries up to 3 times on timeout.
//
// Protocol flow:
//  1. Send DATA (signed + encrypted keyID) -> Receive ACK
func udpClient(address string, psk []byte, keyID string, timeout time.Duration, maxClockSkew time.Duration) error {
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
		dataBytes := base64.StdEncoding.EncodeToString(dataPkt.Marshal(psk))
		_, err = conn.Write([]byte(dataBytes))
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

		ackRaw, err := base64.StdEncoding.DecodeString(string(ackBuf[:n]))
		if err != nil {
			return fmt.Errorf("authentication failed")
		}
		ackPkt, err := auth.UnmarshalPacket(psk, ackRaw)
		if err != nil {
			return fmt.Errorf("authentication failed")
		}
		if ackPkt.Type != auth.PacketAck {
			return fmt.Errorf("authentication failed")
		}

		now := time.Now().Unix()
		diff := now - ackPkt.Timestamp
		if diff < 0 {
			diff = -diff
		}
		if diff > int64(maxClockSkew.Seconds()) {
			return fmt.Errorf("authentication failed")
		}

		return nil // success
	}
	return fmt.Errorf("unreachable")
}
