package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/auth"
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/kms"
	"github.com/arnika-project/arnika/services"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
	// Prefix variables initialized after config is parsed
	PRIMARYLOGPREFIX string
	BACKUPLOGPREFIX  string
	ARNIKALOGPREFIX  string
)

// maxClockSkew is the maximum allowed timestamp difference in seconds (replay protection).
const maxClockSkew int64 = 60

// rateLimiter implements a simple per-IP rate limiter.
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go func() {
		for {
			time.Sleep(window)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	times := rl.requests[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for ip, times := range rl.requests {
		valid := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// udpServer listens for incoming UDP packets using the security-hardened protocol:
//   - Stateless cookie exchange (DDoS protection)
//   - HMAC-SHA256 signature verification (authentication)
//   - Timestamp validation (replay protection)
//   - Per-IP rate limiting (flood protection)
//   - Constant-time checks, uniform error messages (side-channel resistance)
//
// Protocol flow:
//  1. Client sends INIT packet (signed, no payload) -> Server replies with COOKIE
//  2. Client sends DATA packet (signed, with cookie + encrypted payload) -> Server replies with ACK
func udpServer(address string, psk string, result chan string, done chan bool) {
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

	// Generate per-instance server secret for cookie generation
	serverSecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverSecret); err != nil {
		log.Panicf("[ERROR] failed to generate server secret: %v", err)
	}

	// Rate limiter: 30 requests per IP per minute
	limiter := newRateLimiter(30, time.Minute)

	go func() {
		<-quit
		log.Printf("[INFO] %s UDP server shutdown triggered on %s", ARNIKALOGPREFIX, address)
		close(done)
		conn.Close()
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
		pkt, err := auth.UnmarshalPacket([]byte(psk), raw)
		if err != nil {
			log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		// 4. Timestamp check (replay protection)
		now := time.Now().Unix()
		diff := now - pkt.Timestamp
		if diff < 0 {
			diff = -diff
		}
		if diff > maxClockSkew {
			log.Printf("[DEBUG] %s packet rejected from %s (timestamp)", BACKUPLOGPREFIX, remoteAddr)
			continue
		}

		switch pkt.Type {
		case auth.PacketInit:
			// Generate cookie and send back — no decryption, very cheap
			cookie := auth.GenerateCookie(serverSecret, clientIP, pkt.Timestamp)
			resp := &auth.Packet{
				Type:      auth.PacketCookie,
				Timestamp: time.Now().Unix(),
				Cookie:    cookie,
			}
			respB64 := base64.StdEncoding.EncodeToString(resp.Marshal([]byte(psk)))
			_, _ = conn.WriteToUDP([]byte(respB64), remoteAddr)
			log.Printf("[DEBUG] %s sent cookie to %s", BACKUPLOGPREFIX, remoteAddr)

		case auth.PacketData:
			// 5. Verify cookie (cheap HMAC, before decryption)
			if !auth.VerifyCookie(serverSecret, clientIP, pkt.Cookie, now, maxClockSkew) {
				log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
				continue
			}

			// 6. Decrypt payload (expensive, only after all cheap checks pass)
			decrypted, err := auth.Decrypt([]byte(psk), pkt.Payload)
			if err != nil {
				log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
				log.Printf("[ERROR] %s authentication failed, psk mismatch or message corrupted", BACKUPLOGPREFIX)
				continue
			}

			// 7. Send ACK
			ack := &auth.Packet{
				Type:      auth.PacketAck,
				Timestamp: time.Now().Unix(),
			}
			ackB64 := base64.StdEncoding.EncodeToString(ack.Marshal([]byte(psk)))
			_, _ = conn.WriteToUDP([]byte(ackB64), remoteAddr)

			log.Printf("[INFO] %s [RCV] received key_id %s from %s", BACKUPLOGPREFIX, string(decrypted), remoteAddr)
			result <- string(decrypted)

		default:
			log.Printf("[DEBUG] %s packet rejected from %s", BACKUPLOGPREFIX, remoteAddr)
		}
	}
}

// udpClient sends an encrypted, HMAC-signed key ID to the peer via the security-hardened
// UDP protocol. Uses cookie exchange for DDoS protection. Retries up to 3 times on timeout.
//
// Protocol flow:
//  1. Send INIT -> Receive COOKIE
//  2. Send DATA (with cookie + encrypted keyID) -> Receive ACK
func udpClient(address, psk, keyID string, timeout time.Duration) error {
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
	defer conn.Close()

	const maxRetries = 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Step 1: Send INIT to request cookie
		initPkt := &auth.Packet{
			Type:      auth.PacketInit,
			Timestamp: time.Now().Unix(),
		}
		initBytes := base64.StdEncoding.EncodeToString(initPkt.Marshal([]byte(psk)))
		_, err = conn.Write([]byte(initBytes))
		if err != nil {
			return fmt.Errorf("failed to write INIT packet: %w", err)
		}

		// Step 2: Wait for COOKIE response
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}
		cookieBuf := make([]byte, 1024)
		n, err := conn.Read(cookieBuf)
		if err != nil {
			if attempt < maxRetries {
				log.Printf("[DEBUG] %s cookie timeout (attempt %d/%d), retrying...", PRIMARYLOGPREFIX, attempt, maxRetries)
				continue
			}
			return fmt.Errorf("no cookie after %d attempts: %w", maxRetries, err)
		}

		cookieRaw, err := base64.StdEncoding.DecodeString(string(cookieBuf[:n]))
		if err != nil {
			return fmt.Errorf("failed to decode cookie response: %w", err)
		}
		cookiePkt, err := auth.UnmarshalPacket([]byte(psk), cookieRaw)
		if err != nil {
			return fmt.Errorf("authentication failed")
		}
		if cookiePkt.Type != auth.PacketCookie {
			return fmt.Errorf("authentication failed")
		}

		// Step 3: Send DATA with cookie + encrypted keyID
		encrypted, err := auth.Encrypt([]byte(psk), []byte(keyID))
		if err != nil {
			return fmt.Errorf("failed to encrypt key_id: %w", err)
		}
		dataPkt := &auth.Packet{
			Type:      auth.PacketData,
			Timestamp: time.Now().Unix(),
			Cookie:    cookiePkt.Cookie,
			Payload:   encrypted,
		}
		dataBytes := base64.StdEncoding.EncodeToString(dataPkt.Marshal([]byte(psk)))
		_, err = conn.Write([]byte(dataBytes))
		if err != nil {
			return fmt.Errorf("failed to write DATA packet: %w", err)
		}

		// Step 4: Wait for ACK
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}
		ackBuf := make([]byte, 1024)
		n, err = conn.Read(ackBuf)
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
		ackPkt, err := auth.UnmarshalPacket([]byte(psk), ackRaw)
		if err != nil {
			return fmt.Errorf("authentication failed")
		}
		if ackPkt.Type != auth.PacketAck {
			return fmt.Errorf("authentication failed")
		}

		return nil // success
	}
	return fmt.Errorf("unreachable")
}

// --- Legacy TCP implementation (kept for reference) ---

/*
func handleServerConnection(c net.Conn, psk string, result chan string) {
	if c == nil {
		panic("received nil connection")
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()
	defer c.Close()
	scanner := bufio.NewScanner(c)
	if scanner == nil {
		panic("received nil scanner")
	}
	for scanner.Scan() {
		msg := scanner.Text()
		decrypted, err := auth.Decrypt([]byte(psk), []byte(msg))
		if err != nil {
			log.Printf("[DEBUG] failed to decrypt message: %s, %v", msg, err)
			log.Println("[ERROR] Authentication failed, psk mismatch or message corrupted")
			break
		}
		result <- string(decrypted)
		_, err = c.Write([]byte("ACK" + "\n"))
		if err != nil {
			fmt.Println("[ERROR] Failed to write to connection:", err)
			break
		}
		log.Printf("[INFO] %s [RCV] received key_id %s from %s", BACKUPLOGPREFIX, decrypted, c.RemoteAddr())
	}
	if errRead := scanner.Err(); errRead != nil {
		log.Printf("[INFO] %s connection closed from %s: %v", BACKUPLOGPREFIX, c.RemoteAddr(), errRead)
	}
}

func tcpServer(url string, psk string, result chan string, done chan bool) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	go func() {
		<-quit
		log.Printf("[INFO] %s TCP server shutdown triggered on %s", ARNIKALOGPREFIX, url)
		close(done)
	}()
	log.Printf("[INFO] %s TCP server started on %s\n", ARNIKALOGPREFIX, url)
	ln, err := net.Listen("tcp", url)
	if err != nil {
		log.Panicln(err.Error())
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			go handleServerConnection(c, psk, result)
		}
	}()
	<-done
	err = ln.Close()
	if err != nil {
		log.Println(err.Error())
	}
}

func tcpClient(url, data string, timeout time.Duration) error {
	if url == "" {
		return fmt.Errorf("url is empty")
	}
	if data == "" {
		return fmt.Errorf("data is empty")
	}
	c, err := net.DialTimeout("tcp", url, timeout)
	if err != nil {
		return err
	}
	defer func() {
		if c != nil {
			c.Close()
		}
	}()
	_, err = c.Write([]byte(data + "\n"))
	if err != nil {
		return err
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	reader := bufio.NewReader(c)
	_, err = reader.ReadString('\n')
	return err
}
*/

func getPQCKey(pqcKeyFile string) (string, error) {
	file, err := os.Open(pqcKeyFile)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	return scanner.Text(), nil
}

func setPSK(keyWriter *services.KeyWriterService, qkd string, cfg *config.Config, logPrefix string) {
	psk := qkd
	msg := ""
	defer func() {
		if msg != "" {
			log.Println(msg)
			log.Printf("[ERROR] %s [STOP] configure random PSK to invalidate WireGuard session", logPrefix)
			if err := keyWriter.InvalidateTunnel(); err != nil {
				log.Printf("[ERROR] %s failed to configure random PSK: %v", logPrefix, err)
			}
		}
	}()
	if qkd == "" {
		if cfg.IsQKDRequired() {
			msg = fmt.Sprintf("[ERROR] %s mode set to %s but no QKD key received", logPrefix, cfg.Mode)
			return
		}
		log.Printf("[WARNING] %s failed to retrieve QKD key, switching to PQC key since mode is set to %s", logPrefix, cfg.Mode)
	}
	if cfg.UsePQC() {
		pQCKey, err := getPQCKey(cfg.PQCPSKFile)
		if err != nil {
			if cfg.IsPQCRequired() {
				msg = fmt.Sprintf("[ERROR] %s failed to retrieve PQC key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
				return
			}
			log.Printf("[WARNING] %s failed to retrieve PQC key, switching to QKD key since mode is set to %s", logPrefix, cfg.Mode)
		} else {
			pqc, err := base64.StdEncoding.DecodeString(pQCKey)
			if err != nil {
				if cfg.IsPQCRequired() {
					msg = fmt.Sprintf("[ERROR] %s failed to decode PQC key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
					return
				} else {
					log.Printf("[WARNING] %s failed to decode PQC key, switching to QKD key since mode is set to %s", logPrefix, cfg.Mode)
				}
			} else {
				// a key derivation will happen, either with key or with all zeros
				psk, err = kdf.DeriveKey(psk, pqc)
				if err != nil {
					msg = fmt.Sprintf("[ERROR] %s failed to derive key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
					return
				}
				log.Printf("[INFO] %s [OK] HKDF derivation completed for QKD+PQC key", logPrefix)
			}
		}
	}
	if psk == "" {
		msg = fmt.Sprintf("[ERROR] %s no PSK available", logPrefix)
		return
	}
	if err := keyWriter.SetPSK(psk); err != nil {
		msg = fmt.Sprintf("[ERROR] %s failed to configure PSK on WireGuard interface: %v", logPrefix, err)
		return
	}
	log.Printf("[INFO] %s [OK] PSK configured on WireGuard interface: %s for peer: %s", logPrefix, cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	versionLong := flag.Bool("version", false, "print version and exit")
	versionShort := flag.Bool("v", false, "alias for version")
	flag.Parse()
	if *versionShort || *versionLong {
		fmt.Printf("%s version %s\n", APPName, Version)
		os.Exit(0)
	}
	help := flag.Bool("help", false, "print usage and exit")
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("[ERROR] failed to parse config: %v", err)
	}
	cfg.PrintStartupConfig()
	// Initialize prefixes with ArnikaID
	PRIMARYLOGPREFIX = fmt.Sprintf("PRIMARY[%s]", cfg.ArnikaID)
	BACKUPLOGPREFIX = fmt.Sprintf("BACKUP[%s]", cfg.ArnikaID)
	ARNIKALOGPREFIX = fmt.Sprintf("ARNIKA[%s]", cfg.ArnikaID)
	interval := cfg.Interval
	done := make(chan bool)
	skip := make(chan bool, 1)
	result := make(chan string)
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	keyWriter, err := getKeyWriterService(cfg)
	if err != nil {
		log.Panicf("[ERROR] [STOP] Failed to create WireGuard repository: %v", err)
	}
	go udpServer(cfg.ListenAddress, cfg.ArnikaPSK, result, done)
	go func() {
		for {
			r := <-result
			select {
			case skip <- true:
			default:
			}
			log.Printf("[INFO] %s [REQ] request QKD key for key_id %s from %s\n", BACKUPLOGPREFIX, r, cfg.KMSURL)
			key, err := kmsServer.GetKeyByID(r)
			if err != nil {
				log.Printf("[ERROR] %s failed to retrieve QKD key for key_id %s from %s, %v", BACKUPLOGPREFIX, r, cfg.KMSURL, err)
				continue
			}
			setPSK(keyWriter, key.GetKey(), cfg, BACKUPLOGPREFIX)
		}
	}()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			ticker.Reset(interval)
			select {
			case <-skip:
			default:
				// get key_id and send
				log.Printf("[INFO] %s [REQ] request QKD key from %s\n", PRIMARYLOGPREFIX, cfg.KMSURL)
				key, err := kmsServer.GetNewKey()
				if err != nil {
					log.Printf("[ERROR] %s failed to retrieve QKD key from %s, %v", PRIMARYLOGPREFIX, cfg.KMSURL, err)
					ticker.Reset(cfg.KMSRetryInterval)
				} else {
					now := time.Now()
					var nextTick time.Time
					if cfg.PreferedState == "BACKUP" {
						// Wait until the next .5 second (e.g., 12:34:56.500)
						nextTick = now.Truncate(time.Second).Add(500 * time.Millisecond)
						if now.After(nextTick) {
							nextTick = nextTick.Add(time.Second)
						}
						log.Printf("[INFO] %s [REQ] use 500ms delay\n", BACKUPLOGPREFIX)
					} else {
						// Wait until the next full second (e.g., 12:34:57.000)
						nextTick = now.Truncate(time.Second).Add(time.Second)
					}
					time.Sleep(nextTick.Sub(now))
					// Check if a key was received from peer during the delay
					select {
					case <-skip:
					default:
						log.Printf("[INFO] %s [SND] send key_id %s to %s\n", PRIMARYLOGPREFIX, key.GetID(), cfg.ServerAddress)
						err = udpClient(cfg.ServerAddress, cfg.ArnikaPSK, key.GetID(), cfg.ArnikaPeerTimeout)
						if err != nil {
							log.Printf("[ERROR] %s failed to send key_id %s to %s: %v", PRIMARYLOGPREFIX, key.GetID(), cfg.ServerAddress, err)
						}
						setPSK(keyWriter, key.GetKey(), cfg, PRIMARYLOGPREFIX)
					}
				}
			}
			<-ticker.C
		}
	}()
	<-done
}
