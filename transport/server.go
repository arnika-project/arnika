// Package transport carries Arnika's authenticated UDP peer protocol for QKD key ids and PQC frames.
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

// QKDQueueDepth stays small: a deeper queue only holds key ids superseded by the time they are served.
const QKDQueueDepth = 8

const qkdQueueWarnEvery = 10 * time.Second

// PQCHandler must not block: it runs on the UDP read loop that also carries the QKD key ids.
type PQCHandler func(frame []byte, reply func(frame []byte) error) error

// KeyIDRequest is one key id from the peer; call Ack only once its PSK is installed.
type KeyIDRequest struct {
	KeyID string
	Ack   func()
}

type ServerConfig struct {
	Address      string
	PSK          []byte
	DirOut       auth.Direction
	DirIn        auth.Direction
	KeyIDs       chan<- KeyIDRequest
	Done         chan bool // closed by Serve on SIGTERM or SIGINT
	PQC          PQCHandler
	RateLimit    int
	RateWindow   time.Duration
	MaxClockSkew time.Duration

	Log *slog.Logger
}

type ClientConfig struct {
	Address      string
	PSK          []byte
	DirOut       auth.Direction
	DirIn        auth.Direction
	KeyID        string
	Timeout      time.Duration
	Deadline     time.Time
	MaxClockSkew time.Duration

	Log *slog.Logger
}

func Serve(c ServerConfig) error {
	backupLog := c.Log.With("role", "backup")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	addr, err := net.ResolveUDPAddr("udp", c.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve the UDP listen c.Address %s: %w", c.Address, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", c.Address, err)
	}
	c.Log.Info("UDP server started", "c.Address", c.Address)

	limiter := newRateLimiter(c.RateLimit, c.RateWindow)
	queueFullWarn := logThrottle{interval: qkdQueueWarnEvery}

	go func() {
		<-quit
		c.Log.Info("UDP server shutdown triggered", "c.Address", c.Address)
		close(c.Done)
		_ = conn.Close()
	}()

	send := func(typ auth.PacketType, payload []byte, to *net.UDPAddr) error {
		encrypted, err := auth.Encrypt(c.PSK, payload)
		if err != nil {
			return err
		}
		out := &auth.Packet{
			Type:      typ,
			Timestamp: time.Now().Unix(),
			Payload:   encrypted,
		}
		_, err = conn.WriteToUDP(out.Marshal(c.PSK, c.DirOut), to)
		return err
	}

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.Done:
				return nil
			default:
				c.Log.Error("UDP read error", "err", err)
				continue
			}
		}

		clientIP := remoteAddr.IP.String()

		if !limiter.Allow(clientIP) {
			backupLog.Debug("rate limited", "peer", remoteAddr)
			continue
		}

		pkt, err := auth.UnmarshalPacket(c.PSK, buf[:n], c.DirIn)
		if err != nil {
			backupLog.Warn("packet rejected", "peer", remoteAddr, "reason", "authentication")
			continue
		}

		if !auth.WithinSkew(pkt.Timestamp, c.MaxClockSkew) {
			backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "timestamp")
			continue
		}

		switch pkt.Type {
		case auth.PacketData:
			decrypted, err := auth.Decrypt(c.PSK, pkt.Payload)
			if err != nil {
				backupLog.Error("packet rejected, ARNIKA_PSK mismatch or the message is corrupted",
					"peer", remoteAddr, "reason", "decryption")
				continue
			}

			keyID := string(decrypted)
			select { // never block: a KMS outage in the worker would stall every PQC frame on this loop
			case c.KeyIDs <- KeyIDRequest{KeyID: keyID, Ack: func() {
				_ = send(auth.PacketAck, []byte(keyID), remoteAddr)
			}}:
			default:
				if queueFullWarn.allow() {
					backupLog.Warn("QKD queue full, key_id dropped; the sender will retry",
						"slots", cap(c.KeyIDs), "peer", remoteAddr)
				}
				continue
			}

			backupLog.Info("received a key_id from the peer", "key_id", keyID, "peer", remoteAddr)

		case auth.PacketPQC:
			if c.PQC == nil {
				backupLog.Debug("PQC frame dropped, no PQC key reader wired", "peer", remoteAddr)
				continue
			}
			decrypted, err := auth.Decrypt(c.PSK, pkt.Payload)
			if err != nil {
				backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "decryption")
				continue
			}
			reply := func(frame []byte) error {
				return send(auth.PacketPQC, frame, remoteAddr)
			}
			if err := c.PQC(decrypted, reply); err != nil {
				backupLog.Warn("PQC frame not accepted", "peer", remoteAddr, "err", err)
			}

		default:
			backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "unknown type")
			continue
		}
	}
}

const udpClientMaxAttempts = 3

// SendKeyID returns once the peer has installed a PSK built from KeyID, resending after Timeout, 2*Timeout, ... until Deadline.
func SendKeyID(c ClientConfig) error {
	if c.Address == "" {
		return fmt.Errorf("c.Address is empty")
	}
	if c.KeyID == "" {
		return fmt.Errorf("c.KeyID is empty")
	}
	if c.Deadline.IsZero() {
		return fmt.Errorf("c.Deadline is unset")
	}

	raddr, err := net.ResolveUDPAddr("udp", c.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve c.Address: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer func() { _ = conn.Close() }()

	wait := c.Timeout
	for attempt := 1; attempt <= udpClientMaxAttempts; attempt++ {
		encrypted, err := auth.Encrypt(c.PSK, []byte(c.KeyID))
		if err != nil {
			return fmt.Errorf("failed to encrypt key_id: %w", err)
		}
		dataPkt := &auth.Packet{
			Type:      auth.PacketData,
			Timestamp: time.Now().Unix(),
			Payload:   encrypted,
		}
		_, err = conn.Write(dataPkt.Marshal(c.PSK, c.DirOut))
		if err != nil {
			return fmt.Errorf("failed to write DATA packet: %w", err)
		}

		until := time.Now().Add(wait)
		if attempt == udpClientMaxAttempts || until.After(c.Deadline) {
			until = c.Deadline
		}
		if awaitAck(conn, c, until) {
			return nil
		}
		if !time.Now().Before(c.Deadline) {
			break
		}
		c.Log.Debug("no ACK yet, resending the key_id", "attempt", attempt, "of", udpClientMaxAttempts)
		wait *= 2
	}
	return fmt.Errorf("no ACK by %s", c.Deadline.Format(time.TimeOnly))
}

func awaitAck(conn *net.UDPConn, c ClientConfig, until time.Time) bool {
	if err := conn.SetReadDeadline(until); err != nil {
		return false
	}
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return false
		}
		pkt, err := auth.UnmarshalPacket(c.PSK, buf[:n], c.DirIn)
		if err != nil || pkt.Type != auth.PacketAck || !auth.WithinSkew(pkt.Timestamp, c.MaxClockSkew) {
			continue
		}
		keyID, err := auth.Decrypt(c.PSK, pkt.Payload)
		if err == nil && string(keyID) == c.KeyID {
			return true
		}
	}
}

// RunKeyIDWorker must be the queue's only consumer, so PSKs are installed in the order the peer sent the key ids.
func RunKeyIDWorker(done <-chan bool, queue <-chan KeyIDRequest, install func(keyID string) bool) {
	var last string
	var installed bool
	for {
		select {
		case <-done:
			return
		case req := <-queue:
			if req.KeyID != last {
				last, installed = req.KeyID, install(req.KeyID)
			}
			if installed {
				req.Ack()
			}
		}
	}
}
