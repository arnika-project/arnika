// Package transport carries Arnika's authenticated UDP peer protocol for QKD key ids and PQC frames.
package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/auth"
)

// QKDQueueDepth stays small: a deeper queue only holds key ids superseded by the time they are served.
const QKDQueueDepth = 8

const qkdQueueWarnEvery = 10 * time.Second

const authFailWarnEvery = 10 * time.Second

// replayBucket is one limiter key shared by every copy of an already-seen datagram, so copies from spoofed sources
// neither spend the peer's per-IP budget nor add limiter entries.
const replayBucket = "replay"

// maxAckCopies caps the senders of copies remembered while a key_id installs; fresh datagrams come only from the PSK holder.
const maxAckCopies = 8

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
	authFailWarn := logThrottle{interval: authFailWarnEvery}
	started := time.Now().Unix() // nothing captured before a restart is accepted after it
	var lastKeyID string
	var lastKeyTS int64          // newest authenticated DATA timestamp; the peer's clock, so a local clock step cannot lower it
	var lastAcks *ackSet         // everyone who sent lastKeyID, answered once it is installed
	seen := map[[32]byte]int64{} // HMAC tag -> timestamp of datagrams already processed; only the peer can add one

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

		pkt, err := auth.UnmarshalPacket(c.PSK, buf[:n], c.DirIn)
		if err != nil {
			if authFailWarn.allow() {
				backupLog.Warn("packet rejected", "peer", remoteAddr, "reason", "authentication")
			}
			continue
		}

		if !auth.WithinSkew(pkt.Timestamp, c.MaxClockSkew) || pkt.Timestamp < started {
			backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "timestamp")
			continue
		}

		// Every legitimate send re-encrypts under a fresh GCM nonce, so a repeated tag is a copy of a datagram already
		// processed: a replay, or the original after a raced copy. Copies only ever get an answer, never a second run.
		tag := [32]byte(pkt.Signature)
		_, dup := seen[tag]
		bucket := remoteAddr.IP.String()
		if dup {
			bucket = replayBucket
		} else {
			cutoff := time.Now().Unix() - int64(c.MaxClockSkew.Seconds())
			for t, ts := range seen {
				if ts < cutoff { // WithinSkew rejects these already
					delete(seen, t)
				}
			}
			seen[tag] = pkt.Timestamp
		}

		// Charged after authentication: the source IP is forgeable, so neither junk nor copies may spend the peer's budget.
		if !limiter.Allow(bucket) {
			backupLog.Debug("rate limited", "peer", remoteAddr)
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
			// A newer key_id is first sent on a later whole second than any send of the one before it (main.go waits for
			// the next tick), so an older timestamp on a different key_id is a replay. Only a new key_id takes a queue
			// slot; every sender of the current one, a raced copy or the real sender, is ACKed once it is installed.
			if keyID != lastKeyID {
				if pkt.Timestamp < lastKeyTS {
					backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "stale key_id")
					continue
				}
				acks := &ackSet{send: func(to *net.UDPAddr) { _ = send(auth.PacketAck, []byte(keyID), to) }}
				select { // never block: a KMS outage in the worker would stall every PQC frame on this loop
				case c.KeyIDs <- KeyIDRequest{KeyID: keyID, Ack: acks.ack}:
				default:
					if queueFullWarn.allow() {
						backupLog.Warn("QKD queue full, key_id dropped; the sender will retry",
							"slots", cap(c.KeyIDs), "peer", remoteAddr)
					}
					continue // lastKeyID stays, so the retry queues it
				}
				lastKeyID, lastAcks = keyID, acks
				backupLog.Info("received a key_id from the peer", "key_id", keyID, "peer", remoteAddr)
			}
			lastKeyTS = max(lastKeyTS, pkt.Timestamp)
			lastAcks.add(remoteAddr, !dup)

		case auth.PacketPQC:
			if c.PQC == nil {
				backupLog.Debug("PQC frame dropped, no PQC key reader wired", "peer", remoteAddr)
				continue
			}
			if dup { // a copy must not reset reassembly or force a second encapsulation; the initiator's retry is fresh
				backupLog.Debug("packet rejected", "peer", remoteAddr, "reason", "copy of a PQC frame")
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
		if err := WriteConnected(conn, dataPkt.Marshal(c.PSK, c.DirOut)); err != nil {
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

// WriteConnected writes b to a connected UDP socket. A failed write consumes a pending ICMP error, which anyone can
// spoof, so the write is retried; a real local error recurs and is returned. The authenticated reply decides the exchange.
func WriteConnected(conn *net.UDPConn, b []byte) (err error) {
	for range 3 {
		if _, err = conn.Write(b); err == nil || errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	return err
}

func awaitAck(conn *net.UDPConn, c ClientConfig, until time.Time) bool {
	if err := conn.SetReadDeadline(until); err != nil {
		return false
	}
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) {
				return false
			}
			continue // an unauthenticated ICMP error (ECONNREFUSED) must not end the wait for the authenticated ACK
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

// ackSet answers every sender of one key_id: those seen before the install when it lands, later ones at once.
type ackSet struct {
	mu        sync.Mutex
	send      func(to *net.UDPAddr)
	installed bool
	fresh     []*net.UDPAddr // senders of fresh datagrams, which only the PSK holder can produce
	copies    []*net.UDPAddr // senders of copies, capped because a spoofer picks them
}

func (a *ackSet) add(to *net.UDPAddr, fresh bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.installed {
		a.send(to)
		return
	}
	list := &a.copies
	if fresh {
		list = &a.fresh
	}
	for _, x := range *list {
		if x.String() == to.String() {
			return
		}
	}
	if fresh || len(a.copies) < maxAckCopies {
		*list = append(*list, to)
	}
}

func (a *ackSet) ack() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.installed {
		return
	}
	a.installed = true
	for _, to := range append(a.fresh, a.copies...) {
		a.send(to)
	}
	a.fresh, a.copies = nil, nil
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
