// Package transport carries Arnika's authenticated UDP peer protocol for QKD key ids and PQC frames.
package transport

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
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

// PQCHandler must not block: it runs on the UDP read loop that also carries the QKD key ids.
type PQCHandler func(frame []byte, reply func(frame []byte) error) error

// KeyIDRequest is one key id from the peer; call Ack only once its PSK is installed.
type KeyIDRequest struct {
	KeyID string
	Ack   func(pqcRound string)
}

type ServerConfig struct {
	Address      string
	PSK          []byte
	DirOut       auth.Direction
	DirIn        auth.Direction
	KeyIDs       chan<- KeyIDRequest
	Done         <-chan bool // closing it stops Serve
	PQC          PQCHandler
	RateLimit    int
	RateWindow   time.Duration
	MaxClockSkew time.Duration
	Interval     time.Duration // DATA stamped before the current wall-clock interval is dropped; zero skips the check

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
	logger := c.Log
	addr, err := net.ResolveUDPAddr("udp", c.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve the UDP listen c.Address %s: %w", c.Address, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", c.Address, err)
	}
	c.Log.Info("UDP server started", "address", c.Address)

	limiter := newRateLimiter(c.RateLimit, c.RateWindow)
	queueFullWarn := logThrottle{interval: qkdQueueWarnEvery}
	authFailWarn := logThrottle{interval: authFailWarnEvery}
	started := time.Now().Unix() // nothing captured before a restart is accepted after it
	var lastKeyID string
	var lastKeyTS int64          // newest authenticated DATA timestamp; the peer's clock, so a local clock step cannot lower it
	var lastAcks *ackSet         // everyone who sent lastKeyID, answered once it is installed
	seen := map[[32]byte]int64{} // HMAC tag -> timestamp of datagrams already processed; only the peer can add one

	go func() {
		<-c.Done
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
				logger.Warn("packet rejected", "peer", remoteAddr, "reason", "authentication")
			}
			continue
		}

		if !auth.WithinSkew(pkt.Timestamp, c.MaxClockSkew) || pkt.Timestamp < started {
			logger.Debug("packet rejected", "peer", remoteAddr, "reason", "timestamp")
			continue
		}

		// Only DATA and PQC are addressed to this listener, so nothing else may spend the budget.
		if pkt.Type != auth.PacketData && pkt.Type != auth.PacketPQC {
			logger.Debug("packet rejected", "peer", remoteAddr, "reason", "unknown type")
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
			logger.Debug("rate limited", "peer", remoteAddr)
			continue
		}

		switch pkt.Type {
		case auth.PacketData:
			if c.Interval > 0 && pkt.Timestamp < time.Now().UnixNano()/int64(c.Interval)*int64(c.Interval)/int64(time.Second) {
				logger.Debug("packet rejected", "peer", remoteAddr, "reason", "earlier interval") // a capture replayed after a restart, even from a peer whose clock leads
				continue
			}
			decrypted, err := auth.Decrypt(c.PSK, pkt.Payload)
			if err != nil {
				logger.Error("packet rejected, ARNIKA_PSK mismatch or the message is corrupted",
					"peer", remoteAddr, "reason", "decryption")
				continue
			}

			keyID := string(decrypted)
			if keyID == "" { // honest peers never send one, and lastAcks is still nil for it
				logger.Debug("packet rejected", "peer", remoteAddr, "reason", "empty key_id")
				continue
			}
			// A newer key_id is first sent on a later whole second than any send of the one before it (main.go waits for
			// the next tick), so an older timestamp on a different key_id is a replay. Only a new key_id takes a queue
			// slot; every sender of the current one, a raced copy or the real sender, is ACKed once it is installed.
			if keyID != lastKeyID {
				if pkt.Timestamp < lastKeyTS {
					logger.Debug("packet rejected", "peer", remoteAddr, "reason", "stale key_id")
					continue
				}
				acks := &ackSet{keyID: keyID, send: func(to *net.UDPAddr, payload []byte) { _ = send(auth.PacketAck, payload, to) }}
				select { // never block: a KMS outage in the worker would stall every PQC frame on this loop
				case c.KeyIDs <- KeyIDRequest{KeyID: keyID, Ack: acks.ack}:
				default:
					if queueFullWarn.allow() {
						logger.Warn("QKD queue full, key_id dropped; the sender will retry",
							"slots", cap(c.KeyIDs), "peer", remoteAddr)
					}
					continue // lastKeyID stays, so the retry queues it
				}
				lastKeyID, lastAcks = keyID, acks
				logger.Info("received a key_id from the peer", "key_id", keyID, "peer", remoteAddr)
			}
			lastKeyTS = max(lastKeyTS, pkt.Timestamp)
			lastAcks.add(remoteAddr, !dup)

		case auth.PacketPQC:
			if c.PQC == nil {
				logger.Debug("PQC frame dropped, no PQC key reader wired", "peer", remoteAddr)
				continue
			}
			if dup { // a copy must not reset reassembly or force a second encapsulation; the initiator's retry is fresh
				logger.Debug("packet rejected", "peer", remoteAddr, "reason", "copy of a PQC frame")
				continue
			}
			decrypted, err := auth.Decrypt(c.PSK, pkt.Payload)
			if err != nil {
				logger.Debug("packet rejected", "peer", remoteAddr, "reason", "decryption")
				continue
			}
			reply := func(frame []byte) error {
				return send(auth.PacketPQC, frame, remoteAddr)
			}
			if err := c.PQC(decrypted, reply); err != nil {
				logger.Warn("PQC frame not accepted", "peer", remoteAddr, "err", err)
			}
		}
	}
}

const udpClientMaxAttempts = 3

// natKeepalive bounds the gap between two sends of one key_id, so a NAT in front of the primary keeps the mapping the ACK returns through.
var natKeepalive = 15 * time.Second

// keyIDSendsPerInterval bounds the DATA packets SendKeyID sends within one interval.
func keyIDSendsPerInterval(interval time.Duration) int {
	return udpClientMaxAttempts + int(interval/natKeepalive)
}

// SendKeyID returns the PQC round the peer derived its PSK from once it has installed a PSK built from KeyID, resending after Timeout, 2*Timeout, ..., then every natKeepalive until Deadline.
func SendKeyID(c ClientConfig) (pqcRound string, err error) {
	if c.Address == "" {
		return "", fmt.Errorf("c.Address is empty")
	}
	if c.KeyID == "" {
		return "", fmt.Errorf("c.KeyID is empty")
	}
	if c.Deadline.IsZero() {
		return "", fmt.Errorf("c.Deadline is unset")
	}
	if !time.Now().Before(c.Deadline) { // the peer would install a key_id this side has already given up on
		return "", fmt.Errorf("c.Deadline %s has passed", c.Deadline.Format(time.TimeOnly))
	}

	raddr, err := net.ResolveUDPAddr("udp", c.Address)
	if err != nil {
		return "", fmt.Errorf("failed to resolve c.Address: %w", err)
	}
	conn, err := net.ListenUDP("udp", nil) // unconnected: no spoofable ICMP errors, and the ACK to our source address passes a NAT
	if err != nil {
		return "", fmt.Errorf("failed to open a UDP socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	wait := c.Timeout
	for attempt := 1; ; attempt++ {
		encrypted, err := auth.Encrypt(c.PSK, []byte(c.KeyID))
		if err != nil {
			return "", fmt.Errorf("failed to encrypt key_id: %w", err)
		}
		dataPkt := &auth.Packet{
			Type:      auth.PacketData,
			Timestamp: time.Now().Unix(),
			Payload:   encrypted,
		}
		if _, err := conn.WriteToUDP(dataPkt.Marshal(c.PSK, c.DirOut), raddr); err != nil {
			return "", fmt.Errorf("failed to write DATA packet: %w", err)
		}

		if attempt >= udpClientMaxAttempts {
			wait = natKeepalive
		}
		until := time.Now().Add(min(wait, natKeepalive))
		if until.After(c.Deadline) {
			until = c.Deadline
		}
		if round, ok := awaitAck(conn, c, until); ok {
			return round, nil
		}
		if !time.Now().Before(c.Deadline) {
			break
		}
		c.Log.Debug("no ACK yet, resending the key_id", "attempt", attempt)
		wait *= 2
	}
	return "", fmt.Errorf("no ACK by %s", c.Deadline.Format(time.TimeOnly))
}

// ackPayload names the key_id and the PQC round the backup derived its PSK from, empty when it used none.
func ackPayload(keyID, pqcRound string) []byte {
	if pqcRound == "" {
		return []byte(keyID)
	}
	return []byte(keyID + "\x00" + pqcRound)
}

func awaitAck(conn *net.UDPConn, c ClientConfig, until time.Time) (pqcRound string, ok bool) {
	if err := conn.SetReadDeadline(until); err != nil {
		return "", false
	}
	buf := make([]byte, 1024)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "", false
		}
		pkt, err := auth.UnmarshalPacket(c.PSK, buf[:n], c.DirIn)
		if err != nil || pkt.Type != auth.PacketAck || !auth.WithinSkew(pkt.Timestamp, c.MaxClockSkew) {
			continue
		}
		payload, err := auth.Decrypt(c.PSK, pkt.Payload)
		if err != nil {
			continue
		}
		if keyID, round, _ := strings.Cut(string(payload), "\x00"); keyID == c.KeyID {
			return round, true
		}
	}
}

// ackSet answers every sender of one key_id: those seen before the install when it lands, later ones at once.
type ackSet struct {
	mu        sync.Mutex
	keyID     string
	send      func(to *net.UDPAddr, payload []byte)
	payload   []byte
	installed bool
	fresh     []*net.UDPAddr // senders of fresh datagrams, which only the PSK holder can produce
	copies    []*net.UDPAddr // senders of copies; uncapped, since the replay bucket bounds them and a cap lets racers crowd out the sender
}

func (a *ackSet) add(to *net.UDPAddr, fresh bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.installed {
		a.send(to, a.payload)
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
	*list = append(*list, to)
}

func (a *ackSet) ack(pqcRound string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.installed {
		return
	}
	a.installed, a.payload = true, ackPayload(a.keyID, pqcRound)
	for _, to := range append(a.fresh, a.copies...) {
		a.send(to, a.payload)
	}
	a.fresh, a.copies = nil, nil
}

// RunKeyIDWorker must be the queue's only consumer, so PSKs are installed in the order the peer sent the key ids.
func RunKeyIDWorker(done <-chan bool, queue <-chan KeyIDRequest, install func(keyID string) (pqcRound string, ok bool)) {
	var last, round string
	var installed bool
	for {
		select {
		case <-done:
			return
		case req := <-queue:
			if req.KeyID != last {
				last = req.KeyID
				round, installed = install(req.KeyID)
			}
			if installed {
				req.Ack(round)
			}
		}
	}
}
