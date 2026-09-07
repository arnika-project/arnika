// Package repositories - pqc-hpke key reader.
//
// This adapter derives the 32-byte PQC key by running an HPKE (RFC 9180) key
// agreement directly with the Arnika peer, replacing the reader that took the
// PQC key via file from an external PQC provider. It has no build tag and no
// platform constraint: it compiles, vets, lints and tests on every platform.
//
// The file is organised in three sections:
//
//  1. frame layer      - splitting and reassembling messages that exceed one datagram
//  2. HPKE core        - the key agreement itself, plus mandatory key confirmation
//  3. transport/scheduler - rounds, retries and the KeyReaderUnmanaged surface
package repositories

import (
	"context"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log"
	"runtime/secret"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 1. Frame layer
// ---------------------------------------------------------------------------

// pqcKind identifies what a frame carries. It lives inside the AES-GCM payload,
// so it is not observable on the wire - only the single PacketPQC type byte is.
type pqcKind uint8

const (
	pqcKindPubKey  pqcKind = 1 // HPKE public key (1665 bytes, 2 frames)
	pqcKindEnc     pqcKind = 2 // HPKE encapsulation (1665 bytes, 2 frames)
	pqcKindAck     pqcKind = 3 // acknowledges a complete message
	pqcKindConfirm pqcKind = 4 // key confirmation tag
)

const (
	// pqcFrameHeaderLen is [round uint32][kind uint8][seq uint8][total uint8][reserved uint8].
	pqcFrameHeaderLen = 8

	// pqcChunkPayload keeps a frame inside a 1492-byte PPPoE path:
	// 908 (header+data) -> 936 (AES-GCM) -> 979 (auth.Packet) -> 1306 (base64)
	// -> 1334 with UDP/IPv4 headers.
	pqcChunkPayload = 900

	// pqcMaxFrames bounds reassembly state. The largest message is 1665 bytes,
	// which needs two frames; the headroom is for a future suite change.
	pqcMaxFrames = 4
)

// pqcFrame is one datagram's worth of a PQC message.
type pqcFrame struct {
	round uint32
	kind  pqcKind
	seq   uint8
	total uint8
	data  []byte
}

// encodeFrame serialises a frame. The caller seals the result with auth.Encrypt.
func encodeFrame(f pqcFrame) ([]byte, error) {
	if f.total == 0 || f.total > pqcMaxFrames {
		return nil, fmt.Errorf("pqc: invalid frame total %d", f.total)
	}
	if f.seq >= f.total {
		return nil, fmt.Errorf("pqc: frame seq %d out of range for total %d", f.seq, f.total)
	}
	if len(f.data) > pqcChunkPayload {
		return nil, fmt.Errorf("pqc: frame data %d bytes exceeds %d", len(f.data), pqcChunkPayload)
	}
	buf := make([]byte, pqcFrameHeaderLen+len(f.data))
	binary.BigEndian.PutUint32(buf[0:4], f.round)
	buf[4] = byte(f.kind)
	buf[5] = f.seq
	buf[6] = f.total
	buf[7] = 0 // reserved
	copy(buf[pqcFrameHeaderLen:], f.data)
	return buf, nil
}

// decodeFrame parses a decrypted frame. It rejects malformed input rather than
// panicking: everything here is attacker-influenced, even after authentication.
func decodeFrame(b []byte) (pqcFrame, error) {
	if len(b) < pqcFrameHeaderLen {
		return pqcFrame{}, fmt.Errorf("pqc: frame too short (%d bytes)", len(b))
	}
	f := pqcFrame{
		round: binary.BigEndian.Uint32(b[0:4]),
		kind:  pqcKind(b[4]),
		seq:   b[5],
		total: b[6],
	}
	if f.total == 0 || f.total > pqcMaxFrames {
		return pqcFrame{}, fmt.Errorf("pqc: invalid frame total %d", f.total)
	}
	if f.seq >= f.total {
		return pqcFrame{}, fmt.Errorf("pqc: frame seq %d out of range for total %d", f.seq, f.total)
	}
	data := b[pqcFrameHeaderLen:]
	if len(data) > pqcChunkPayload {
		return pqcFrame{}, fmt.Errorf("pqc: frame data %d bytes exceeds %d", len(data), pqcChunkPayload)
	}
	f.data = make([]byte, len(data))
	copy(f.data, data)
	return f, nil
}

// splitMessage cuts a message into encoded frames. A zero-length message still
// produces one frame, so an ack is a message like any other.
func splitMessage(round uint32, kind pqcKind, msg []byte) ([][]byte, error) {
	total := (len(msg) + pqcChunkPayload - 1) / pqcChunkPayload
	if total == 0 {
		total = 1
	}
	if total > pqcMaxFrames {
		return nil, fmt.Errorf("pqc: message of %d bytes needs %d frames, maximum %d",
			len(msg), total, pqcMaxFrames)
	}
	out := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		start := i * pqcChunkPayload
		end := min(start+pqcChunkPayload, len(msg))
		enc, err := encodeFrame(pqcFrame{
			round: round,
			kind:  kind,
			seq:   uint8(i),
			total: uint8(total),
			data:  msg[start:end],
		})
		if err != nil {
			return nil, err
		}
		out = append(out, enc)
	}
	return out, nil
}

// pqcPartial accumulates the frames of one (round, kind).
type pqcPartial struct {
	total uint8
	parts [][]byte
	have  int
}

// pqcReassembler collects frames for the single active round. Frames for any
// other round are dropped: at most one round is ever in flight, so there is no
// reassembly garbage to collect beyond resetting on a round change.
type pqcReassembler struct {
	active  uint32
	started bool
	parts   map[pqcKind]*pqcPartial
}

func newPQCReassembler() *pqcReassembler {
	return &pqcReassembler{parts: make(map[pqcKind]*pqcPartial)}
}

// SetRound makes round the active one and discards any partial state.
func (r *pqcReassembler) SetRound(round uint32) {
	r.active = round
	r.started = true
	r.parts = make(map[pqcKind]*pqcPartial)
}

// Add feeds one decoded frame in. It returns the reassembled message once every
// frame of that (round, kind) has arrived. Duplicate and out-of-order frames are
// handled; frames from another round are ignored.
func (r *pqcReassembler) Add(f pqcFrame) (msg []byte, complete bool) {
	if !r.started || f.round != r.active {
		return nil, false
	}
	p, ok := r.parts[f.kind]
	if !ok {
		p = &pqcPartial{total: f.total, parts: make([][]byte, f.total)}
		r.parts[f.kind] = p
	}
	if p.total != f.total {
		// Inconsistent framing for the same message: restart this kind.
		p = &pqcPartial{total: f.total, parts: make([][]byte, f.total)}
		r.parts[f.kind] = p
	}
	if int(f.seq) >= len(p.parts) {
		return nil, false
	}
	if p.parts[f.seq] == nil {
		p.parts[f.seq] = f.data
		p.have++
	}
	if p.have != int(p.total) {
		return nil, false
	}
	out := make([]byte, 0, int(p.total)*pqcChunkPayload)
	for _, part := range p.parts {
		out = append(out, part...)
	}
	delete(r.parts, f.kind)
	return out, true
}

// ---------------------------------------------------------------------------
// 2. HPKE core
// ---------------------------------------------------------------------------

const (
	// pqcExporterContext is the HPKE exporter context. Both peers must use the
	// identical string or they derive different keys.
	pqcExporterContext = "arnika-pqc-hpke-v1"

	// pqcKeyLen is the size of the agreed PQC key, matching the QKD key so the
	// two combine cleanly in kdf.DeriveKey.
	pqcKeyLen = 32

	// pqcConfirmTagLen is ample: an attacker gets one guess per round.
	pqcConfirmTagLen = 16
)

// pqcSuite is the ciphersuite. ExportOnly is deliberate: this module needs key
// derivation only, and that variant makes Seal and Open return errors by
// construction, so the context can never be misused for message encryption.
func pqcSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM1024P384(), hpke.HKDFSHA384(), hpke.ExportOnly()
}

// pqcRoundInfo binds protocol version and round index into the HPKE key
// schedule. Both peers must compute the same value, so the responder takes the
// round from the received frames and never from its own clock.
func pqcRoundInfo(round uint32) []byte {
	return binary.BigEndian.AppendUint32([]byte(pqcExporterContext+"|"), round)
}

// pqcInitiatorStart generates the per-round key pair. Called by the initiator,
// which is the HPKE recipient. A fresh pair every round is what provides
// forward secrecy.
func pqcInitiatorStart() (hpke.PrivateKey, []byte, error) {
	kem, _, _ := pqcSuite()
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: keygen: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// pqcResponderRespond encapsulates to the peer's public key and exports the
// shared key. Called by the responder, which is the HPKE sender.
//
// round MUST come from the received frames, never from the local clock.
func pqcResponderRespond(pubBytes []byte, round uint32) (enc, key []byte, err error) {
	kem, kdf, aead := pqcSuite()
	pub, err := kem.NewPublicKey(pubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: bad peer public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(pub, kdf, aead, pqcRoundInfo(round))
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: encapsulate: %w", err)
	}
	secret.Do(func() {
		key, err = sender.Export(pqcExporterContext, pqcKeyLen)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: export: %w", err)
	}
	if len(key) != pqcKeyLen {
		return nil, nil, fmt.Errorf("pqc: export returned %d bytes, want %d", len(key), pqcKeyLen)
	}
	return enc, key, nil
}

// pqcInitiatorFinish decapsulates and exports the same key.
//
// Note that this cannot detect a corrupted encapsulation: FIPS 203 ML-KEM uses
// implicit rejection, so decapsulation of a malformed ciphertext returns a
// pseudorandom shared secret rather than an error. Divergence is caught by the
// confirmation exchange below, never here.
func pqcInitiatorFinish(priv hpke.PrivateKey, enc []byte, round uint32) (key []byte, err error) {
	_, kdf, aead := pqcSuite()
	recip, err := hpke.NewRecipient(enc, priv, kdf, aead, pqcRoundInfo(round))
	if err != nil {
		return nil, fmt.Errorf("pqc: decapsulate: %w", err)
	}
	secret.Do(func() {
		key, err = recip.Export(pqcExporterContext, pqcKeyLen)
	})
	if err != nil {
		return nil, fmt.Errorf("pqc: export: %w", err)
	}
	if len(key) != pqcKeyLen {
		return nil, fmt.Errorf("pqc: export returned %d bytes, want %d", len(key), pqcKeyLen)
	}
	return key, nil
}

// pqcConfirmTag proves possession of the agreed key without revealing it. The
// tag is round-bound, so one from an earlier round cannot be replayed.
//
// REQUIRED, not belt-and-braces. ML-KEM decapsulation never fails, so without
// this check a corrupted encapsulation leaves the two peers holding different
// keys with no error raised anywhere, and the divergence surfaces one interval
// later as an unexplained WireGuard handshake failure. Do not remove as
// redundant.
func pqcConfirmTag(pqcKey []byte, round uint32) ([]byte, error) {
	info := string(binary.BigEndian.AppendUint32([]byte("arnika-pqc-hpke-confirm-v1|"), round))
	var tag []byte
	var err error
	secret.Do(func() {
		tag, err = hkdf.Key(sha3.New256, pqcKey, nil, info, pqcConfirmTagLen)
	})
	if err != nil {
		return nil, fmt.Errorf("pqc: confirm tag: %w", err)
	}
	return tag, nil
}

// pqcVerifyConfirm gates publication. Callers MUST NOT publish a key before
// this returns true.
func pqcVerifyConfirm(pqcKey []byte, round uint32, peerTag []byte) bool {
	want, err := pqcConfirmTag(pqcKey, round)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, peerTag) == 1
}

// ---------------------------------------------------------------------------
// 3. Transport, round scheduler and the key reader surface
// ---------------------------------------------------------------------------

// pqcMaxSendAttempts mirrors udpClient's send-with-ack retry count.
const pqcMaxSendAttempts = 3

// pqcResult is one agreed key and the moment it was agreed.
type pqcResult struct {
	key []byte
	at  time.Time
}

// PQCHPKERepository implements services.KeyReaderUnmanaged by running an HPKE
// key agreement with the Arnika peer once per round. It replaces reading the
// PQC key via file from an external PQC provider; the key never touches disk.
//
// The adapter owns no socket. It receives already-verified, already-decrypted
// frames on inbound and emits plaintext frames through send, both supplied by
// the wiring, which keeps it testable without any network.
type PQCHPKERepository struct {
	inbound <-chan []byte
	send    func([]byte) error

	// isInitiator pins the role for a round. Arnika's role alternates per
	// interval, so it is evaluated once at round start and held for the whole
	// round: re-deriving it mid-round would flip initiator and responder in
	// flight and fail the round intermittently.
	isInitiator func(round uint32) bool

	roundInterval time.Duration
	roundTimeout  time.Duration
	maxAge        time.Duration

	// keyMu guards latest and the zeroing of the buffer it supersedes.
	//
	// An atomic.Pointer is not enough here: it orders the pointer, not the bytes
	// behind it. With one, publish() could zero the superseded buffer while
	// GetNewKey() was still copying out of it after its own Load, handing the
	// caller an all-zero 32-byte "key" that nothing downstream rejects.
	keyMu  sync.RWMutex
	latest *pqcResult

	mu     sync.Mutex
	active bool // at most one round in flight
}

// NewPQCHPKERepository builds the adapter. Every dependency is an argument: it
// reads no environment and opens no socket.
func NewPQCHPKERepository(
	inbound <-chan []byte,
	send func([]byte) error,
	isInitiator func(round uint32) bool,
	roundInterval, roundTimeout, maxAge time.Duration,
) (*PQCHPKERepository, error) {
	if inbound == nil {
		return nil, fmt.Errorf("pqc: inbound channel is nil")
	}
	if send == nil {
		return nil, fmt.Errorf("pqc: send function is nil")
	}
	if isInitiator == nil {
		return nil, fmt.Errorf("pqc: isInitiator function is nil")
	}
	if roundInterval <= 0 {
		return nil, fmt.Errorf("pqc: round interval must be positive, got %s", roundInterval)
	}
	if roundTimeout <= 0 || roundTimeout >= roundInterval {
		return nil, fmt.Errorf("pqc: round timeout %s must be positive and shorter than the round interval %s",
			roundTimeout, roundInterval)
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("pqc: max key age must be positive, got %s", maxAge)
	}
	return &PQCHPKERepository{
		inbound:       inbound,
		send:          send,
		isInitiator:   isInitiator,
		roundInterval: roundInterval,
		roundTimeout:  roundTimeout,
		maxAge:        maxAge,
	}, nil
}

// pqcRoundIndex derives the round number from the clock, so it survives an
// asymmetric restart. An in-memory counter would deadlock when one peer
// restarts and the other does not.
func pqcRoundIndex(t time.Time, interval time.Duration) uint32 {
	secs := int64(interval.Seconds())
	if secs < 1 {
		secs = 1
	}
	return uint32(t.Unix() / secs)
}

// GetNewKey implements services.KeyReaderUnmanaged.
//
// It reads a register rather than a channel: it is called synchronously from
// setPSK(), may be called more than once per round, and needs the key's age.
// Staleness is reported as an error, leaving the decision to setPSK()'s existing
// IsPQCRequired() branch - no new policy is added here.
//
// The read lock is held only for a 32-byte copy, and the sole writer holds the
// write lock for a copy plus a clear, so this cannot block for a meaningful
// amount of time even though it is on the synchronous rekeying path.
func (r *PQCHPKERepository) GetNewKey() ([]byte, error) {
	r.keyMu.RLock()
	defer r.keyMu.RUnlock()

	v := r.latest
	if v == nil {
		return nil, fmt.Errorf("pqc-hpke: no key agreed yet")
	}
	if age := time.Since(v.at); age > r.maxAge {
		return nil, fmt.Errorf("pqc-hpke: key stale (age %s, max %s)",
			age.Truncate(time.Second), r.maxAge)
	}
	out := make([]byte, pqcKeyLen)
	copy(out, v.key)
	return out, nil
}

// publish installs a freshly agreed key and zeroes the one it supersedes.
// Callers must not reach here before confirmation has succeeded.
//
// The swap and the clear both happen under the write lock. Zeroing the
// superseded buffer outside it would race a GetNewKey() that had already taken
// its reference, and hand that caller an all-zero key: sync.RWMutex.Lock waits
// for every outstanding reader, so once it is held no reader can still be
// reading prev.key.
func (r *PQCHPKERepository) publish(key []byte) error {
	if len(key) != pqcKeyLen {
		return fmt.Errorf("pqc-hpke: refusing to publish %d-byte key, want %d", len(key), pqcKeyLen)
	}
	k := make([]byte, pqcKeyLen)
	copy(k, key)

	r.keyMu.Lock()
	defer r.keyMu.Unlock()

	prev := r.latest
	r.latest = &pqcResult{key: k, at: time.Now()}
	if prev != nil {
		clear(prev.key)
	}
	return nil
}

// Run drives the round schedule until ctx is cancelled.
//
// Two properties matter and neither is free:
//
//   - A round runs immediately on start. Waiting for the first boundary left
//     the first rekey with no key at all, which surfaced as a "failed to
//     retrieve PQC key" warning and a fallback for one whole interval.
//   - Later rounds are scheduled to *finish* before their boundary, by waking
//     one round timeout early, so a key for that boundary exists rather than
//     being published at it.
//
// Note what this does NOT do: it does not make the two peers read the same
// round's key during a rekey. Arnika's rekey instant is independent of the
// round boundary, so the probability that a publish lands between the two
// peers' setPSK calls is the read gap divided by the interval, wherever the
// publish sits. Closing that needs a shared selector - the peers agreeing on
// *which* round's key a given rekey uses - not a different schedule.
func (r *PQCHPKERepository) Run(ctx context.Context) {
	secs := int64(r.roundInterval.Seconds())
	if secs < 1 {
		secs = 1
	}

	// Best effort: this only completes if both peers start inside the same
	// interval, so a failure here is expected and not worth alarming about.
	startup := pqcRoundIndex(time.Now(), r.roundInterval)
	if err := r.RunRound(ctx, startup); err != nil {
		log.Printf("[INFO] pqc-hpke: startup round %d did not complete (%v); the first scheduled round follows",
			startup, err)
	}
	if ctx.Err() != nil {
		return
	}

	nextIdx := time.Now().Unix()/secs + 1
	for {
		wake := time.Unix(nextIdx*secs, 0).Add(-r.roundTimeout)
		if d := time.Until(wake); d > 0 {
			timer := time.NewTimer(d)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else if ctx.Err() != nil {
			return
		}

		// Indexed by the boundary this round serves, which both peers compute
		// identically from the clock.
		round := uint32(nextIdx)
		if err := r.RunRound(ctx, round); err != nil {
			log.Printf("[WARNING] pqc-hpke: round %d failed: %v", round, err)
		}

		nextIdx++
		// If a round overran its boundary, skip forward rather than chasing
		// boundaries that have already passed.
		if cur := time.Now().Unix()/secs + 1; nextIdx < cur {
			nextIdx = cur
		}
	}
}

// RunRound executes one complete agreement round. Nothing is published unless
// the round completes through confirmation.
func (r *PQCHPKERepository) RunRound(ctx context.Context, round uint32) error {
	r.mu.Lock()
	if r.active {
		r.mu.Unlock()
		return fmt.Errorf("pqc-hpke: round %d rejected, another round is already active", round)
	}
	r.active = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active = false
		r.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, r.roundTimeout)
	defer cancel()

	s := &pqcSession{
		repo:    r,
		round:   round,
		re:      newPQCReassembler(),
		pending: make(map[pqcKind][]byte),
		acked:   make(map[pqcKind]bool),
	}
	s.re.SetRound(round)

	// Pinned once, held for the whole round.
	if r.isInitiator(round) {
		return s.runInitiator(ctx)
	}
	return s.runResponder(ctx)
}

// pqcSession is the per-round state. Frames for other rounds never reach it.
type pqcSession struct {
	repo    *PQCHPKERepository
	round   uint32
	re      *pqcReassembler
	pending map[pqcKind][]byte // completed messages not yet consumed
	acked   map[pqcKind]bool   // kinds the peer has acknowledged
}

// pump reads one inbound frame and files the result.
func (s *pqcSession) pump(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case raw, ok := <-s.repo.inbound:
		if !ok {
			return fmt.Errorf("pqc-hpke: inbound channel closed")
		}
		f, err := decodeFrame(raw)
		if err != nil {
			return nil // malformed frame: drop, keep waiting
		}
		msg, complete := s.re.Add(f)
		if !complete {
			return nil
		}
		if f.kind == pqcKindAck {
			if len(msg) == 1 {
				s.acked[pqcKind(msg[0])] = true
			}
			return nil
		}
		s.pending[f.kind] = msg
		return nil
	}
}

// waitFor blocks until a complete message of the given kind is available.
func (s *pqcSession) waitFor(ctx context.Context, kind pqcKind) ([]byte, error) {
	for {
		if msg, ok := s.pending[kind]; ok {
			delete(s.pending, kind)
			return msg, nil
		}
		if err := s.pump(ctx); err != nil {
			return nil, err
		}
	}
}

// sendFrames emits every frame of a message.
func (s *pqcSession) sendFrames(kind pqcKind, msg []byte) error {
	frames, err := splitMessage(s.round, kind, msg)
	if err != nil {
		return err
	}
	for _, f := range frames {
		if err := s.repo.send(f); err != nil {
			return fmt.Errorf("pqc-hpke: send: %w", err)
		}
	}
	return nil
}

// sendAck acknowledges a received message.
func (s *pqcSession) sendAck(kind pqcKind) error {
	return s.sendFrames(pqcKindAck, []byte{byte(kind)})
}

// sendWithAck sends a message and waits for the peer's ack, retrying the whole
// message on timeout as udpClient does. HPKE is single-shot, so there is no
// partial state to recover: an exhausted retry budget simply fails the round.
func (s *pqcSession) attemptTimeout() time.Duration {
	d := s.repo.roundTimeout / pqcMaxSendAttempts
	if d <= 0 {
		d = s.repo.roundTimeout
	}
	return d
}

func (s *pqcSession) sendWithAck(ctx context.Context, kind pqcKind, msg []byte) error {
	attemptTimeout := s.attemptTimeout()
	for attempt := 1; attempt <= pqcMaxSendAttempts; attempt++ {
		if err := s.sendFrames(kind, msg); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		err := s.waitAck(attemptCtx, kind)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return fmt.Errorf("pqc-hpke: no ack for kind %d after %d attempts", kind, pqcMaxSendAttempts)
}

// waitAck blocks until the peer acknowledges the given kind.
func (s *pqcSession) waitAck(ctx context.Context, kind pqcKind) error {
	for {
		if s.acked[kind] {
			delete(s.acked, kind)
			return nil
		}
		if err := s.pump(ctx); err != nil {
			return err
		}
	}
}

// serviceConfirmRetries re-acknowledges repeated confirm messages for a grace
// period, so a lost acknowledgement costs a retry rather than the round.
func (s *pqcSession) serviceConfirmRetries(ctx context.Context, grace time.Duration) {
	lctx, cancel := context.WithTimeout(ctx, grace)
	defer cancel()
	for {
		if _, ok := s.pending[pqcKindConfirm]; ok {
			delete(s.pending, pqcKindConfirm)
			if err := s.sendAck(pqcKindConfirm); err != nil {
				return
			}
			continue
		}
		if err := s.pump(lctx); err != nil {
			return
		}
	}
}

// runInitiator is the HPKE recipient: it generates the key pair, receives the
// encapsulation, and derives the key.
func (s *pqcSession) runInitiator(ctx context.Context) error {
	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		return err
	}

	if err := s.sendWithAck(ctx, pqcKindPubKey, pub); err != nil {
		return err
	}

	enc, err := s.waitFor(ctx, pqcKindEnc)
	if err != nil {
		return fmt.Errorf("pqc-hpke: waiting for encapsulation: %w", err)
	}
	if err := s.sendAck(pqcKindEnc); err != nil {
		return err
	}

	key, err := pqcInitiatorFinish(priv, enc, s.round)
	if err != nil {
		return err
	}
	defer clear(key)
	defer clear(enc)

	return s.confirmAndPublish(ctx, key, true)
}

// runResponder is the HPKE sender: it encapsulates to the peer's public key.
func (s *pqcSession) runResponder(ctx context.Context) error {
	pub, err := s.waitFor(ctx, pqcKindPubKey)
	if err != nil {
		return fmt.Errorf("pqc-hpke: waiting for public key: %w", err)
	}
	if err := s.sendAck(pqcKindPubKey); err != nil {
		return err
	}

	// The round comes from the received frames, never from the local clock.
	enc, key, err := pqcResponderRespond(pub, s.round)
	if err != nil {
		return err
	}
	defer clear(key)
	defer clear(enc)

	if err := s.sendWithAck(ctx, pqcKindEnc, enc); err != nil {
		return err
	}

	return s.confirmAndPublish(ctx, key, false)
}

// confirmAndPublish exchanges confirmation tags and publishes only if they
// match. The initiator sends its tag first, mirroring the protocol flow.
//
// This gate exists because ML-KEM decapsulation never fails: without it two
// peers could hold different keys and poison the WireGuard PSK an interval
// later, with no error anywhere.
//
// The tag is a function of (key, round) alone, so both peers compute the same
// value and reach the same verdict - the only asymmetry is a lost frame. Both
// tags are therefore acknowledged: without that, the responder published as
// soon as it had verified, and a single lost confirm left it holding a key the
// initiator did not have. A residual remains, as it must for any last message:
// the final acknowledgement is itself unacknowledged, so an exhausted retry
// budget can still leave the two sides one round apart. The next round
// reconverges them, and maxAge bounds how long a lone key can be used.
func (s *pqcSession) confirmAndPublish(ctx context.Context, key []byte, initiator bool) error {
	tag, err := pqcConfirmTag(key, s.round)
	if err != nil {
		return err
	}

	var peerTag []byte
	if initiator {
		// Acked, so we know the responder can compare before we wait on it.
		if err := s.sendWithAck(ctx, pqcKindConfirm, tag); err != nil {
			return fmt.Errorf("pqc-hpke: sending confirmation: %w", err)
		}
		peerTag, err = s.waitFor(ctx, pqcKindConfirm)
		if err != nil {
			return fmt.Errorf("pqc-hpke: confirmation exchange: %w", err)
		}
		// Tell the responder its tag arrived; it publishes on this.
		if err := s.sendAck(pqcKindConfirm); err != nil {
			return err
		}
		if !pqcVerifyConfirm(key, s.round, peerTag) {
			return fmt.Errorf("pqc-hpke: key confirmation failed for round %d; nothing published", s.round)
		}
		if err := s.repo.publish(key); err != nil {
			return err
		}
		log.Printf("[INFO] pqc-hpke: round %d agreed a fresh PQC key", s.round)
		// Our ack is the last message and is itself unacknowledged. Stay and
		// answer retries for a while: otherwise a single lost ack would leave
		// the responder retrying into silence and failing a round we have
		// already committed to, which is the divergence this exchange exists
		// to prevent.
		s.serviceConfirmRetries(ctx, 2*s.attemptTimeout())
		return nil
	} else {
		peerTag, err = s.waitFor(ctx, pqcKindConfirm)
		if err != nil {
			return fmt.Errorf("pqc-hpke: confirmation exchange: %w", err)
		}
		if err := s.sendAck(pqcKindConfirm); err != nil {
			return err
		}
		// Verify before answering, so a mismatch never sends a tag back.
		if !pqcVerifyConfirm(key, s.round, peerTag) {
			return fmt.Errorf("pqc-hpke: key confirmation failed for round %d; nothing published", s.round)
		}
		// Publish only once the initiator has acknowledged our tag.
		if err := s.sendWithAck(ctx, pqcKindConfirm, tag); err != nil {
			return fmt.Errorf("pqc-hpke: confirming to peer: %w", err)
		}
	}

	if err := s.repo.publish(key); err != nil {
		return err
	}
	log.Printf("[INFO] pqc-hpke: round %d agreed a fresh PQC key", s.round)
	return nil
}
