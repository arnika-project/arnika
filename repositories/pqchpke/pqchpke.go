// Package pqchpke agrees the PQC key with the Arnika peer over HPKE (RFC 9180): pubKey out, enc‖tag_R back, tag_I out.
package pqchpke

import (
	"context"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log/slog"
	"runtime/secret"
	"sync"
	"time"
)

type pqcKind uint8

const (
	pqcKindPubKey pqcKind = 1
	pqcKindEnc    pqcKind = 2
	pqcKindTag    pqcKind = 3
)

const (
	pqcFrameHeaderLen = 8
	pqcChunkPayload   = 900 // a frame plus AES-GCM, auth.Packet and UDP/IPv4 overhead stays under a 1024-byte MTU
	pqcMaxFrames      = 2
)

type pqcFrame struct {
	round uint32
	kind  pqcKind
	seq   uint8
	total uint8
	data  []byte
}

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
	buf[7] = 0
	copy(buf[pqcFrameHeaderLen:], f.data)
	return buf, nil
}

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

type pqcJoiner struct {
	round uint32
	kind  pqcKind
	total int
	have  int
	parts [pqcMaxFrames][]byte
}

func (j *pqcJoiner) add(f pqcFrame) (msg []byte, complete bool) {
	if j.total == 0 || f.round != j.round || f.kind != j.kind || int(f.total) != j.total {
		*j = pqcJoiner{round: f.round, kind: f.kind, total: int(f.total)}
	}
	if j.total < 1 || j.total > pqcMaxFrames || int(f.seq) >= j.total { // unreachable past decodeFrame, kept so a looser header cannot panic from the wire
		*j = pqcJoiner{}
		return nil, false
	}
	if j.parts[f.seq] == nil {
		j.parts[f.seq] = f.data
		j.have++
	}
	if j.have != j.total {
		return nil, false
	}
	msg = make([]byte, 0, j.total*pqcChunkPayload)
	for i := 0; i < j.total; i++ {
		msg = append(msg, j.parts[i]...)
	}
	*j = pqcJoiner{}
	return msg, true
}

const (
	pqcExporterContext = "arnika-pqc-hpke-v1"
	pqcKeyLen          = 32
	pqcConfirmTagLen   = 16
	pqcRoleInitiator   = "I" // role labels keep the second confirmation tag from being an echo of the first
	pqcRoleResponder   = "R"
)

func pqcSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM1024P384(), hpke.HKDFSHA384(), hpke.ExportOnly()
}

func pqcRoundInfo(round uint32) []byte {
	return binary.BigEndian.AppendUint32([]byte(pqcExporterContext+"|"), round)
}

// pqcInitiatorStart makes a fresh key pair every round, which is what gives forward secrecy.
func pqcInitiatorStart() (hpke.PrivateKey, []byte, error) {
	kem, _, _ := pqcSuite()
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: keygen: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// pqcResponderRespond takes round from the received frames, never the local clock, or the peers derive different keys.
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

// pqcConfirmTag is required: ML-KEM decapsulation never fails, so only these round- and role-bound tags catch divergent keys.
func pqcConfirmTag(pqcKey []byte, round uint32, role string) ([]byte, error) {
	info := string(binary.BigEndian.AppendUint32([]byte("arnika-pqc-hpke-confirm-v1|"+role+"|"), round))
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

func pqcVerifyConfirm(pqcKey []byte, round uint32, peerRole string, peerTag []byte) bool {
	want, err := pqcConfirmTag(pqcKey, round, peerRole)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, peerTag) == 1
}

const pqcMaxSendAttempts = 3

const (
	MessageFrames   = pqcMaxFrames
	MaxSendAttempts = pqcMaxSendAttempts
)

func RoundSeconds(interval time.Duration) int64 {
	return pqcIntervalSecs(interval)
}

const pqcSendRetryDelay = 50 * time.Millisecond

const pqcStartupGrace = 100 * time.Millisecond

// pqcAgreedMsg is counted by ci/local-darwin/run.sh and ci/e2e to assert that rounds progress.
const pqcAgreedMsg = "round agreed a fresh PQC key"

type pqcResult struct {
	key   []byte
	round uint32
	at    time.Time
}

type pqcResponderState struct {
	join  pqcJoiner
	round uint32
	live  bool
	key   []byte
	reply [][]byte
}

type Repository struct {
	send        func(frame []byte) error
	recv        func(deadline time.Time) ([]byte, error)
	isInitiator func(round uint32) bool

	roundInterval time.Duration
	roundTimeout  time.Duration
	maxAge        time.Duration

	log *slog.Logger

	keyMu  sync.RWMutex // also orders zeroing the superseded key against readers, which an atomic.Pointer cannot
	latest *pqcResult

	respMu sync.Mutex
	resp   pqcResponderState
}

func NewRepository(
	logger *slog.Logger,
	send func(frame []byte) error,
	recv func(deadline time.Time) ([]byte, error),
	isInitiator func(round uint32) bool,
	roundInterval, roundTimeout, maxAge time.Duration,
) (*Repository, error) {
	if send == nil {
		return nil, fmt.Errorf("pqc: send function is nil")
	}
	if recv == nil {
		return nil, fmt.Errorf("pqc: recv function is nil")
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
	if maxAge <= roundInterval { // else the key is stale for part of every healthy round
		return nil, fmt.Errorf("pqc: max key age %s must be longer than the round interval %s",
			maxAge, roundInterval)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Repository{
		log:           logger.With("component", "pqc-hpke"),
		send:          send,
		recv:          recv,
		isInitiator:   isInitiator,
		roundInterval: roundInterval,
		roundTimeout:  roundTimeout,
		maxAge:        maxAge,
	}, nil
}

func pqcIntervalSecs(interval time.Duration) int64 {
	if secs := int64(interval.Seconds()); secs >= 1 {
		return secs
	}
	return 1
}

// pqcRoundIndex comes from the clock, not a counter, so a peer that restarts alone still agrees on the round.
func pqcRoundIndex(t time.Time, interval time.Duration) uint32 {
	return uint32(t.Unix() / pqcIntervalSecs(interval))
}

// pqcNextRound serves the boundary after now and starts late rather than skipping it, so peers never pick different rounds.
func pqcNextRound(now time.Time, interval, timeout time.Duration) (round uint32, wake time.Time) {
	secs := pqcIntervalSecs(interval)
	idx := now.Unix()/secs + 1
	wake = time.Unix(idx*secs, 0).Add(-timeout)
	if wake.Before(now) {
		wake = now
	}
	return uint32(idx), wake
}

// pqcFollowingRound skips served, which the clock names again when Run's monotonic boundary sleep wakes early.
func pqcFollowingRound(now time.Time, interval, timeout time.Duration, served uint32) (round uint32, wake time.Time) {
	round, wake = pqcNextRound(now, interval, timeout)
	if round != served {
		return round, wake
	}
	round = served + 1
	wake = time.Unix(int64(round)*pqcIntervalSecs(interval), 0).Add(-timeout)
	if wake.Before(now) {
		wake = now
	}
	return round, wake
}

func sleepUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (r *Repository) GetNewKey() ([]byte, error) {
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

// publish keeps the highest round while it is fresh so peers converge in any order; once stale any round replaces it, recovering a backward clock step.
func (r *Repository) publish(round uint32, key []byte) error {
	if len(key) != pqcKeyLen {
		return fmt.Errorf("pqc-hpke: refusing to publish %d-byte key, want %d", len(key), pqcKeyLen)
	}
	k := make([]byte, pqcKeyLen)
	copy(k, key)

	r.keyMu.Lock()
	defer r.keyMu.Unlock()

	prev := r.latest
	if prev != nil && round < prev.round {
		age := time.Since(prev.at)
		if age <= r.maxAge {
			clear(k)
			r.log.Info("round agreed, but a newer round is already published and still fresh; keeping the newer one",
				"round", round, "published_round", prev.round, "age", age.Truncate(time.Second))
			return nil
		}
		r.log.Warn("round is behind the published one but that key is stale; taking the lower round as the new baseline, which is how a backward clock step recovers",
			"round", round, "published_round", prev.round, "age", age.Truncate(time.Second), "max_age", r.maxAge)
	}
	r.latest = &pqcResult{key: k, round: round, at: time.Now()}
	if prev != nil {
		clear(prev.key)
	}
	return nil
}

func (r *Repository) Run(ctx context.Context) {
	if !sleepUntil(ctx, time.Now().Add(pqcStartupGrace)) {
		return
	}

	if startup := pqcRoundIndex(time.Now(), r.roundInterval); r.isInitiator(startup) {
		if err := r.runRound(ctx, startup); err != nil {
			r.log.Info("startup round did not complete; the first scheduled round follows",
				"round", startup, "err", err)
		}
	}
	if ctx.Err() != nil {
		return
	}

	secs := pqcIntervalSecs(r.roundInterval)
	var served uint32
	for {
		round, wake := pqcFollowingRound(time.Now(), r.roundInterval, r.roundTimeout, served)
		if !sleepUntil(ctx, wake) {
			return
		}

		if r.isInitiator(round) {
			if err := r.runRound(ctx, round); err != nil {
				r.log.Warn("round failed", "round", round, "err", err)
			}
		}
		served = round

		if !sleepUntil(ctx, time.Unix(int64(round)*secs, 0)) { // until the boundary passes the clock names this round again
			return
		}
	}
}

func (r *Repository) runRound(ctx context.Context, round uint32) error {
	ctx, cancel := context.WithTimeout(ctx, r.roundTimeout)
	defer cancel()

	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		return err
	}

	reply, err := r.exchange(ctx, round, pub)
	if err != nil {
		return err
	}
	if len(reply) <= pqcConfirmTagLen {
		return fmt.Errorf("pqc-hpke: reply of %d bytes carries no encapsulation", len(reply))
	}
	enc, peerTag := reply[:len(reply)-pqcConfirmTagLen], reply[len(reply)-pqcConfirmTagLen:]
	defer clear(enc)

	key, err := pqcInitiatorFinish(priv, enc, round)
	if err != nil {
		return err
	}
	defer clear(key)

	if !pqcVerifyConfirm(key, round, pqcRoleResponder, peerTag) {
		return fmt.Errorf("pqc-hpke: key confirmation failed for round %d; nothing published", round)
	}

	tag, err := pqcConfirmTag(key, round, pqcRoleInitiator)
	if err != nil {
		return err
	}
	if err := r.sendMessage(ctx, round, pqcKindTag, tag); err != nil { // before publish, so a local send failure leaves neither side with a key
		return err
	}
	if err := r.publish(round, key); err != nil {
		return err
	}
	r.log.Info(pqcAgreedMsg, "round", round, "as", "initiator")
	return nil
}

func (r *Repository) exchange(ctx context.Context, round uint32, pub []byte) ([]byte, error) {
	attempt := r.roundTimeout / pqcMaxSendAttempts
	if attempt <= 0 {
		attempt = r.roundTimeout
	}
	var lastErr error
	for i := 1; i <= pqcMaxSendAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := r.sendMessage(ctx, round, pqcKindPubKey, pub); err != nil {
			return nil, err
		}
		reply, err := r.readMessage(ctx, round, pqcKindEnc, time.Now().Add(attempt))
		if err == nil {
			return reply, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("pqc-hpke: no reply to the public key after %d attempts: %w",
		pqcMaxSendAttempts, lastErr)
}

func (r *Repository) readMessage(ctx context.Context, round uint32, kind pqcKind, deadline time.Time) ([]byte, error) {
	var join pqcJoiner
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := r.recv(deadline)
		if err != nil {
			return nil, err
		}
		f, err := decodeFrame(raw)
		if err != nil || f.round != round || f.kind != kind {
			continue
		}
		if msg, complete := join.add(f); complete {
			return msg, nil
		}
	}
}

// sendMessage retries failed writes, since a peer still binding its listener shows up as ICMP port-unreachable.
func (r *Repository) sendMessage(ctx context.Context, round uint32, kind pqcKind, msg []byte) error {
	frames, err := splitMessage(round, kind, msg)
	if err != nil {
		return err
	}
	for attempt := 1; attempt <= pqcMaxSendAttempts; attempt++ {
		if err = pqcSendFrames(r.send, frames); err == nil {
			return nil
		}
		if !sleepUntil(ctx, time.Now().Add(pqcSendRetryDelay)) {
			return ctx.Err()
		}
	}
	return err
}

func pqcSendFrames(send func([]byte) error, frames [][]byte) error {
	for _, f := range frames {
		if err := send(f); err != nil {
			return fmt.Errorf("pqc-hpke: send: %w", err)
		}
	}
	return nil
}

// HandleFrame runs on the UDP read loop that also carries QKD, so neither it nor reply may block.
func (r *Repository) HandleFrame(raw []byte, reply func(frame []byte) error) error {
	f, err := decodeFrame(raw)
	if err != nil {
		return err
	}

	cur := int64(pqcRoundIndex(time.Now(), r.roundInterval))
	if !pqcInWindow(f.round, cur) {
		return fmt.Errorf("pqc-hpke: frame for round %d outside the window [%d,%d]", f.round, cur-1, cur+1)
	}

	r.respMu.Lock()
	defer r.respMu.Unlock()

	if r.resp.live && !pqcInWindow(r.resp.round, cur) {
		r.log.Warn("round abandoned: it is outside the round window, so its confirmation can no longer arrive",
			"round", r.resp.round, "window_low", cur-1, "window_high", cur+1)
		r.clearResponder()
	}

	msg, complete := r.resp.join.add(f)
	if !complete {
		return nil
	}
	switch f.kind {
	case pqcKindPubKey:
		return r.respondPubKey(f.round, msg, reply)
	case pqcKindTag:
		return r.respondTag(f.round, msg)
	default:
		return fmt.Errorf("pqc-hpke: responder received unexpected kind %d", f.kind)
	}
}

// pqcInWindow is replay protection: the envelope accepts an authenticated frame for MAX_CLOCK_SKEW, several rounds.
func pqcInWindow(round uint32, cur int64) bool {
	d := int64(round) - cur
	return d >= -1 && d <= 1
}

func (r *Repository) respondPubKey(round uint32, pub []byte, reply func([]byte) error) error {
	if r.resp.live && r.resp.round == round { // resend: a second encapsulation would agree a second key for this round
		return pqcSendFrames(reply, r.resp.reply)
	}
	if r.resp.live && round < r.resp.round {
		return fmt.Errorf("pqc-hpke: public key for round %d behind the round in flight %d",
			round, r.resp.round)
	}

	enc, key, err := pqcResponderRespond(pub, round)
	if err != nil {
		return err
	}
	tag, err := pqcConfirmTag(key, round, pqcRoleResponder)
	if err != nil {
		clear(key)
		return err
	}
	msg := make([]byte, 0, len(enc)+len(tag))
	msg = append(msg, enc...)
	msg = append(msg, tag...)
	frames, err := splitMessage(round, pqcKindEnc, msg)
	clear(enc)
	if err != nil {
		clear(key)
		return err
	}

	r.clearResponder()
	r.resp.round, r.resp.live, r.resp.key, r.resp.reply = round, true, key, frames
	return pqcSendFrames(reply, frames)
}

func (r *Repository) respondTag(round uint32, peerTag []byte) error {
	if !r.resp.live || r.resp.round != round {
		return fmt.Errorf("pqc-hpke: confirmation for round %d with no round in flight", round)
	}
	defer r.clearResponder()

	if !pqcVerifyConfirm(r.resp.key, round, pqcRoleInitiator, peerTag) {
		return fmt.Errorf("pqc-hpke: key confirmation failed for round %d; nothing published", round)
	}
	if err := r.publish(round, r.resp.key); err != nil {
		return err
	}
	r.log.Info(pqcAgreedMsg, "round", round, "as", "responder")
	return nil
}

func (r *Repository) clearResponder() {
	clear(r.resp.key)
	r.resp = pqcResponderState{}
}
