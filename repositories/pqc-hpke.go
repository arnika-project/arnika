// Package repositories - pqc-hpke key reader.
//
// This adapter derives the 32-byte PQC key by running an HPKE (RFC 9180) key
// agreement directly with the Arnika peer, replacing the reader that took the
// PQC key via file from an external PQC provider. It has no build tag and no
// platform constraint: it compiles, vets, lints and tests on every platform.
//
// The exchange is three messages and two round trips, in the same
// send-and-wait-for-the-reply shape udpClient uses for the QKD key id:
//
//	initiator -> responder   pubKey        (2 frames)
//	initiator <- responder   enc ‖ tag_R   (2 frames, the reply is the ack)
//	initiator -> responder   tag_I         (1 frame, the tag is the ack)
//
// The initiator owns the schedule, the retries and the timeout. The responder
// has none of the three: it is driven entirely by the messages it receives, so
// its whole protocol is HandleFrame.
//
// The file is organised in three sections:
//
//  1. frame layer         - splitting and reassembling messages that exceed one datagram
//  2. HPKE core           - the key agreement itself, plus mandatory key confirmation
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
	pqcKindPubKey pqcKind = 1 // HPKE public key (1665 bytes, 2 frames)
	pqcKindEnc    pqcKind = 2 // HPKE encapsulation ‖ responder tag (1681 bytes, 2 frames)
	pqcKindTag    pqcKind = 3 // initiator key confirmation tag (16 bytes, 1 frame)
)

const (
	// pqcFrameHeaderLen is [round uint32][kind uint8][seq uint8][total uint8][reserved uint8].
	pqcFrameHeaderLen = 8

	// pqcChunkPayload leaves room on a small path: 908 (header+data) -> 936
	// (AES-GCM) -> 979 (auth.Packet) -> 1007 with UDP/IPv4 headers. That fits
	// a 1492-byte PPPoE path with margin to spare, and even a 1024-byte one.
	pqcChunkPayload = 900

	// pqcMaxFrames bounds reassembly state. The largest message is the 1681-byte
	// encapsulation plus tag, which needs two frames. A suite whose messages
	// exceed 1800 bytes has to raise this.
	pqcMaxFrames = 2
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
// produces one frame, so an empty message is a message like any other.
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

// pqcJoiner reassembles the frames of one message. Exactly one message is ever
// in flight per direction, so the state is a fixed array and a frame belonging
// to another (round, kind) simply restarts it: there is no reassembly garbage
// to collect and nothing to time out.
type pqcJoiner struct {
	round uint32
	kind  pqcKind
	total int
	have  int
	parts [pqcMaxFrames][]byte
}

// add files one frame and returns the message once every frame has arrived.
// Duplicate and out-of-order frames are handled.
func (j *pqcJoiner) add(f pqcFrame) (msg []byte, complete bool) {
	if j.total == 0 || f.round != j.round || f.kind != j.kind || int(f.total) != j.total {
		*j = pqcJoiner{round: f.round, kind: f.kind, total: int(f.total)}
	}
	if j.total < 1 || j.total > pqcMaxFrames || int(f.seq) >= j.total {
		// decodeFrame rules this out; kept because a panic here would be
		// reachable from the wire if a future header change loosened it.
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

	// Role labels for the confirmation tags. Without them both peers compute
	// the identical tag, and the second one to be sent is a pure echo of the
	// first: it proves possession of the PSK, which the envelope already did,
	// and nothing about the agreed key.
	pqcRoleInitiator = "I"
	pqcRoleResponder = "R"
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
// confirmation tags below, never here.
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
// tag is bound to the round and to the sender's role, so neither an earlier
// round's tag nor the peer's own tag can be replayed back at it.
//
// REQUIRED, not belt-and-braces. ML-KEM decapsulation never fails, so without
// this check a corrupted encapsulation leaves the two peers holding different
// keys with no error raised anywhere, and the divergence surfaces one interval
// later as an unexplained WireGuard handshake failure. Do not remove as
// redundant.
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

// pqcVerifyConfirm gates publication. Callers MUST NOT publish a key before
// this returns true. role is the label the *peer* signs with.
func pqcVerifyConfirm(pqcKey []byte, round uint32, role string, peerTag []byte) bool {
	want, err := pqcConfirmTag(pqcKey, round, role)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, peerTag) == 1
}

// ---------------------------------------------------------------------------
// 3. Transport, round scheduler and the key reader surface
// ---------------------------------------------------------------------------

// pqcMaxSendAttempts mirrors udpClient's send-with-reply retry count.
const pqcMaxSendAttempts = 3

// pqcSendRetryDelay spaces retries of a failed write. A UDP send can fail with
// ICMP port-unreachable simply because the peer has not bound its socket yet,
// which is routine when both peers start at once, so the delay is short.
const pqcSendRetryDelay = 50 * time.Millisecond

// pqcStartupGrace lets a peer starting at the same moment bind its listener
// before the startup round tries to reach it. The startup round is the one
// round with no earlier round to fall back on.
const pqcStartupGrace = 100 * time.Millisecond

// pqcResult is one agreed key, the round that agreed it, and when.
type pqcResult struct {
	key   []byte
	round uint32
	at    time.Time
}

// pqcResponderState is what the responder carries between the two messages it
// sees in a round.
//
// The reply frames are kept so that a retried public key is answered by
// resending them: encapsulating a second time would agree a second key for the
// same round, and whichever reply reached the initiator first would silently
// decide which one it confirmed.
type pqcResponderState struct {
	join  pqcJoiner
	round uint32
	live  bool
	key   []byte
	reply [][]byte
}

// PQCHPKERepository implements services.KeyReaderUnmanaged by running an HPKE
// key agreement with the Arnika peer once per round. It replaces reading the
// PQC key via file from an external PQC provider; the key never touches disk.
//
// The adapter owns no socket. As initiator it sends and receives plaintext
// frames through send and recv; as responder it is handed already-verified,
// already-decrypted frames through HandleFrame and answers through the reply
// function that comes with them. All four are supplied by the wiring, which
// keeps the whole module testable without any network.
type PQCHPKERepository struct {
	// send and recv are the initiator's request/response channel to the peer:
	// a connected UDP socket in production, exactly what udpClient uses for
	// the QKD key id, and a pair of channels in tests.
	send func(frame []byte) error
	recv func(deadline time.Time) ([]byte, error)

	// isInitiator decides who knocks in a given round. Both peers compute it
	// from the same clock-derived round index and the same PSK, so exactly one
	// of them initiates; the other only ever answers.
	isInitiator func(round uint32) bool

	roundInterval time.Duration
	roundTimeout  time.Duration
	maxAge        time.Duration

	// logPrefix identifies this reader in the log, in the same NAME[ARNIKA_ID]
	// form the rest of Arnika uses. Supplied by the wiring, which is where the
	// node's identity and its colour live.
	logPrefix string

	// keyMu guards latest and the zeroing of the buffer it supersedes.
	//
	// An atomic.Pointer is not enough here: it orders the pointer, not the bytes
	// behind it. With one, publish() could zero the superseded buffer while
	// GetNewKey() was still copying out of it after its own Load, handing the
	// caller an all-zero 32-byte "key" that nothing downstream rejects.
	keyMu  sync.RWMutex
	latest *pqcResult

	// respMu guards the responder state. HandleFrame runs on the UDP read loop,
	// a single goroutine, but publish is shared with the initiator's round and
	// the tests drive both from their own goroutines.
	respMu sync.Mutex
	resp   pqcResponderState
}

// NewPQCHPKERepository builds the adapter. Every dependency is an argument: it
// reads no environment and opens no socket.
func NewPQCHPKERepository(
	logPrefix string,
	send func(frame []byte) error,
	recv func(deadline time.Time) ([]byte, error),
	isInitiator func(round uint32) bool,
	roundInterval, roundTimeout, maxAge time.Duration,
) (*PQCHPKERepository, error) {
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
	if maxAge <= 0 {
		return nil, fmt.Errorf("pqc: max key age must be positive, got %s", maxAge)
	}
	if logPrefix == "" {
		logPrefix = "PQC-HPKE"
	}
	return &PQCHPKERepository{
		logPrefix:     logPrefix,
		send:          send,
		recv:          recv,
		isInitiator:   isInitiator,
		roundInterval: roundInterval,
		roundTimeout:  roundTimeout,
		maxAge:        maxAge,
	}, nil
}

// pqcIntervalSecs is the round interval in whole seconds, floored at one. The
// round index is second-granular, so every derivation of it must round the
// interval the same way or the two peers can disagree.
func pqcIntervalSecs(interval time.Duration) int64 {
	if secs := int64(interval.Seconds()); secs >= 1 {
		return secs
	}
	return 1
}

// pqcRoundIndex derives the round number from the clock, so it survives an
// asymmetric restart. An in-memory counter would deadlock when one peer
// restarts and the other does not.
func pqcRoundIndex(t time.Time, interval time.Duration) uint32 {
	return uint32(t.Unix() / pqcIntervalSecs(interval))
}

// pqcNextRound returns the round to serve next and the moment to start it.
//
// The round is always the boundary that follows now, so it is in the future by
// construction and never a boundary that has already passed. Both peers derive
// it from the clock alone, and the only input is which interval each is in -
// nothing finer.
//
// If the ideal start has passed the round begins immediately rather than being
// skipped. Skipping looked tidier but made the choice depend on which side of
// the wake instant each peer happened to evaluate: two peers milliseconds apart
// then picked different rounds, and the one that ran alone burned an interval.
// Starting late costs part of the round's budget; disagreeing costs the round.
func pqcNextRound(now time.Time, interval, timeout time.Duration) (round uint32, wake time.Time) {
	secs := pqcIntervalSecs(interval)
	idx := now.Unix()/secs + 1
	wake = time.Unix(idx*secs, 0).Add(-timeout)
	if wake.Before(now) {
		wake = now
	}
	return uint32(idx), wake
}

// pqcFollowingRound picks the round to serve after served, and when to start it.
//
// It is pqcNextRound plus one guard. The boundary wait in Run measures its gap
// on the wall clock but sleeps on the monotonic one, so it can return in the
// second *before* the boundary rather than on it, and the clock then names the
// round just served a second time. Serving a round twice agrees a second key
// for it and logs it twice. Taking the round after it is exactly what the clock
// itself returns a moment later, so the two peers still agree.
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

// sleepUntil blocks until t, reporting false if ctx was cancelled first.
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
// A key from an *older* round never supersedes a newer one. Two rounds can
// complete at the same instant - at startup the round for the current index and
// the round for the next boundary are both due, and one peer initiates each -
// and the order the two publishes land in is then reversed on the two peers.
// Keeping the last one had them hold different keys and derive two different
// PSKs from them, which is exactly the divergence that has no symptom until the
// WireGuard handshake fails. Keeping the highest round is order-independent, so
// both peers converge on the same key whatever the interleaving.
//
// The swap and the clear both happen under the write lock. Zeroing the
// superseded buffer outside it would race a GetNewKey() that had already taken
// its reference, and hand that caller an all-zero key: sync.RWMutex.Lock waits
// for every outstanding reader, so once it is held no reader can still be
// reading prev.key.
func (r *PQCHPKERepository) publish(round uint32, key []byte) error {
	if len(key) != pqcKeyLen {
		return fmt.Errorf("pqc-hpke: refusing to publish %d-byte key, want %d", len(key), pqcKeyLen)
	}
	k := make([]byte, pqcKeyLen)
	copy(k, key)

	r.keyMu.Lock()
	defer r.keyMu.Unlock()

	prev := r.latest
	if prev != nil && round < prev.round {
		clear(k)
		log.Printf("[INFO] %s [OK] round %d agreed, but round %d is already published; keeping the newer one",
			r.logPrefix, round, prev.round)
		return nil
	}
	r.latest = &pqcResult{key: k, round: round, at: time.Now()}
	if prev != nil {
		clear(prev.key)
	}
	return nil
}

// Run drives the round schedule until ctx is cancelled. Only the initiator of a
// round does anything here; the responder needs no schedule, because the
// initiator's first message is what starts its side of the round.
//
// Four properties matter and none is free:
//
//   - A round runs immediately on start, after a short grace for a peer binding
//     its listener at the same moment. Waiting for the first boundary left the
//     first rekey with no key at all, which surfaced as a "failed to retrieve
//     PQC key" warning and a fallback for one whole interval.
//   - Later rounds are scheduled to *finish* before their boundary, by waking
//     one round timeout early, so a key for that boundary exists rather than
//     being published at it.
//   - The round served is always the boundary that *follows* now, so it is in
//     the future by construction. If the ideal start has passed the round begins
//     late rather than being skipped: skipping made the choice depend on which
//     side of the wake instant each peer evaluated, and peers milliseconds apart
//     then picked different rounds. A late start costs part of a round's budget;
//     disagreeing costs the round.
//   - Each iteration waits out its round's boundary before asking for the next
//     one, because the index is clock-derived and would otherwise repeat.
//
// The residual, as for any protocol whose last message is unacknowledged: if
// the initiator's tag is lost, it has published and the responder has not, and
// for one interval the two may feed different keys into the PSK. The next round
// reconverges them and maxAge bounds how long a lone key can be used.
//
// Note what this does NOT do: it does not make the two peers read the same
// round's key during a rekey. Arnika's rekey instant is independent of the
// round boundary, so the probability that a publish lands between the two
// peers' setPSK calls is the read gap divided by the interval, wherever the
// publish sits. Closing that needs a shared selector - the peers agreeing on
// *which* round's key a given rekey uses - not a different schedule.
func (r *PQCHPKERepository) Run(ctx context.Context) {
	// Give a peer starting at the same moment time to bind its listener. The
	// startup round is the one round with no earlier round to fall back on.
	if !sleepUntil(ctx, time.Now().Add(pqcStartupGrace)) {
		return
	}

	// Best effort: this only completes if both peers start inside the same
	// interval, so a failure here is expected and not worth alarming about.
	if startup := pqcRoundIndex(time.Now(), r.roundInterval); r.isInitiator(startup) {
		if err := r.runRound(ctx, startup); err != nil {
			log.Printf("[INFO] %s [FAIL] startup round %d did not complete (%v); the first scheduled round follows",
				r.logPrefix, startup, err)
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
				log.Printf("[WARNING] %s [FAIL] round %d failed: %v", r.logPrefix, round, err)
			}
		}
		served = round

		// Wait out this round's boundary before asking for the next one. The
		// index comes from the clock, so looping while the boundary is still
		// ahead names the same round again: a round that finished early - the
		// normal case, in milliseconds - would be run over and over until the
		// boundary passed, and a node that is not the initiator would spin.
		// pqcFollowingRound covers the remainder, where this wait returns a
		// hair early because it is a monotonic sleep to a wall-clock instant.
		if !sleepUntil(ctx, time.Unix(int64(round)*secs, 0)) {
			return
		}
	}
}

// runRound executes one agreement as the initiator. Nothing is published unless
// the responder's tag verifies against the key this side derived.
func (r *PQCHPKERepository) runRound(ctx context.Context, round uint32) error {
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
	// Sent before publishing, so that a send that fails locally leaves both
	// sides without a key rather than only this one. A frame lost in flight is
	// indistinguishable from a delivered one and leaves the residual Run
	// documents.
	if err := r.sendMessage(ctx, round, pqcKindTag, tag); err != nil {
		return err
	}
	if err := r.publish(round, key); err != nil {
		return err
	}
	log.Printf("[INFO] %s [OK] round %d agreed a fresh PQC key (initiator)", r.logPrefix, round)
	return nil
}

// exchange sends the public key and returns the peer's reply, retrying the
// whole message on timeout as udpClient does. HPKE is single-shot, so an
// exhausted budget has no partial state to recover: the round simply fails and
// the next one proceeds.
func (r *PQCHPKERepository) exchange(ctx context.Context, round uint32, pub []byte) ([]byte, error) {
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

// readMessage collects frames until the wanted message is complete or the
// deadline passes. Frames of another round or another kind are dropped: a late
// reply from an earlier round must not be mistaken for this one's.
func (r *PQCHPKERepository) readMessage(ctx context.Context, round uint32, kind pqcKind, deadline time.Time) ([]byte, error) {
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

// sendMessage emits every frame of one message on the initiator's channel,
// tolerating a transient write failure.
//
// A failed write must cost a retry, not the round: at startup the peer's
// listener may be milliseconds behind ours, and the kernel reports that as ICMP
// port-unreachable on the next send. Returning it immediately threw away a
// round that one retry would have completed.
//
// Only the initiator retries. The responder answers the source address of a
// datagram it just received, so that port is bound by definition, and its
// unconnected socket is never handed an ICMP error in the first place - while a
// sleep on its path would block the UDP read loop, and with it the QKD path.
func (r *PQCHPKERepository) sendMessage(ctx context.Context, round uint32, kind pqcKind, msg []byte) error {
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

// HandleFrame is the responder's entire protocol: two messages in, one message
// out, no schedule, no timeout and no retry, because the initiator owns all
// three. It is called once per verified, decrypted PacketPQC frame.
//
// reply sends one plaintext frame back to whoever sent this one. Neither it nor
// this function may block: both run on the UDP read loop, which also carries
// the QKD path.
func (r *PQCHPKERepository) HandleFrame(raw []byte, reply func(frame []byte) error) error {
	f, err := decodeFrame(raw)
	if err != nil {
		return err
	}

	// Only a round the schedule could legitimately be serving is accepted: the
	// boundary that follows now, the current index the startup round uses, and
	// one interval of slack for clock skew between the peers.
	//
	// REQUIRED. The envelope authenticates a frame but does not make it fresh:
	// its timestamp is only bounded by MAX_CLOCK_SKEW, a minute by default, so
	// an off-path attacker who captured a public key needs no PSK to replay it
	// several rounds later. Without this window that replay would install
	// itself as the round in flight and destroy the state of the real one,
	// leaving the responder unable to confirm and the initiator published
	// alone - precisely the divergence the confirmation exists to prevent.
	cur := int64(pqcRoundIndex(time.Now(), r.roundInterval))
	if d := int64(f.round) - cur; d < -1 || d > 1 {
		return fmt.Errorf("pqc-hpke: frame for round %d outside the window [%d,%d]", f.round, cur-1, cur+1)
	}

	r.respMu.Lock()
	defer r.respMu.Unlock()

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

// respondPubKey encapsulates to the peer's public key and answers with the
// encapsulation and this side's confirmation tag as one message.
func (r *PQCHPKERepository) respondPubKey(round uint32, pub []byte, reply func([]byte) error) error {
	// A retried public key is answered from the stored reply. Encapsulating
	// again would agree a second key for the same round, and the initiator
	// would confirm whichever reply reached it first while this side kept the
	// other - the exact divergence the tags exist to prevent.
	if r.resp.live && r.resp.round == round {
		return pqcSendFrames(reply, r.resp.reply)
	}
	// A public key for an *older* round never replaces the round in flight.
	// Inside the window above a replay can still name the previous round, and
	// taking it would discard the pending key the confirmation is about to be
	// checked against.
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
	// One message: the initiator needs both halves, and neither is of any use
	// without the other.
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

// respondTag verifies the initiator's tag and publishes on a match. This is the
// check that catches ML-KEM implicit rejection: the initiator cannot produce
// this tag from a divergent key.
func (r *PQCHPKERepository) respondTag(round uint32, peerTag []byte) error {
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
	log.Printf("[INFO] %s [OK] round %d agreed a fresh PQC key (responder)", r.logPrefix, round)
	return nil
}

// clearResponder zeroes the unpublished key and drops the round state.
func (r *PQCHPKERepository) clearResponder() {
	clear(r.resp.key)
	r.resp = pqcResponderState{}
}
