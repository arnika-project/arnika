// Package repositories - pqc-hpke key reader.
//
// This adapter derives the 32-byte PQC key by running an HPKE (RFC 9180) key
// agreement directly with the Arnika peer, replacing the file-based Rosenpass
// reader. It has no build tag and no platform constraint: it compiles, vets,
// lints and tests on every platform.
//
// The file is organised in three sections:
//
//  1. frame layer      - splitting and reassembling messages that exceed one datagram
//  2. HPKE core        - the key agreement itself, plus mandatory key confirmation
//  3. transport/scheduler - rounds, retries and the KeyReaderUnmanaged surface
package repositories

import (
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"runtime/secret"
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
