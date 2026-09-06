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
	"encoding/binary"
	"fmt"
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
