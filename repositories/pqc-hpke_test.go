package repositories

import (
	"bytes"
	"crypto/hpke"
	"crypto/rand"
	"testing"
)

// --- frame layer ------------------------------------------------------------

func mustSplit(t *testing.T, round uint32, kind pqcKind, msg []byte) [][]byte {
	t.Helper()
	frames, err := splitMessage(round, kind, msg)
	if err != nil {
		t.Fatalf("splitMessage: %v", err)
	}
	return frames
}

func TestPQCFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		size       int
		wantFrames int
	}{
		{"empty (ack)", 0, 1},
		{"one byte", 1, 1},
		{"one frame exactly", pqcChunkPayload, 1},
		{"one byte over the boundary", pqcChunkPayload + 1, 2},
		{"hpke public key", 1665, 2},
		{"two frames exactly", 2 * pqcChunkPayload, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := make([]byte, tc.size)
			if _, err := rand.Read(msg); err != nil {
				t.Fatalf("rand: %v", err)
			}
			frames := mustSplit(t, 42, pqcKindPubKey, msg)
			if len(frames) != tc.wantFrames {
				t.Fatalf("got %d frames, want %d", len(frames), tc.wantFrames)
			}

			r := newPQCReassembler()
			r.SetRound(42)
			var got []byte
			var done bool
			for _, raw := range frames {
				f, err := decodeFrame(raw)
				if err != nil {
					t.Fatalf("decodeFrame: %v", err)
				}
				got, done = r.Add(f)
			}
			if !done {
				t.Fatal("message never completed")
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("reassembled %d bytes, want %d, content differs", len(got), len(msg))
			}
		})
	}
}

func TestPQCFrameRejectsMalformed(t *testing.T) {
	good := mustSplit(t, 1, pqcKindEnc, make([]byte, 1665))[0]

	cases := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"truncated header", good[:pqcFrameHeaderLen-1]},
		{"total zero", []byte{0, 0, 0, 1, 1, 0, 0, 0}},
		{"total over max", []byte{0, 0, 0, 1, 1, 0, pqcMaxFrames + 1, 0}},
		{"seq beyond total", []byte{0, 0, 0, 1, 1, 5, 2, 0}},
		{"data over chunk size", append([]byte{0, 0, 0, 1, 1, 0, 1, 0}, make([]byte, pqcChunkPayload+1)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeFrame(tc.in); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestPQCReassemblyOutOfOrderAndDuplicate(t *testing.T) {
	msg := make([]byte, 1665)
	if _, err := rand.Read(msg); err != nil {
		t.Fatalf("rand: %v", err)
	}
	frames := mustSplit(t, 7, pqcKindPubKey, msg)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}

	r := newPQCReassembler()
	r.SetRound(7)

	add := func(raw []byte) ([]byte, bool) {
		f, err := decodeFrame(raw)
		if err != nil {
			t.Fatalf("decodeFrame: %v", err)
		}
		return r.Add(f)
	}

	// Reversed, with the second frame delivered twice.
	if _, done := add(frames[1]); done {
		t.Fatal("completed after one frame")
	}
	if _, done := add(frames[1]); done {
		t.Fatal("a duplicate frame completed the message")
	}
	got, done := add(frames[0])
	if !done {
		t.Fatal("message did not complete after both frames arrived")
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("out-of-order reassembly produced the wrong bytes")
	}
}

func TestPQCReassemblyDropsOtherRounds(t *testing.T) {
	msg := make([]byte, 1665)
	frames := mustSplit(t, 9, pqcKindEnc, msg)

	r := newPQCReassembler()
	r.SetRound(10) // a different active round

	for _, raw := range frames {
		f, err := decodeFrame(raw)
		if err != nil {
			t.Fatalf("decodeFrame: %v", err)
		}
		if _, done := r.Add(f); done {
			t.Fatal("a frame from an inactive round was accepted")
		}
	}

	// Before any round is active, everything is dropped.
	fresh := newPQCReassembler()
	f, err := decodeFrame(frames[0])
	if err != nil {
		t.Fatalf("decodeFrame: %v", err)
	}
	if _, done := fresh.Add(f); done {
		t.Fatal("a frame was accepted before a round was started")
	}
}

func TestPQCSplitRejectsOversizedMessage(t *testing.T) {
	if _, err := splitMessage(1, pqcKindPubKey, make([]byte, pqcMaxFrames*pqcChunkPayload+1)); err == nil {
		t.Fatal("expected an error for a message needing more than pqcMaxFrames frames")
	}
}

// FuzzDecodeFrame is audit programme target A3: arbitrary bytes into the frame
// decoder must never panic.
func FuzzDecodeFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 1, 0, 1, 0})
	if seed, err := splitMessage(3, pqcKindPubKey, make([]byte, 1665)); err == nil {
		for _, s := range seed {
			f.Add(s)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := decodeFrame(data)
		if err != nil {
			return
		}
		if frame.total == 0 || frame.total > pqcMaxFrames || frame.seq >= frame.total {
			t.Fatalf("decodeFrame accepted an invalid frame: seq=%d total=%d", frame.seq, frame.total)
		}
		r := newPQCReassembler()
		r.SetRound(frame.round)
		r.Add(frame) // must not panic
	})
}

// --- HPKE core --------------------------------------------------------------

// TestPQCAgreementDerivesIdenticalKeys runs both roles in one process.
func TestPQCAgreementDerivesIdenticalKeys(t *testing.T) {
	const round = 12345

	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	if len(pub) != 1665 {
		t.Fatalf("public key is %d bytes, expected 1665 for MLKEM1024-P384", len(pub))
	}

	enc, keyResponder, err := pqcResponderRespond(pub, round)
	if err != nil {
		t.Fatalf("responderRespond: %v", err)
	}
	if len(enc) != 1665 {
		t.Fatalf("encapsulation is %d bytes, expected 1665", len(enc))
	}

	keyInitiator, err := pqcInitiatorFinish(priv, enc, round)
	if err != nil {
		t.Fatalf("initiatorFinish: %v", err)
	}

	if len(keyInitiator) != pqcKeyLen {
		t.Fatalf("key is %d bytes, want %d", len(keyInitiator), pqcKeyLen)
	}
	if !bytes.Equal(keyInitiator, keyResponder) {
		t.Fatal("initiator and responder derived different keys")
	}
}

// TestPQCRoundBindingSeparatesKeys asserts that a delayed message from another
// round cannot produce usable material.
func TestPQCRoundBindingSeparatesKeys(t *testing.T) {
	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	enc, keyResponder, err := pqcResponderRespond(pub, 100)
	if err != nil {
		t.Fatalf("responderRespond: %v", err)
	}

	// The initiator believes it is a different round.
	keyInitiator, err := pqcInitiatorFinish(priv, enc, 101)
	if err != nil {
		return // rejecting outright is also acceptable
	}
	if bytes.Equal(keyInitiator, keyResponder) {
		t.Fatal("a round mismatch produced the same key; info is not bound to the round")
	}
	// And the mismatch must be caught before publication.
	tag, err := pqcConfirmTag(keyResponder, 100)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if pqcVerifyConfirm(keyInitiator, 101, tag) {
		t.Fatal("confirmation accepted a cross-round key")
	}
}

func TestPQCRejectsMalformedPeerMaterial(t *testing.T) {
	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}

	t.Run("malformed public key", func(t *testing.T) {
		for _, bad := range [][]byte{nil, {}, make([]byte, 10), make([]byte, 1664), make([]byte, 1666)} {
			if _, _, err := pqcResponderRespond(bad, 1); err == nil {
				t.Fatalf("accepted a %d-byte public key", len(bad))
			}
		}
	})

	t.Run("truncated encapsulation", func(t *testing.T) {
		enc, _, err := pqcResponderRespond(pub, 1)
		if err != nil {
			t.Fatalf("responderRespond: %v", err)
		}
		if _, err := pqcInitiatorFinish(priv, enc[:len(enc)-1], 1); err == nil {
			t.Fatal("accepted a truncated encapsulation")
		}
	})
}

// TestPQCSealIsRefused asserts the ExportOnly instantiation cannot be misused
// for message encryption.
func TestPQCSealIsRefused(t *testing.T) {
	kem, kdf, aead := pqcSuite()
	priv, err := kem.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, sender, err := hpke.NewSender(priv.PublicKey(), kdf, aead, pqcRoundInfo(1))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	if _, err := sender.Seal(nil, []byte("payload")); err == nil {
		t.Fatal("Seal succeeded under ExportOnly; the suite is not export-only")
	}
}

// TestPQCConfirmationCatchesImplicitRejection is the load-bearing test for
// ML-KEM implicit rejection: a corrupted encapsulation must produce no error
// from decapsulation, and must be caught by the confirmation exchange instead.
func TestPQCConfirmationCatchesImplicitRejection(t *testing.T) {
	const round = 77

	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	enc, keyResponder, err := pqcResponderRespond(pub, round)
	if err != nil {
		t.Fatalf("responderRespond: %v", err)
	}

	corrupted := bytes.Clone(enc)
	corrupted[len(corrupted)/2] ^= 0xff

	keyInitiator, err := pqcInitiatorFinish(priv, corrupted, round)
	if err != nil {
		t.Skipf("decapsulation rejected the corrupted enc outright (%v); implicit rejection did not apply here", err)
	}

	// This is the whole point: no error, but the keys differ.
	if bytes.Equal(keyInitiator, keyResponder) {
		t.Fatal("corrupting the encapsulation did not change the derived key")
	}

	responderTag, err := pqcConfirmTag(keyResponder, round)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if pqcVerifyConfirm(keyInitiator, round, responderTag) {
		t.Fatal("confirmation accepted divergent keys; the PSK would have been poisoned silently")
	}
}

func TestPQCConfirmTagProperties(t *testing.T) {
	key := make([]byte, pqcKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	tag, err := pqcConfirmTag(key, 5)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if len(tag) != pqcConfirmTagLen {
		t.Fatalf("tag is %d bytes, want %d", len(tag), pqcConfirmTagLen)
	}
	if bytes.Contains(tag, key[:8]) {
		t.Fatal("the tag leaks key material")
	}
	if !pqcVerifyConfirm(key, 5, tag) {
		t.Fatal("a matching key and round failed verification")
	}
	if pqcVerifyConfirm(key, 6, tag) {
		t.Fatal("a tag from another round verified; tags are not round-bound")
	}
	other := make([]byte, pqcKeyLen)
	if pqcVerifyConfirm(other, 5, tag) {
		t.Fatal("a different key verified against the tag")
	}
	if pqcVerifyConfirm(key, 5, tag[:len(tag)-1]) {
		t.Fatal("a truncated tag verified")
	}
}
