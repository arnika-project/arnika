package repositories

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"sync"
	"testing"
	"time"
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

// --- transport and scheduler ------------------------------------------------

// pqcPipe wires two repositories back to back over in-memory channels, with an
// optional frame loss rate, so a full round can run without any network.
type pqcPipe struct {
	initiator, responder *PQCHPKERepository
}

func newPQCPipe(t *testing.T, lossPercent int, seed int64, timeout time.Duration) *pqcPipe {
	t.Helper()
	rng := mrand.New(mrand.NewSource(seed))
	var mu sync.Mutex
	drop := func(bool, pqcFrame) bool {
		mu.Lock()
		defer mu.Unlock()
		return rng.Intn(100) < lossPercent
	}
	return newPQCPipeDropping(t, drop, 10*time.Second, timeout)
}

// newPQCPipeDropping wires two repositories back to back and consults drop for
// every frame, so a test can lose exactly one kind in one direction.
// fromInitiator reports which side sent it.
func newPQCPipeDropping(t *testing.T, drop func(fromInitiator bool, f pqcFrame) bool,
	interval, timeout time.Duration) *pqcPipe {
	t.Helper()

	toInitiator := make(chan []byte, 64)
	toResponder := make(chan []byte, 64)

	path := func(dst chan []byte, fromInitiator bool) func([]byte) error {
		return func(frame []byte) error {
			f, err := decodeFrame(frame)
			if err != nil {
				t.Errorf("a sent frame does not decode: %v", err)
				return nil
			}
			if drop != nil && drop(fromInitiator, f) {
				return nil // silently lost in transit, as a datagram would be
			}
			cp := make([]byte, len(frame))
			copy(cp, frame)
			select {
			case dst <- cp:
			default: // receiver's queue full: dropped, exactly as udpServer does
			}
			return nil
		}
	}

	initiator, err := NewPQCHPKERepository(toInitiator, path(toResponder, true),
		func(uint32) bool { return true }, interval, timeout, time.Minute)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}
	responder, err := NewPQCHPKERepository(toResponder, path(toInitiator, false),
		func(uint32) bool { return false }, interval, timeout, time.Minute)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}
	return &pqcPipe{initiator: initiator, responder: responder}
}

// run executes one round on both ends concurrently and returns their errors.
func (p *pqcPipe) run(t *testing.T, round uint32, wall time.Duration) (errInit, errResp error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wall)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errInit = p.initiator.RunRound(ctx, round) }()
	go func() { defer wg.Done(); errResp = p.responder.RunRound(ctx, round) }()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(wall + 5*time.Second):
		t.Fatal("round hung: RunRound did not return within the wall clock budget")
	}
	return errInit, errResp
}

func TestPQCRoundAgreesOverCleanPipe(t *testing.T) {
	p := newPQCPipe(t, 0, 1, 3*time.Second)

	errInit, errResp := p.run(t, 4242, 10*time.Second)
	if errInit != nil {
		t.Fatalf("initiator: %v", errInit)
	}
	if errResp != nil {
		t.Fatalf("responder: %v", errResp)
	}

	keyA, err := p.initiator.GetNewKey()
	if err != nil {
		t.Fatalf("initiator GetNewKey: %v", err)
	}
	keyB, err := p.responder.GetNewKey()
	if err != nil {
		t.Fatalf("responder GetNewKey: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("peers published different keys")
	}
	if len(keyA) != pqcKeyLen {
		t.Fatalf("key is %d bytes, want %d", len(keyA), pqcKeyLen)
	}
}

// TestPQCRoundUnderLoss asserts the property that matters operationally: with
// frames going missing, a round either completes with matching keys or fails
// cleanly. It must never hang, and it must never publish divergent keys.
func TestPQCRoundUnderLoss(t *testing.T) {
	for _, loss := range []int{1, 5, 20} {
		t.Run(fmt.Sprintf("%d%%_loss", loss), func(t *testing.T) {
			completed := 0
			const rounds = 5
			for i := range rounds {
				p := newPQCPipe(t, loss, int64(loss*100+i), 2*time.Second)
				errInit, errResp := p.run(t, uint32(1000+i), 8*time.Second)

				keyA, errA := p.initiator.GetNewKey()
				keyB, errB := p.responder.GetNewKey()

				switch {
				case errInit == nil && errResp == nil:
					if errA != nil || errB != nil {
						t.Fatalf("round reported success but a key is missing: %v / %v", errA, errB)
					}
					if !bytes.Equal(keyA, keyB) {
						t.Fatal("both ends succeeded with different keys; confirmation did not hold")
					}
					completed++
				default:
					// A failed round must publish nothing on the failing side.
					if errInit != nil && errA == nil {
						t.Fatal("initiator failed the round but still published a key")
					}
					if errResp != nil && errB == nil {
						t.Fatal("responder failed the round but still published a key")
					}
				}
			}
			t.Logf("%d%% loss: %d/%d rounds completed", loss, completed, rounds)
			if loss <= 5 && completed == 0 {
				t.Fatalf("no round completed at %d%% loss; retries are not recovering", loss)
			}
		})
	}
}

func TestPQCGetNewKeyBeforeAnyRound(t *testing.T) {
	p := newPQCPipe(t, 0, 2, time.Second)
	if _, err := p.initiator.GetNewKey(); err == nil {
		t.Fatal("expected an error before the first round has agreed a key")
	}
}

func TestPQCGetNewKeyStale(t *testing.T) {
	inbound := make(chan []byte, 1)
	r, err := NewPQCHPKERepository(inbound, func([]byte) error { return nil },
		func(uint32) bool { return true }, time.Second, 100*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}

	key := make([]byte, pqcKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := r.publish(key); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := r.GetNewKey(); err != nil {
		t.Fatalf("a fresh key must be returned: %v", err)
	}

	time.Sleep(80 * time.Millisecond) // now older than maxAge
	if _, err := r.GetNewKey(); err == nil {
		t.Fatal("expected a staleness error once the key exceeds maxAge")
	}
}

func TestPQCPublishRejectsWrongLength(t *testing.T) {
	inbound := make(chan []byte, 1)
	r, err := NewPQCHPKERepository(inbound, func([]byte) error { return nil },
		func(uint32) bool { return true }, time.Second, 100*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}
	for _, n := range []int{0, 16, 31, 33, 64} {
		if err := r.publish(make([]byte, n)); err == nil {
			t.Fatalf("publish accepted a %d-byte key", n)
		}
	}
}

// TestPQCPublishDoesNotCorruptConcurrentGetNewKey pins the fix for a data race
// between the round goroutine and the rekeying goroutine.
//
// publish() zeroes the buffer it supersedes, and GetNewKey() copies out of the
// buffer it has taken a reference to. While the register was an atomic.Pointer
// the two were ordered on the pointer but not on the bytes behind it, so a
// publish landing between GetNewKey's load and its copy zeroed the array being
// read and returned 32 zero bytes - which nothing downstream rejects, and which
// kdf.DeriveKey folds straight into the WireGuard PSK.
//
// The defaults put both callers on the same clock boundary (PQC_ROUND_INTERVAL
// defaults to INTERVAL), so this is not a far-fetched interleaving. Before the
// fix this test failed within a few hundred iterations; -race alone does not
// catch it, because the atomic Swap/Load supplied a partial happens-before edge.
func TestPQCPublishDoesNotCorruptConcurrentGetNewKey(t *testing.T) {
	r, err := NewPQCHPKERepository(make(chan []byte, 1), func([]byte) error { return nil },
		func(uint32) bool { return true }, time.Minute, time.Second, time.Hour)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}

	want := make([]byte, pqcKeyLen)
	if _, err := rand.Read(want); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := r.publish(want); err != nil {
		t.Fatalf("seed publish: %v", err)
	}

	const iterations = 20000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range iterations {
			if err := r.publish(want); err != nil {
				t.Errorf("publish: %v", err)
				return
			}
		}
	}()
	corrupted := 0
	go func() {
		defer wg.Done()
		for range iterations {
			got, err := r.GetNewKey()
			if err != nil {
				t.Errorf("GetNewKey: %v", err)
				return
			}
			if !bytes.Equal(got, want) {
				corrupted++
			}
		}
	}()
	wg.Wait()

	if corrupted != 0 {
		t.Fatalf("GetNewKey returned a corrupted key %d times out of %d: publish zeroed a buffer that was still being read",
			corrupted, iterations)
	}
}

// TestPQCConcurrentRoundRejected asserts that only one round is ever active.
func TestPQCConcurrentRoundRejected(t *testing.T) {
	inbound := make(chan []byte, 1)
	r, err := NewPQCHPKERepository(inbound, func([]byte) error { return nil },
		func(uint32) bool { return false }, // responder: blocks waiting for a public key
		time.Second, 700*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}

	ctx := context.Background()
	started := make(chan struct{})
	go func() {
		close(started)
		_ = r.RunRound(ctx, 1)
	}()
	<-started
	time.Sleep(100 * time.Millisecond) // let the first round take the slot

	if err := r.RunRound(ctx, 2); err == nil {
		t.Fatal("a second concurrent round was accepted; only one may be active")
	}
}

func TestPQCConstructorValidation(t *testing.T) {
	inbound := make(chan []byte, 1)
	send := func([]byte) error { return nil }
	role := func(uint32) bool { return true }

	cases := []struct {
		name                      string
		inbound                   <-chan []byte
		send                      func([]byte) error
		role                      func(uint32) bool
		interval, timeout, maxAge time.Duration
	}{
		{"nil inbound", nil, send, role, time.Second, time.Millisecond, time.Minute},
		{"nil send", inbound, nil, role, time.Second, time.Millisecond, time.Minute},
		{"nil role", inbound, send, nil, time.Second, time.Millisecond, time.Minute},
		{"zero interval", inbound, send, role, 0, time.Millisecond, time.Minute},
		{"timeout equals interval", inbound, send, role, time.Second, time.Second, time.Minute},
		{"timeout exceeds interval", inbound, send, role, time.Second, 2 * time.Second, time.Minute},
		{"zero maxAge", inbound, send, role, time.Second, time.Millisecond, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPQCHPKERepository(tc.inbound, tc.send, tc.role, tc.interval, tc.timeout, tc.maxAge); err == nil {
				t.Fatal("expected a constructor error")
			}
		})
	}
}

func TestPQCRoundIndexIsClockDerived(t *testing.T) {
	interval := 10 * time.Second
	base := time.Unix(1_000_000_000, 0)

	if got, want := pqcRoundIndex(base, interval), uint32(100_000_000); got != want {
		t.Fatalf("round index = %d, want %d", got, want)
	}
	// Both peers must land on the same index anywhere inside the interval.
	if pqcRoundIndex(base.Add(9*time.Second), interval) != pqcRoundIndex(base, interval) {
		t.Fatal("the index changed inside a single interval")
	}
	if pqcRoundIndex(base.Add(10*time.Second), interval) == pqcRoundIndex(base, interval) {
		t.Fatal("the index did not advance across an interval boundary")
	}
	// A sub-second interval must not divide by zero.
	_ = pqcRoundIndex(base, time.Millisecond)
}

// TestPQCLostConfirmDoesNotPublishAlone is the regression test for one-sided
// publication. The responder used to publish as soon as it had verified the
// initiator's tag, so losing its own confirm left it holding a key the
// initiator did not have - and the next rekey then derived two different PSKs
// with nothing logged to explain it.
//
// Both tags are acknowledged now, so losing one must leave the round failed on
// both sides rather than committed on one.
func TestPQCLostConfirmDoesNotPublishAlone(t *testing.T) {
	// Lose every confirm frame travelling responder -> initiator.
	p := newPQCPipeDropping(t, func(fromInitiator bool, f pqcFrame) bool {
		return !fromInitiator && f.kind == pqcKindConfirm
	}, 10*time.Second, 1500*time.Millisecond)

	errInit, errResp := p.run(t, 500, 10*time.Second)

	_, errKeyInit := p.initiator.GetNewKey()
	_, errKeyResp := p.responder.GetNewKey()
	publishedInit := errKeyInit == nil
	publishedResp := errKeyResp == nil

	if publishedInit != publishedResp {
		t.Fatalf("one-sided publish: initiator published=%v, responder published=%v (round errors: %v / %v)",
			publishedInit, publishedResp, errInit, errResp)
	}
	if publishedInit {
		t.Fatal("a round whose confirmation never arrived must not publish on either side")
	}
}

// TestPQCLostConfirmAckStillConverges asserts the acknowledgement itself is
// retried: losing the first ack of the responder's tag must not fail the round.
func TestPQCLostConfirmAckStillConverges(t *testing.T) {
	var mu sync.Mutex
	seen := 0
	p := newPQCPipeDropping(t, func(fromInitiator bool, f pqcFrame) bool {
		if fromInitiator && f.kind == pqcKindAck && len(f.data) == 1 && pqcKind(f.data[0]) == pqcKindConfirm {
			mu.Lock()
			defer mu.Unlock()
			seen++
			return seen == 1 // lose only the first one
		}
		return false
	}, 10*time.Second, 3*time.Second)

	errInit, errResp := p.run(t, 501, 12*time.Second)
	if errInit != nil || errResp != nil {
		t.Fatalf("round should survive a single lost confirm-ack: %v / %v", errInit, errResp)
	}

	keyA, err := p.initiator.GetNewKey()
	if err != nil {
		t.Fatalf("initiator GetNewKey: %v", err)
	}
	keyB, err := p.responder.GetNewKey()
	if err != nil {
		t.Fatalf("responder GetNewKey: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("peers published different keys")
	}
}

// TestPQCRunAgreesAKeyBeforeTheFirstBoundary asserts the startup round: with a
// five-minute round interval, a key that appears within seconds can only have
// come from the immediate round, not from waiting for a boundary.
func TestPQCRunAgreesAKeyBeforeTheFirstBoundary(t *testing.T) {
	const interval = 5 * time.Minute
	p := newPQCPipeDropping(t, nil, interval, 2*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.initiator.Run(ctx)
	go p.responder.Run(ctx)

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		keyA, errA := p.initiator.GetNewKey()
		keyB, errB := p.responder.GetNewKey()
		if errA == nil && errB == nil {
			if !bytes.Equal(keyA, keyB) {
				t.Fatal("the startup round published different keys on the two peers")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no key within 6s at a %s interval: the startup round did not run", interval)
}

// TestPQCNextRoundServesAFutureBoundary pins the scheduling decision. Both
// peers derive it from the clock alone, so it must never name a boundary that
// has passed, never sleep into the past, and depend on nothing finer than which
// interval the caller is in.
func TestPQCNextRoundServesAFutureBoundary(t *testing.T) {
	const interval = 5 * time.Second
	const timeout = 1250 * time.Millisecond

	// Walk a whole interval in 10 ms steps, crossing the ideal start instant.
	base := time.Unix(1788781835, 0) // a boundary, from the CI run
	for off := 0; off < 5000; off += 10 {
		now := base.Add(time.Duration(off) * time.Millisecond)
		round, wake := pqcNextRound(now, interval, timeout)

		boundary := time.Unix(int64(round)*5, 0)
		if !boundary.After(now) {
			t.Fatalf("at +%dms round %d serves boundary %s, which is not in the future", off, round, boundary)
		}
		if wake.Before(now) {
			t.Fatalf("at +%dms the wake %s is in the past", off, wake)
		}
		if wake.After(boundary) {
			t.Fatalf("at +%dms the wake %s is after the boundary %s", off, wake, boundary)
		}
		// Every instant in one interval must map to the same round, so two peers
		// that are merely milliseconds apart cannot disagree.
		if want := uint32(base.Unix()/5 + 1); round != want {
			t.Fatalf("at +%dms round=%d, want %d: the choice depends on more than the interval", off, round, want)
		}
	}
}

// TestPQCNextRoundAgreesAcrossPeers asserts two peers whose clocks differ by
// less than the read gap still target the same round.
func TestPQCNextRoundAgreesAcrossPeers(t *testing.T) {
	const interval = 5 * time.Second
	const timeout = 1250 * time.Millisecond
	base := time.Unix(1788781838, 688_000_000) // node-A's start, from the CI run

	roundA, _ := pqcNextRound(base, interval, timeout)
	roundB, _ := pqcNextRound(base.Add(62*time.Millisecond), interval, timeout) // node-B, 62 ms later
	if roundA != roundB {
		t.Fatalf("peers 62ms apart targeted different rounds: %d vs %d", roundA, roundB)
	}
}

// TestPQCRoundSurvivesTransientSendFailure reproduces the startup case from CI:
// the peer's listener was not bound yet, so the first writes failed with ICMP
// port-unreachable and the whole round was thrown away. A failed write must
// cost a retry instead.
func TestPQCRoundSurvivesTransientSendFailure(t *testing.T) {
	toInitiator := make(chan []byte, 64)
	toResponder := make(chan []byte, 64)

	deliver := func(dst chan []byte) func([]byte) error {
		return func(frame []byte) error {
			cp := make([]byte, len(frame))
			copy(cp, frame)
			select {
			case dst <- cp:
			default:
			}
			return nil
		}
	}

	var mu sync.Mutex
	remaining := 2 // both frames of the initiator's first message fail
	initiatorSend := func(frame []byte) error {
		mu.Lock()
		if remaining > 0 {
			remaining--
			mu.Unlock()
			return fmt.Errorf("write udp 10.0.0.1:46886->10.0.0.2:9998: write: connection refused")
		}
		mu.Unlock()
		return deliver(toResponder)(frame)
	}

	const interval = 10 * time.Second
	initiator, err := NewPQCHPKERepository(toInitiator, initiatorSend,
		func(uint32) bool { return true }, interval, 3*time.Second, time.Minute)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}
	responder, err := NewPQCHPKERepository(toResponder, deliver(toInitiator),
		func(uint32) bool { return false }, interval, 3*time.Second, time.Minute)
	if err != nil {
		t.Fatalf("NewPQCHPKERepository: %v", err)
	}

	p := &pqcPipe{initiator: initiator, responder: responder}
	errInit, errResp := p.run(t, 357756367, 15*time.Second)
	if errInit != nil || errResp != nil {
		t.Fatalf("a round must survive two failed writes: %v / %v", errInit, errResp)
	}

	keyA, err := p.initiator.GetNewKey()
	if err != nil {
		t.Fatalf("initiator GetNewKey: %v", err)
	}
	keyB, err := p.responder.GetNewKey()
	if err != nil {
		t.Fatalf("responder GetNewKey: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("peers published different keys")
	}
}
