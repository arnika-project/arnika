package pqchpke

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"fmt"
	"log/slog"
	mrand "math/rand"
	"os"
	"sync"
	"testing"
	"time"
)

func mustSplit(t *testing.T, round uint32, kind pqcKind, msg []byte) [][]byte {
	t.Helper()
	frames, err := splitMessage(round, kind, msg)
	if err != nil {
		t.Fatalf("splitMessage: %v", err)
	}
	return frames
}

func currentRound(interval time.Duration) uint32 {
	return pqcRoundIndex(time.Now(), interval)
}

func mustDecode(t *testing.T, raw []byte) pqcFrame {
	t.Helper()
	f, err := decodeFrame(raw)
	if err != nil {
		t.Fatalf("decodeFrame: %v", err)
	}
	return f
}

func TestPQCFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		size       int
		wantFrames int
	}{
		{"empty", 0, 1},
		{"one byte", 1, 1},
		{"confirmation tag", pqcConfirmTagLen, 1},
		{"one frame exactly", pqcChunkPayload, 1},
		{"one byte over the boundary", pqcChunkPayload + 1, 2},
		{"hpke public key", 1665, 2},
		{"encapsulation plus tag", 1665 + pqcConfirmTagLen, 2},
		{"two frames exactly", pqcMaxFrames * pqcChunkPayload, 2},
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

			var j pqcJoiner
			var got []byte
			var done bool
			for _, raw := range frames {
				got, done = j.add(mustDecode(t, raw))
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

func TestPQCJoinerOutOfOrderAndDuplicate(t *testing.T) {
	msg := make([]byte, 1665)
	if _, err := rand.Read(msg); err != nil {
		t.Fatalf("rand: %v", err)
	}
	frames := mustSplit(t, 7, pqcKindPubKey, msg)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}

	var j pqcJoiner

	if _, done := j.add(mustDecode(t, frames[1])); done {
		t.Fatal("completed after one frame")
	}
	if _, done := j.add(mustDecode(t, frames[1])); done {
		t.Fatal("a duplicate frame completed the message")
	}
	got, done := j.add(mustDecode(t, frames[0]))
	if !done {
		t.Fatal("message did not complete after both frames arrived")
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("out-of-order reassembly produced the wrong bytes")
	}
}

func TestPQCJoinerRestartsOnOtherRoundOrKind(t *testing.T) {
	a := mustSplit(t, 7, pqcKindPubKey, make([]byte, 1665))
	cases := []struct {
		name  string
		other []byte
	}{
		{"other round", mustSplit(t, 8, pqcKindPubKey, make([]byte, 1665))[1]},
		{"other kind", mustSplit(t, 7, pqcKindEnc, make([]byte, 1665))[1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var j pqcJoiner
			if _, done := j.add(mustDecode(t, a[0])); done {
				t.Fatal("completed after one frame")
			}
			if _, done := j.add(mustDecode(t, tc.other)); done {
				t.Fatal("a frame from another message completed the first one")
			}
			if _, done := j.add(mustDecode(t, a[1])); done {
				t.Fatal("the restarted joiner completed from a stale half")
			}
		})
	}
}

func TestPQCSplitRejectsOversizedMessage(t *testing.T) {
	if _, err := splitMessage(1, pqcKindPubKey, make([]byte, pqcMaxFrames*pqcChunkPayload+1)); err == nil {
		t.Fatal("expected an error for a message needing more than pqcMaxFrames frames")
	}
}

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
		var j pqcJoiner
		j.add(frame)
		j.add(frame)
	})
}

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

func TestPQCEncMessageFitsTheFrameBudget(t *testing.T) {
	_, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	enc, _, err := pqcResponderRespond(pub, 1)
	if err != nil {
		t.Fatalf("responderRespond: %v", err)
	}
	largest := len(enc) + pqcConfirmTagLen
	if largest > pqcMaxFrames*pqcChunkPayload {
		t.Fatalf("the largest message is %d bytes but only %d fit in %d frames; raise pqcMaxFrames",
			largest, pqcMaxFrames*pqcChunkPayload, pqcMaxFrames)
	}
}

func TestPQCRoundBindingSeparatesKeys(t *testing.T) {
	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	enc, keyResponder, err := pqcResponderRespond(pub, 100)
	if err != nil {
		t.Fatalf("responderRespond: %v", err)
	}

	keyInitiator, err := pqcInitiatorFinish(priv, enc, 101)
	if err != nil {
		return
	}
	if bytes.Equal(keyInitiator, keyResponder) {
		t.Fatal("a round mismatch produced the same key; info is not bound to the round")
	}
	tag, err := pqcConfirmTag(keyResponder, 100, pqcRoleResponder)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if pqcVerifyConfirm(keyInitiator, 101, pqcRoleResponder, tag) {
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

	if bytes.Equal(keyInitiator, keyResponder) {
		t.Fatal("corrupting the encapsulation did not change the derived key")
	}

	responderTag, err := pqcConfirmTag(keyResponder, round, pqcRoleResponder)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if pqcVerifyConfirm(keyInitiator, round, pqcRoleResponder, responderTag) {
		t.Fatal("confirmation accepted divergent keys; the PSK would have been poisoned silently")
	}
	initiatorTag, err := pqcConfirmTag(keyInitiator, round, pqcRoleInitiator)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if pqcVerifyConfirm(keyResponder, round, pqcRoleInitiator, initiatorTag) {
		t.Fatal("the responder's check accepted a divergent key")
	}
}

func TestPQCConfirmTagProperties(t *testing.T) {
	key := make([]byte, pqcKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	tag, err := pqcConfirmTag(key, 5, pqcRoleInitiator)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if len(tag) != pqcConfirmTagLen {
		t.Fatalf("tag is %d bytes, want %d", len(tag), pqcConfirmTagLen)
	}
	if bytes.Contains(tag, key[:8]) {
		t.Fatal("the tag leaks key material")
	}
	if !pqcVerifyConfirm(key, 5, pqcRoleInitiator, tag) {
		t.Fatal("a matching key, round and role failed verification")
	}
	if pqcVerifyConfirm(key, 6, pqcRoleInitiator, tag) {
		t.Fatal("a tag from another round verified; tags are not round-bound")
	}
	other := make([]byte, pqcKeyLen)
	if pqcVerifyConfirm(other, 5, pqcRoleInitiator, tag) {
		t.Fatal("a different key verified against the tag")
	}
	if pqcVerifyConfirm(key, 5, pqcRoleInitiator, tag[:len(tag)-1]) {
		t.Fatal("a truncated tag verified")
	}
}

func TestPQCConfirmTagsAreRoleSeparated(t *testing.T) {
	key := make([]byte, pqcKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	tagI, err := pqcConfirmTag(key, 5, pqcRoleInitiator)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	tagR, err := pqcConfirmTag(key, 5, pqcRoleResponder)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	if bytes.Equal(tagI, tagR) {
		t.Fatal("both roles compute the same tag; echoing it back would verify")
	}
	if pqcVerifyConfirm(key, 5, pqcRoleResponder, tagI) {
		t.Fatal("the initiator's tag verified as the responder's")
	}
	if pqcVerifyConfirm(key, 5, pqcRoleInitiator, tagR) {
		t.Fatal("the responder's tag verified as the initiator's")
	}
}

func mustNotInitiate() (func([]byte) error, func(time.Time) ([]byte, error)) {
	return func([]byte) error { return fmt.Errorf("send called on a responder-only repository") },
		func(time.Time) ([]byte, error) {
			return nil, fmt.Errorf("recv called on a responder-only repository")
		}
}

func newPQCTestRepo(t *testing.T, interval, timeout, maxAge time.Duration) *Repository {
	t.Helper()
	send, recv := mustNotInitiate()
	r, err := NewRepository(slog.New(slog.DiscardHandler), send, recv,
		func(uint32) bool { return false }, interval, timeout, maxAge)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	return r
}

type pqcPipe struct {
	initiator, responder *Repository

	mu      sync.Mutex
	sent    []pqcFrame
	respErr []error
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

func newPQCPipeDropping(t *testing.T, drop func(fromInitiator bool, f pqcFrame) bool,
	interval, timeout time.Duration) *pqcPipe {
	t.Helper()
	return newPQCPipeWith(t, drop, nil, interval, timeout)
}

func newPQCPipeFailingSends(t *testing.T, failSend func() bool,
	interval, timeout time.Duration) *pqcPipe {
	t.Helper()
	return newPQCPipeWith(t, nil, failSend, interval, timeout)
}

func newPQCPipeWith(t *testing.T, drop func(fromInitiator bool, f pqcFrame) bool,
	failSend func() bool, interval, timeout time.Duration) *pqcPipe {
	t.Helper()

	p := &pqcPipe{}
	toInitiator := make(chan []byte, 64)
	toResponder := make(chan []byte, 64)

	deliver := func(dst chan []byte, fromInitiator bool) func([]byte) error {
		return func(frame []byte) error {
			if fromInitiator && failSend != nil && failSend() {
				return fmt.Errorf("write udp 10.0.0.1:46886->10.0.0.2:9998: write: connection refused")
			}
			f, err := decodeFrame(frame)
			if err != nil {
				return fmt.Errorf("a sent frame does not decode: %w", err)
			}
			p.mu.Lock()
			p.sent = append(p.sent, f)
			p.mu.Unlock()
			if drop != nil && drop(fromInitiator, f) {
				return nil
			}
			cp := bytes.Clone(frame)
			select {
			case dst <- cp:
			default:
			}
			return nil
		}
	}

	recv := func(src chan []byte) func(time.Time) ([]byte, error) {
		return func(deadline time.Time) ([]byte, error) {
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()
			select {
			case frame := <-src:
				return frame, nil
			case <-timer.C:
				return nil, os.ErrDeadlineExceeded
			}
		}
	}

	initiator, err := NewRepository(slog.New(slog.DiscardHandler),
		deliver(toResponder, true), recv(toInitiator),
		func(uint32) bool { return true }, interval, timeout, 2*interval)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	send, recvUnused := mustNotInitiate()
	responder, err := NewRepository(slog.New(slog.DiscardHandler), send, recvUnused,
		func(uint32) bool { return false }, interval, timeout, 2*interval)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	p.initiator, p.responder = initiator, responder

	reply := deliver(toInitiator, false)
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case frame := <-toResponder:
				if err := responder.HandleFrame(frame, reply); err != nil {
					p.mu.Lock()
					p.respErr = append(p.respErr, err)
					p.mu.Unlock()
				}
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-stopped })

	return p
}

func (p *pqcPipe) run(t *testing.T, round uint32, wall time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wall)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- p.initiator.runRound(ctx, round) }()
	select {
	case err := <-done:
		return err
	case <-time.After(wall + 5*time.Second):
		t.Fatal("round hung: runRound did not return within the wall clock budget")
		return nil
	}
}

func (p *pqcPipe) framesSent() []pqcFrame {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]pqcFrame(nil), p.sent...)
}

func (p *pqcPipe) settle() { time.Sleep(200 * time.Millisecond) }

func waitPublished(r *Repository, wait time.Duration) ([]byte, error) {
	deadline := time.Now().Add(wait)
	for {
		key, err := r.GetNewKey()
		if err == nil {
			return key, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPQCRoundAgreesOverCleanPipe(t *testing.T) {
	p := newPQCPipe(t, 0, 1, 3*time.Second)

	if err := p.run(t, currentRound(10*time.Second), 10*time.Second); err != nil {
		t.Fatalf("initiator: %v", err)
	}

	keyA, err := p.initiator.GetNewKey()
	if err != nil {
		t.Fatalf("initiator GetNewKey: %v", err)
	}
	keyB, err := waitPublished(p.responder, 2*time.Second)
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

func TestPQCRoundIsThreeMessagesAndFiveDatagrams(t *testing.T) {
	p := newPQCPipe(t, 0, 3, 3*time.Second)
	if err := p.run(t, currentRound(10*time.Second), 10*time.Second); err != nil {
		t.Fatalf("initiator: %v", err)
	}
	if _, err := waitPublished(p.responder, 2*time.Second); err != nil {
		t.Fatalf("responder GetNewKey: %v", err)
	}

	counts := map[pqcKind]int{}
	for _, f := range p.framesSent() {
		counts[f.kind]++
	}
	want := map[pqcKind]int{pqcKindPubKey: 2, pqcKindEnc: 2, pqcKindTag: 1}
	if len(counts) != len(want) {
		t.Fatalf("a clean round sent kinds %v, want exactly %v", counts, want)
	}
	total := 0
	for kind, n := range want {
		if counts[kind] != n {
			t.Errorf("kind %d: %d frames, want %d", kind, counts[kind], n)
		}
		total += n
	}
	if got := len(p.framesSent()); got != total {
		t.Fatalf("a clean round sent %d datagrams, want %d", got, total)
	}
}

func TestPQCRoundUnderLoss(t *testing.T) {
	for _, loss := range []int{1, 5, 20} {
		t.Run(fmt.Sprintf("%d%%_loss", loss), func(t *testing.T) {
			completed := 0
			const rounds = 5
			for i := range rounds {
				p := newPQCPipe(t, loss, int64(loss*100+i), 2*time.Second)
				errInit := p.run(t, currentRound(10*time.Second), 8*time.Second)
				p.settle()

				keyA, errA := p.initiator.GetNewKey()
				keyB, errB := p.responder.GetNewKey()

				if errInit != nil {
					if errA == nil {
						t.Fatal("the initiator failed the round but still published a key")
					}
					continue
				}
				if errA != nil {
					t.Fatalf("the round succeeded but the initiator has no key: %v", errA)
				}
				completed++
				if errB == nil && !bytes.Equal(keyA, keyB) {
					t.Fatal("both ends published, with different keys; confirmation did not hold")
				}
			}
			t.Logf("%d%% loss: %d/%d rounds completed", loss, completed, rounds)
			if loss <= 5 && completed == 0 {
				t.Fatalf("no round completed at %d%% loss; retries are not recovering", loss)
			}
		})
	}
}

func TestPQCLostReplyFailsBothSides(t *testing.T) {
	p := newPQCPipeDropping(t, func(fromInitiator bool, f pqcFrame) bool {
		return !fromInitiator && f.kind == pqcKindEnc
	}, 10*time.Second, 900*time.Millisecond)

	if err := p.run(t, currentRound(10*time.Second), 10*time.Second); err == nil {
		t.Fatal("the round reported success although the reply never arrived")
	}
	p.settle()

	if _, err := p.initiator.GetNewKey(); err == nil {
		t.Fatal("the initiator published without ever seeing an encapsulation")
	}
	if _, err := p.responder.GetNewKey(); err == nil {
		t.Fatal("the responder published without the initiator's confirmation")
	}
}

func TestPQCLostTagLeavesOnlyTheInitiatorPublished(t *testing.T) {
	p := newPQCPipeDropping(t, func(fromInitiator bool, f pqcFrame) bool {
		return fromInitiator && f.kind == pqcKindTag
	}, 10*time.Second, 2*time.Second)

	if err := p.run(t, currentRound(10*time.Second), 10*time.Second); err != nil {
		t.Fatalf("the initiator's round must still succeed: %v", err)
	}
	p.settle()

	if _, err := p.initiator.GetNewKey(); err != nil {
		t.Fatalf("the initiator verified the responder's tag and must publish: %v", err)
	}
	if _, err := p.responder.GetNewKey(); err == nil {
		t.Fatal("the responder published without the initiator's confirmation")
	}
}

func TestPQCRetriedPubKeyIsAnsweredFromTheStoredReply(t *testing.T) {
	const firstReplyFrames = 2
	var mu sync.Mutex
	dropped := 0
	p := newPQCPipeDropping(t, func(fromInitiator bool, f pqcFrame) bool {
		if !fromInitiator && f.kind == pqcKindEnc {
			mu.Lock()
			defer mu.Unlock()
			if dropped < firstReplyFrames {
				dropped++
				return true
			}
		}
		return false
	}, 10*time.Second, 3*time.Second)

	if err := p.run(t, currentRound(10*time.Second), 12*time.Second); err != nil {
		t.Fatalf("the round must survive one lost reply: %v", err)
	}

	keyA, err := p.initiator.GetNewKey()
	if err != nil {
		t.Fatalf("initiator GetNewKey: %v", err)
	}
	keyB, err := waitPublished(p.responder, 2*time.Second)
	if err != nil {
		t.Fatalf("responder GetNewKey: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("peers published different keys after a retry")
	}

	var replies [][]byte
	for _, f := range p.framesSent() {
		if f.kind == pqcKindEnc && f.seq == 0 {
			replies = append(replies, f.data)
		}
	}
	if len(replies) < 2 {
		t.Fatalf("expected the reply to be sent at least twice, saw %d", len(replies))
	}
	for i, r := range replies[1:] {
		if !bytes.Equal(replies[0], r) {
			t.Fatalf("reply %d differs from the first: the responder encapsulated again", i+1)
		}
	}
}

func TestPQCResponderRejectsForgedTag(t *testing.T) {
	r := newPQCTestRepo(t, time.Second, 500*time.Millisecond, time.Minute)

	_, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}

	round := currentRound(time.Second)
	var replies [][]byte
	reply := func(frame []byte) error {
		replies = append(replies, bytes.Clone(frame))
		return nil
	}
	for _, f := range mustSplit(t, round, pqcKindPubKey, pub) {
		if err := r.HandleFrame(f, reply); err != nil {
			t.Fatalf("HandleFrame(pubKey): %v", err)
		}
	}
	if len(replies) != 2 {
		t.Fatalf("the responder sent %d reply frames, want 2", len(replies))
	}

	forged := make([]byte, pqcConfirmTagLen)
	for _, f := range mustSplit(t, round, pqcKindTag, forged) {
		if err := r.HandleFrame(f, reply); err == nil {
			t.Fatal("HandleFrame accepted a forged confirmation tag")
		}
	}
	if _, err := r.GetNewKey(); err == nil {
		t.Fatal("the responder published a key on a forged tag")
	}
}

func TestPQCResponderIgnoresUnexpectedFrames(t *testing.T) {
	r := newPQCTestRepo(t, time.Second, 500*time.Millisecond, time.Minute)
	reply := func([]byte) error { return fmt.Errorf("nothing may be answered here") }

	round := currentRound(time.Second)
	cases := []struct {
		name  string
		frame []byte
	}{
		{"tag without a round in flight", mustSplit(t, round, pqcKindTag, make([]byte, pqcConfirmTagLen))[0]},
		{"encapsulation sent to a responder", mustSplit(t, round, pqcKindEnc, make([]byte, 8))[0]},
		{"undecodable frame", []byte{0, 0}},
		{"stale round replayed off-path", mustSplit(t, round-5, pqcKindPubKey, make([]byte, 1665))[0]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := r.HandleFrame(tc.frame, reply); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := r.GetNewKey(); err == nil {
		t.Fatal("the responder published a key from unexpected frames")
	}
}

func TestPQCGetNewKeyBeforeAnyRound(t *testing.T) {
	r := newPQCTestRepo(t, time.Second, 100*time.Millisecond, time.Minute)
	if _, err := r.GetNewKey(); err == nil {
		t.Fatal("expected an error before the first round has agreed a key")
	}
}

func TestPQCGetNewKeyStale(t *testing.T) {
	r := newPQCTestRepo(t, 10*time.Millisecond, 5*time.Millisecond, 50*time.Millisecond)

	key := make([]byte, pqcKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := r.publish(1, key); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := r.GetNewKey(); err != nil {
		t.Fatalf("a fresh key must be returned: %v", err)
	}

	time.Sleep(80 * time.Millisecond)
	if _, err := r.GetNewKey(); err == nil {
		t.Fatal("expected a staleness error once the key exceeds maxAge")
	}
}

func TestPQCPublishRejectsWrongLength(t *testing.T) {
	r := newPQCTestRepo(t, time.Second, 100*time.Millisecond, time.Minute)
	for _, n := range []int{0, 16, 31, 33, 64} {
		if err := r.publish(1, make([]byte, n)); err == nil {
			t.Fatalf("publish accepted a %d-byte key", n)
		}
	}
}

func TestPQCPublishDoesNotCorruptConcurrentGetNewKey(t *testing.T) {
	r := newPQCTestRepo(t, time.Minute, time.Second, time.Hour)

	want := make([]byte, pqcKeyLen)
	if _, err := rand.Read(want); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := r.publish(1, want); err != nil {
		t.Fatalf("seed publish: %v", err)
	}

	const iterations = 20000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range iterations {
			if err := r.publish(1, want); err != nil {
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

func TestPQCConstructorValidation(t *testing.T) {
	send := func([]byte) error { return nil }
	recv := func(time.Time) ([]byte, error) { return nil, nil }
	role := func(uint32) bool { return true }

	cases := []struct {
		name                      string
		send                      func([]byte) error
		recv                      func(time.Time) ([]byte, error)
		role                      func(uint32) bool
		interval, timeout, maxAge time.Duration
	}{
		{"nil send", nil, recv, role, time.Second, time.Millisecond, time.Minute},
		{"nil recv", send, nil, role, time.Second, time.Millisecond, time.Minute},
		{"nil role", send, recv, nil, time.Second, time.Millisecond, time.Minute},
		{"zero interval", send, recv, role, 0, time.Millisecond, time.Minute},
		{"timeout equals interval", send, recv, role, time.Second, time.Second, time.Minute},
		{"timeout exceeds interval", send, recv, role, time.Second, 2 * time.Second, time.Minute},
		{"zero maxAge", send, recv, role, time.Second, time.Millisecond, 0},
		{"maxAge equals interval", send, recv, role, time.Second, time.Millisecond, time.Second},
		{"maxAge below interval", send, recv, role, time.Second, time.Millisecond, 500 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRepository(slog.New(slog.DiscardHandler), tc.send, tc.recv, tc.role,
				tc.interval, tc.timeout, tc.maxAge); err == nil {
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
	if pqcRoundIndex(base.Add(9*time.Second), interval) != pqcRoundIndex(base, interval) {
		t.Fatal("the index changed inside a single interval")
	}
	if pqcRoundIndex(base.Add(10*time.Second), interval) == pqcRoundIndex(base, interval) {
		t.Fatal("the index did not advance across an interval boundary")
	}
	t.Run("sub-second interval does not divide by zero", func(t *testing.T) {
		_ = pqcRoundIndex(base, time.Millisecond)
	})
}

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

func TestPQCNextRoundServesAFutureBoundary(t *testing.T) {
	const interval = 5 * time.Second
	const timeout = 1250 * time.Millisecond

	ciBoundary := time.Unix(1788781835, 0)
	for off := 0; off < 5000; off += 10 {
		now := ciBoundary.Add(time.Duration(off) * time.Millisecond)
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
		if want := uint32(ciBoundary.Unix()/5 + 1); round != want {
			t.Fatalf("at +%dms round=%d, want %d: the choice depends on more than the interval", off, round, want)
		}
	}
}

func TestPQCNextRoundAgreesAcrossPeers(t *testing.T) {
	const interval = 5 * time.Second
	const timeout = 1250 * time.Millisecond
	nodeAStart := time.Unix(1788781838, 688_000_000)
	nodeBStart := nodeAStart.Add(62 * time.Millisecond)

	roundA, _ := pqcNextRound(nodeAStart, interval, timeout)
	roundB, _ := pqcNextRound(nodeBStart, interval, timeout)
	if roundA != roundB {
		t.Fatalf("peers 62ms apart targeted different rounds: %d vs %d", roundA, roundB)
	}
}

func TestPQCRoundSurvivesTransientSendFailure(t *testing.T) {
	var mu sync.Mutex
	failingWrites := 2
	p := newPQCPipeFailingSends(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if failingWrites > 0 {
			failingWrites--
			return true
		}
		return false
	}, 10*time.Second, 3*time.Second)

	if err := p.run(t, currentRound(10*time.Second), 15*time.Second); err != nil {
		t.Fatalf("a round must survive two failed writes: %v", err)
	}

	keyA, err := p.initiator.GetNewKey()
	if err != nil {
		t.Fatalf("initiator GetNewKey: %v", err)
	}
	keyB, err := waitPublished(p.responder, 2*time.Second)
	if err != nil {
		t.Fatalf("responder GetNewKey: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("peers published different keys")
	}
}

func TestPQCRunServesEachRoundOnce(t *testing.T) {
	const interval = time.Second
	p := newPQCPipeDropping(t, nil, interval, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go p.initiator.Run(ctx)
	time.Sleep(2500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	rounds := map[uint32]int{}
	for _, f := range p.framesSent() {
		if f.kind == pqcKindPubKey && f.seq == 0 {
			rounds[f.round]++
		}
	}
	if len(rounds) > 4 {
		t.Fatalf("%d distinct rounds in 2.5s at a 1s interval: %v", len(rounds), rounds)
	}
	for round, n := range rounds {
		if n > 1 {
			t.Fatalf("round %d was started %d times; the scheduler repeats itself", round, n)
		}
	}
}

func TestPQCFollowingRoundNeverRepeats(t *testing.T) {
	const interval = 5 * time.Second
	const timeout = 1250 * time.Millisecond

	boundary := time.Unix(1788793930, 0)
	served := uint32(boundary.Unix() / 5)

	early := boundary.Add(-time.Microsecond)
	if got, _ := pqcNextRound(early, interval, timeout); got != served {
		t.Fatalf("precondition: the clock names %d there, want the round just served %d", got, served)
	}
	round, wake := pqcFollowingRound(early, interval, timeout, served)
	if round != served+1 {
		t.Fatalf("round = %d, want %d: the round just served was handed out again", round, served+1)
	}
	if wake.Before(early) {
		t.Fatalf("wake %s is in the past", wake)
	}
	if b := time.Unix(int64(round)*5, 0); wake.After(b) {
		t.Fatalf("wake %s is after the boundary %s", wake, b)
	}

	for _, off := range []time.Duration{0, time.Second, 3 * time.Second} {
		now := boundary.Add(off)
		gotRound, gotWake := pqcFollowingRound(now, interval, timeout, served)
		wantRound, wantWake := pqcNextRound(now, interval, timeout)
		if gotRound != wantRound || !gotWake.Equal(wantWake) {
			t.Fatalf("at +%s: (%d, %s), want (%d, %s)", off, gotRound, gotWake, wantRound, wantWake)
		}
	}
}

func TestPQCReplayedPubKeyDoesNotDisplaceTheRoundInFlight(t *testing.T) {
	const interval = 10 * time.Second
	r := newPQCTestRepo(t, interval, time.Second, time.Minute)
	round := currentRound(interval)

	priv, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	var replies [][]byte
	reply := func(frame []byte) error {
		replies = append(replies, bytes.Clone(frame))
		return nil
	}
	for _, f := range mustSplit(t, round, pqcKindPubKey, pub) {
		if err := r.HandleFrame(f, reply); err != nil {
			t.Fatalf("HandleFrame(pubKey): %v", err)
		}
	}

	_, stalePub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	for _, f := range mustSplit(t, round-1, pqcKindPubKey, stalePub) {
		_ = r.HandleFrame(f, reply)
	}

	var join pqcJoiner
	var encMsg []byte
	for _, raw := range replies {
		f, err := decodeFrame(raw)
		if err != nil {
			t.Fatalf("decodeFrame: %v", err)
		}
		if f.kind != pqcKindEnc || f.round != round {
			continue
		}
		if msg, done := join.add(f); done {
			encMsg = msg
		}
	}
	if len(encMsg) <= pqcConfirmTagLen {
		t.Fatalf("no encapsulation for the real round: the replay took the reply path")
	}
	key, err := pqcInitiatorFinish(priv, encMsg[:len(encMsg)-pqcConfirmTagLen], round)
	if err != nil {
		t.Fatalf("initiatorFinish: %v", err)
	}
	tag, err := pqcConfirmTag(key, round, pqcRoleInitiator)
	if err != nil {
		t.Fatalf("confirmTag: %v", err)
	}
	for _, f := range mustSplit(t, round, pqcKindTag, tag) {
		if err := r.HandleFrame(f, reply); err != nil {
			t.Fatalf("the replay displaced the round in flight: %v", err)
		}
	}

	got, err := r.GetNewKey()
	if err != nil {
		t.Fatalf("the responder never published, so the initiator would be alone: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("the responder published a key the initiator does not hold")
	}
}

func TestPQCPublishKeepsTheNewerRound(t *testing.T) {
	older := bytes.Repeat([]byte{0xa1}, pqcKeyLen)
	newer := bytes.Repeat([]byte{0xb2}, pqcKeyLen)

	for _, tc := range []struct {
		name  string
		order [][]any
	}{
		{"newer last", [][]any{{uint32(357775722), older}, {uint32(357775723), newer}}},
		{"newer first", [][]any{{uint32(357775723), newer}, {uint32(357775722), older}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPQCTestRepo(t, time.Minute, time.Second, time.Hour)
			for _, step := range tc.order {
				if err := r.publish(step[0].(uint32), step[1].([]byte)); err != nil {
					t.Fatalf("publish: %v", err)
				}
			}
			got, err := r.GetNewKey()
			if err != nil {
				t.Fatalf("GetNewKey: %v", err)
			}
			if !bytes.Equal(got, newer) {
				t.Fatal("the register kept the older round's key; two peers publishing in opposite orders would diverge")
			}
		})
	}
}

func staleRepo(t *testing.T, staleAfter time.Duration) *Repository {
	t.Helper()
	return newPQCTestRepo(t, staleAfter/5, staleAfter/10, staleAfter)
}

func TestPQCPublishLowerRoundRules(t *testing.T) {
	const staleAfter = 100 * time.Millisecond
	keyFor := func(b byte) []byte { return bytes.Repeat([]byte{b}, pqcKeyLen) }

	t.Run("a fresh key beats a lower round", func(t *testing.T) {
		r := staleRepo(t, staleAfter)
		if err := r.publish(101, keyFor(0xa1)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if err := r.publish(100, keyFor(0xb2)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		got, err := r.GetNewKey()
		if err != nil {
			t.Fatalf("GetNewKey: %v", err)
		}
		if !bytes.Equal(got, keyFor(0xa1)) {
			t.Fatal("a lower round replaced a key that was still fresh")
		}
	})

	t.Run("a stale key yields to a lower round", func(t *testing.T) {
		r := staleRepo(t, staleAfter)
		if err := r.publish(101, keyFor(0xa1)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		time.Sleep(2 * staleAfter)
		if _, err := r.GetNewKey(); err == nil {
			t.Fatal("the key should be stale by now")
		}
		if err := r.publish(90, keyFor(0xb2)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		got, err := r.GetNewKey()
		if err != nil {
			t.Fatalf("the lower round did not become the new baseline: %v", err)
		}
		if !bytes.Equal(got, keyFor(0xb2)) {
			t.Fatal("GetNewKey still returns the stale key")
		}

		if err := r.publish(89, keyFor(0xc3)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if got, _ := r.GetNewKey(); !bytes.Equal(got, keyFor(0xb2)) {
			t.Fatal("round 89 displaced the new baseline although it is fresh")
		}
		if err := r.publish(91, keyFor(0xd4)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if got, _ := r.GetNewKey(); !bytes.Equal(got, keyFor(0xd4)) {
			t.Fatal("a higher round did not supersede the new baseline")
		}
	})

	t.Run("an equal round replaces the key", func(t *testing.T) {
		r := staleRepo(t, staleAfter)
		if err := r.publish(101, keyFor(0xa1)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if err := r.publish(101, keyFor(0xb2)); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if got, _ := r.GetNewKey(); !bytes.Equal(got, keyFor(0xb2)) {
			t.Fatal("a repeated round did not refresh the key")
		}
	})
}

func TestPQCStaleLowerRoundResetZeroesTheSupersededKey(t *testing.T) {
	const staleAfter = 100 * time.Millisecond
	r := staleRepo(t, staleAfter)

	if err := r.publish(101, bytes.Repeat([]byte{0xa1}, pqcKeyLen)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	superseded := r.latest.key
	time.Sleep(2 * staleAfter)
	if err := r.publish(90, bytes.Repeat([]byte{0xb2}, pqcKeyLen)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if !bytes.Equal(superseded, make([]byte, pqcKeyLen)) {
		t.Fatal("the lower-round reset left the superseded key material in memory")
	}
}

func TestPQCPeersConvergeAfterBackwardClockStep(t *testing.T) {
	const staleAfter = 100 * time.Millisecond
	a := staleRepo(t, staleAfter)
	b := staleRepo(t, staleAfter)

	old := bytes.Repeat([]byte{0xa1}, pqcKeyLen)
	if err := a.publish(101, old); err != nil {
		t.Fatalf("publish a: %v", err)
	}
	time.Sleep(staleAfter / 2)
	if err := b.publish(101, old); err != nil {
		t.Fatalf("publish b: %v", err)
	}

	time.Sleep(3 * staleAfter / 4)
	lower := bytes.Repeat([]byte{0xb2}, pqcKeyLen)
	if err := a.publish(90, lower); err != nil {
		t.Fatalf("publish a: %v", err)
	}
	if err := b.publish(90, lower); err != nil {
		t.Fatalf("publish b: %v", err)
	}
	if a.latest.round == b.latest.round {
		t.Skip("the two peers became eligible at the same instant; nothing to converge")
	}

	time.Sleep(2 * staleAfter)
	next := bytes.Repeat([]byte{0xc3}, pqcKeyLen)
	if err := a.publish(91, next); err != nil {
		t.Fatalf("publish a: %v", err)
	}
	if err := b.publish(91, next); err != nil {
		t.Fatalf("publish b: %v", err)
	}

	keyA, errA := a.GetNewKey()
	keyB, errB := b.GetNewKey()
	if errA != nil || errB != nil {
		t.Fatalf("a peer has no usable key after recovery: a=%v b=%v", errA, errB)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("the two peers did not converge on the same key")
	}
	if a.latest.round != b.latest.round {
		t.Fatalf("rounds diverged: a=%d b=%d", a.latest.round, b.latest.round)
	}
}

func TestPQCStaleKeyDoesNotBypassTheFrameChecks(t *testing.T) {
	const interval = 10 * time.Second
	r := newPQCTestRepo(t, interval, time.Second, 2*interval)
	round := currentRound(interval)
	stale := bytes.Repeat([]byte{0xa1}, pqcKeyLen)
	if err := r.publish(round, stale); err != nil {
		t.Fatalf("publish: %v", err)
	}
	r.latest.at = time.Now().Add(-time.Hour)
	if _, err := r.GetNewKey(); err == nil {
		t.Fatal("the key should read as stale")
	}

	noReply := func([]byte) error { return fmt.Errorf("the responder must not answer") }

	t.Run("malformed frame", func(t *testing.T) {
		if err := r.HandleFrame([]byte{0x01, 0x02}, noReply); err == nil {
			t.Fatal("a truncated frame was accepted")
		}
	})

	t.Run("round outside the window", func(t *testing.T) {
		_, pub, err := pqcInitiatorStart()
		if err != nil {
			t.Fatalf("initiatorStart: %v", err)
		}
		for _, f := range mustSplit(t, round-5, pqcKindPubKey, pub) {
			if err := r.HandleFrame(f, noReply); err == nil {
				t.Fatal("a frame five rounds behind was accepted")
			}
		}
	})

	t.Run("failed confirmation", func(t *testing.T) {
		var replies [][]byte
		reply := func(frame []byte) error {
			replies = append(replies, bytes.Clone(frame))
			return nil
		}
		_, pub, err := pqcInitiatorStart()
		if err != nil {
			t.Fatalf("initiatorStart: %v", err)
		}
		for _, f := range mustSplit(t, round-1, pqcKindPubKey, pub) {
			if err := r.HandleFrame(f, reply); err != nil {
				t.Fatalf("HandleFrame(pubKey): %v", err)
			}
		}
		forged := bytes.Repeat([]byte{0xff}, pqcConfirmTagLen)
		for _, f := range mustSplit(t, round-1, pqcKindTag, forged) {
			if err := r.HandleFrame(f, reply); err == nil {
				t.Fatal("a forged confirmation tag was accepted")
			}
		}
	})

	if r.latest.round != round {
		t.Fatalf("published round = %d, want the untouched %d", r.latest.round, round)
	}
	if !bytes.Equal(r.latest.key, stale) {
		t.Fatal("a rejected frame changed the published key")
	}
}

func TestPQCAbandonsResponderStateOutsideTheRoundWindow(t *testing.T) {
	const interval = 10 * time.Second
	r := newPQCTestRepo(t, interval, time.Second, 2*interval)
	cur := currentRound(interval)

	future := cur + 100
	_, pub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	_, key, err := pqcResponderRespond(pub, future)
	if err != nil {
		t.Fatalf("responderRespond: %v", err)
	}
	r.resp.round, r.resp.live, r.resp.key = future, true, key

	_, freshPub, err := pqcInitiatorStart()
	if err != nil {
		t.Fatalf("initiatorStart: %v", err)
	}
	var replies [][]byte
	reply := func(frame []byte) error {
		replies = append(replies, bytes.Clone(frame))
		return nil
	}
	for _, f := range mustSplit(t, cur, pqcKindPubKey, freshPub) {
		if err := r.HandleFrame(f, reply); err != nil {
			t.Fatalf("the wedged round blocked the current one: %v", err)
		}
	}
	if len(replies) == 0 {
		t.Fatal("the responder did not answer the current round")
	}
	if r.resp.round != cur {
		t.Fatalf("round in flight = %d, want the current %d", r.resp.round, cur)
	}
	if !bytes.Equal(key, make([]byte, pqcKeyLen)) {
		t.Fatal("the abandoned round's key was not zeroed")
	}
}
