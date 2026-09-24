package main

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/services"
)

// TestNextPQCInstall pins the property the PQC-only build depends on: two peers
// whose clocks agree pick the same install time no matter where in the round
// they happen to ask.
func TestNextPQCInstall(t *testing.T) {
	const interval = 10 * time.Second
	const timeout = 2500 * time.Millisecond

	base := time.Unix(1_700_000_000, 0) // a round boundary for interval=10s
	// Publishes for the boundary at base+interval land in
	// [base+interval-timeout, base+interval], so the install belongs halfway
	// through the quiet remainder: base + 10s + (10s-2.5s)/2.
	want := base.Add(interval).Add((interval - timeout) / 2)
	for _, offset := range []time.Duration{0, time.Millisecond, 3 * time.Second, timeout, interval - time.Nanosecond} {
		if got := nextPQCSetPSKAt(base.Add(offset), interval, timeout); !got.Equal(want) {
			t.Errorf("nextPQCSetPSKAt(boundary+%s) = %s, want %s", offset, got, want)
		}
	}
	// Always in the future, so the caller's Sleep never returns immediately and
	// spins the rotation loop.
	now := base.Add(interval - time.Nanosecond)
	if got := nextPQCSetPSKAt(now, interval, timeout); !got.After(now) {
		t.Errorf("nextPQCSetPSKAt returned %s, which is not after %s", got, now)
	}
	// A sub-second round interval must not divide by zero.
	if got := nextPQCSetPSKAt(base, 100*time.Millisecond, 0); !got.Equal(base.Add(1500 * time.Millisecond)) {
		t.Errorf("nextPQCSetPSKAt with a sub-second interval = %s, want %s", got, base.Add(1500*time.Millisecond))
	}
	// The install must never fall inside the window in which the scheduler
	// publishes, which is what would let two peers straddle a new key.
	for _, to := range []time.Duration{time.Millisecond, interval / 4, interval / 2, interval - time.Millisecond} {
		got := nextPQCSetPSKAt(base, interval, to)
		boundary := base.Add(interval)
		if !got.After(boundary) || !got.Before(boundary.Add(interval).Add(-to)) {
			t.Errorf("nextPQCSetPSKAt(timeout=%s) = %s, outside the quiet window (%s, %s)",
				to, got, boundary, boundary.Add(interval).Add(-to))
		}
	}
}

// TestInstallOnQKDFailure pins who installs the PSK when a QKD retrieval fails,
// which decides whether the two peers stay in step.
//
// The measured failure this encodes: with a KMS outage in AtLeastPqcRequired,
// installing on the local tick as well as on the shared instant had the two
// peers write different keys five seconds apart. In a QKD-optional mode with
// PQC enabled the shared-instant installer owns the PSK and the local tick must
// keep its hands off; in every other combination there is no such installer, so
// the local tick has to act or nothing invalidates the superseded key.
func TestInstallOnQKDFailure(t *testing.T) {
	cases := []struct {
		mode string
		pqc  bool
		want bool
	}{
		// QKD required: no fallback installer exists, so the tick must
		// invalidate the tunnel itself.
		{"QkdAndPqcRequired", true, true},
		{"QkdAndPqcRequired", false, true},
		{"AtLeastQkdRequired", true, true},
		{"AtLeastQkdRequired", false, true},
		// QKD optional with PQC on: the shared-instant installer owns it.
		{"AtLeastPqcRequired", true, false},
		{"EitherQkdOrPqcRequired", true, false},
		// QKD optional with PQC off: no installer, and no key material either,
		// so the tick must run and fail closed.
		{"AtLeastPqcRequired", false, true},
		{"EitherQkdOrPqcRequired", false, true},
	}
	for _, tc := range cases {
		name := tc.mode
		if tc.pqc {
			name += "+pqc"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{Mode: tc.mode, PQCEnabled: tc.pqc}
			if got := shouldSetPSKOnQKDFailure(cfg); got != tc.want {
				t.Fatalf("shouldSetPSKOnQKDFailure = %v, want %v", got, tc.want)
			}
		})
	}
}

type countingWriter struct{ writes int }

func (w *countingWriter) SetPSK([]byte) error {
	w.writes++
	return nil
}

type fakePQCReader struct{ err error }

func (r fakePQCReader) GetNewKey() (string, []byte, error) {
	return "", bytes.Repeat([]byte{7}, 32), r.err
}

func TestBuildPSKLeavesTheWriteToTheCaller(t *testing.T) {
	w := &countingWriter{}
	cfg := &config.Config{Mode: "QkdAndPqcRequired", PQCEnabled: true}
	psk := buildPSK(services.NewKeyWriterService(w), services.NewKeyReaderService(fakePQCReader{}),
		bytes.Repeat([]byte{1}, 32), cfg, slog.New(slog.DiscardHandler))
	if len(psk) == 0 {
		t.Fatal("no PSK built from a QKD and a PQC key")
	}
	if w.writes != 0 {
		t.Fatalf("buildPSK wrote %d PSK(s)", w.writes)
	}
}

func TestBuildPSKInvalidatesAtOnceWhenARequiredPQCKeyIsMissing(t *testing.T) {
	w := &countingWriter{}
	cfg := &config.Config{Mode: "AtLeastPqcRequired", PQCEnabled: true}
	psk := buildPSK(services.NewKeyWriterService(w), services.NewKeyReaderService(fakePQCReader{err: errors.New("no round agreed")}),
		bytes.Repeat([]byte{1}, 32), cfg, slog.New(slog.DiscardHandler))
	if psk != nil {
		t.Fatal("a PSK was built without the required PQC key")
	}
	if w.writes != 1 {
		t.Fatalf("writes = %d, want the one random key that invalidates the tunnel", w.writes)
	}
}
