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

func TestNextPQCInstall(t *testing.T) {
	const interval = 10 * time.Second
	const timeout = 2500 * time.Millisecond
	roundBoundary := time.Unix(1_700_000_000, 0)
	nextBoundary := roundBoundary.Add(interval)

	t.Run("peers asking anywhere in the round install halfway through the quiet remainder", func(t *testing.T) {
		want := nextBoundary.Add((interval - timeout) / 2)
		for _, offset := range []time.Duration{0, time.Millisecond, 3 * time.Second, timeout, interval - time.Nanosecond} {
			if got := nextPQCSetPSKAt(roundBoundary.Add(offset), interval, timeout); !got.Equal(want) {
				t.Errorf("nextPQCSetPSKAt(boundary+%s) = %s, want %s", offset, got, want)
			}
		}
	})
	t.Run("always in the future so the rotation loop cannot spin", func(t *testing.T) {
		now := roundBoundary.Add(interval - time.Nanosecond)
		if got := nextPQCSetPSKAt(now, interval, timeout); !got.After(now) {
			t.Errorf("nextPQCSetPSKAt returned %s, which is not after %s", got, now)
		}
	})
	t.Run("sub-second interval does not divide by zero", func(t *testing.T) {
		if got := nextPQCSetPSKAt(roundBoundary, 100*time.Millisecond, 0); !got.Equal(roundBoundary.Add(1500 * time.Millisecond)) {
			t.Errorf("nextPQCSetPSKAt with a sub-second interval = %s, want %s", got, roundBoundary.Add(1500*time.Millisecond))
		}
	})
	t.Run("never inside the publish window where peers could straddle a new key", func(t *testing.T) {
		for _, to := range []time.Duration{time.Millisecond, interval / 4, interval / 2, interval - time.Millisecond} {
			got := nextPQCSetPSKAt(roundBoundary, interval, to)
			if !got.After(nextBoundary) || !got.Before(nextBoundary.Add(interval).Add(-to)) {
				t.Errorf("nextPQCSetPSKAt(timeout=%s) = %s, outside the quiet window (%s, %s)",
					to, got, nextBoundary, nextBoundary.Add(interval).Add(-to))
			}
		}
	})
}

func TestInstallOnQKDFailureUnlessQKDIsOptionalAndPQCInstallsAtTheSharedInstant(t *testing.T) {
	cases := []struct {
		mode string
		pqc  bool
		want bool
	}{
		{"QkdAndPqcRequired", true, true},
		{"QkdAndPqcRequired", false, true},
		{"AtLeastQkdRequired", true, true},
		{"AtLeastQkdRequired", false, true},
		{"AtLeastPqcRequired", true, false},
		{"EitherQkdOrPqcRequired", true, false},
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
