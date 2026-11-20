package main

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
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

func TestShouldRunQKD(t *testing.T) {
	if got := shouldRunQKD(&config.Config{Mode: "PqcOnly"}); got {
		t.Fatal("shouldRunQKD returned true for PqcOnly")
	}
	if got := shouldRunQKD(&config.Config{Mode: "AtLeastPqcRequired"}); got != qkdCompiled {
		t.Fatalf("shouldRunQKD with AtLeastPqcRequired = %t, want qkdCompiled (%t)", got, qkdCompiled)
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
	psk, _ := buildPSK(services.NewKeyWriterService(w), latestPQC(services.NewKeyReaderService(fakePQCReader{})),
		bytes.Repeat([]byte{1}, 32), cfg, slog.New(slog.DiscardHandler))
	if len(psk) == 0 {
		t.Fatal("no PSK built from a QKD and a PQC key")
	}
	if w.writes != 0 {
		t.Fatalf("buildPSK wrote %d PSK(s)", w.writes)
	}
}

func TestBuildPSKIgnoresQKDInPqcOnlyMode(t *testing.T) {
	keyWriter := services.NewKeyWriterService(&countingWriter{})
	pqc := services.NewKeyReaderService(fakePQCReader{})
	logger := slog.New(slog.DiscardHandler)
	qkd := bytes.Repeat([]byte{1}, 32)

	got, _ := buildPSK(keyWriter, latestPQC(pqc), qkd, &config.Config{Mode: "PqcOnly", PQCEnabled: true}, logger)
	want, _ := buildPSK(keyWriter, latestPQC(pqc), nil, &config.Config{Mode: "AtLeastPqcRequired", PQCEnabled: true}, logger)
	defer clear(got)
	defer clear(want)

	if !bytes.Equal(got, want) {
		t.Fatal("PqcOnly PSK included QKD material")
	}
}

func TestBuildPSKInvalidatesAtOnceWhenARequiredPQCKeyIsMissing(t *testing.T) {
	w := &countingWriter{}
	cfg := &config.Config{Mode: "AtLeastPqcRequired", PQCEnabled: true}
	psk, _ := buildPSK(services.NewKeyWriterService(w), latestPQC(services.NewKeyReaderService(fakePQCReader{err: errors.New("no round agreed")})),
		bytes.Repeat([]byte{1}, 32), cfg, slog.New(slog.DiscardHandler))
	if psk != nil {
		t.Fatal("a PSK was built without the required PQC key")
	}
	if w.writes != 1 {
		t.Fatalf("writes = %d, want the one random key that invalidates the tunnel", w.writes)
	}
}

type roundsPQCReader map[string][]byte

func (r roundsPQCReader) GetNewKey() (string, []byte, error) {
	return "8", r["8"], nil
}

func (r roundsPQCReader) GetKeyByID(id string) ([]byte, error) {
	if k, ok := r[id]; ok {
		return k, nil
	}
	return nil, errors.New("round not held")
}

func TestPrimaryDerivesFromTheRoundTheBackupUsedEvenAfterANewerOneLanded(t *testing.T) {
	pqc := services.NewKeyReaderService(roundsPQCReader{"7": bytes.Repeat([]byte{7}, 32), "8": bytes.Repeat([]byte{8}, 32)})
	keyWriter := services.NewKeyWriterService(&countingWriter{})
	cfg := &config.Config{Mode: "QkdAndPqcRequired", PQCEnabled: true}
	logger := slog.New(slog.DiscardHandler)
	qkd := bytes.Repeat([]byte{1}, 32)

	backup, err := kdf.DeriveKey(qkd, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	primary, round := buildPSK(keyWriter, roundPQC(pqc, "7"), qkd, cfg, logger)
	if round != "7" || !bytes.Equal(primary, backup) {
		t.Fatalf("primary used round %q; its PSK must match the backup's round 7", round)
	}
	if _, latest := buildPSK(keyWriter, latestPQC(pqc), qkd, cfg, logger); latest != "8" {
		t.Fatalf("latest round = %q, want 8", latest)
	}
}

func TestPrimaryFallsBackToQKDOnlyWhenTheBackupUsedNoPQCKey(t *testing.T) {
	pqc := services.NewKeyReaderService(roundsPQCReader{"8": bytes.Repeat([]byte{8}, 32)})
	w := &countingWriter{}
	qkd := bytes.Repeat([]byte{1}, 32)
	logger := slog.New(slog.DiscardHandler)

	psk, round := buildPSK(services.NewKeyWriterService(w), roundPQC(pqc, ""), qkd, &config.Config{Mode: "AtLeastQkdRequired", PQCEnabled: true}, logger)
	if round != "" || !bytes.Equal(psk, qkd) {
		t.Fatalf("round %q: the primary must mirror the backup's QKD-only PSK", round)
	}
	if psk, _ := buildPSK(services.NewKeyWriterService(w), roundPQC(pqc, ""), qkd, &config.Config{Mode: "QkdAndPqcRequired", PQCEnabled: true}, logger); psk != nil {
		t.Fatal("a PSK was built without the PQC key the mode requires")
	}
}

func TestIntervalAtGivesBothPeersTheSameBoundaryWhateverTheirStartTime(t *testing.T) {
	interval := 30 * time.Second
	n1, end1 := intervalAt(time.Unix(1_800_000_001, 0), interval, ^uint64(0))
	n2, end2 := intervalAt(time.Unix(1_800_000_029, 999), interval, ^uint64(0))
	if n1 != n2 || !end1.Equal(end2) || !end1.Equal(time.Unix(1_800_000_030, 0)) {
		t.Fatalf("got (%d, %v) and (%d, %v)", n1, end1, n2, end2)
	}
	if n3, _ := intervalAt(end1, interval, n1); n3 != n1+1 {
		t.Fatalf("boundary belongs to the next interval: got %d, want %d", n3, n1+1)
	}
}

func TestIntervalAtSkipsTheServedIntervalWhenTheSleepWakesBeforeTheClockBoundary(t *testing.T) {
	interval := 30 * time.Second
	n, end := intervalAt(time.Unix(1_800_000_001, 0), interval, ^uint64(0))
	n2, end2 := intervalAt(end.Add(-time.Millisecond), interval, n)
	if n2 != n+1 || !end2.Equal(end.Add(interval)) {
		t.Fatalf("got (%d, %v), want (%d, %v)", n2, end2, n+1, end.Add(interval))
	}
}
