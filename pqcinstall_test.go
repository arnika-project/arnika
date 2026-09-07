package main

import (
	"testing"
	"time"
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
		if got := nextPQCInstall(base.Add(offset), interval, timeout); !got.Equal(want) {
			t.Errorf("nextPQCInstall(boundary+%s) = %s, want %s", offset, got, want)
		}
	}
	// Always in the future, so the caller's Sleep never returns immediately and
	// spins the rotation loop.
	now := base.Add(interval - time.Nanosecond)
	if got := nextPQCInstall(now, interval, timeout); !got.After(now) {
		t.Errorf("nextPQCInstall returned %s, which is not after %s", got, now)
	}
	// A sub-second round interval must not divide by zero.
	if got := nextPQCInstall(base, 100*time.Millisecond, 0); !got.Equal(base.Add(1500 * time.Millisecond)) {
		t.Errorf("nextPQCInstall with a sub-second interval = %s, want %s", got, base.Add(1500*time.Millisecond))
	}
	// The install must never fall inside the window in which the scheduler
	// publishes, which is what would let two peers straddle a new key.
	for _, to := range []time.Duration{time.Millisecond, interval / 4, interval / 2, interval - time.Millisecond} {
		got := nextPQCInstall(base, interval, to)
		boundary := base.Add(interval)
		if !got.After(boundary) || !got.Before(boundary.Add(interval).Add(-to)) {
			t.Errorf("nextPQCInstall(timeout=%s) = %s, outside the quiet window (%s, %s)",
				to, got, boundary, boundary.Add(interval).Add(-to))
		}
	}
}
