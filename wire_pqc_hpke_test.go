package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/arnika-project/arnika/auth"
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/pqchpke"
	"github.com/arnika-project/arnika/transport"
)

// TestPQCAgreementOverRealSockets is the end-to-end test for the wiring, and
// the only one that exercises the property the whole synchronous design rests
// on: the responder answers on its *listening* socket, back to the source
// address, so the reply lands on the initiator's dialled socket and can be read
// there. Everything else is covered without a network; this cannot be.
func TestPQCAgreementOverRealSockets(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	addrA, addrB := freeUDPPort(t), freeUDPPort(t)

	// Different ARNIKA_ID parity, as two real peers are required to have.
	cfgA := &config.Config{
		ListenAddress: addrA, ServerAddress: addrB, ArnikaID: "2",
		ArnikaPSK: psk, MaxClockSkew: time.Minute,
		PQCRoundInterval: 5 * time.Minute, PQCRoundTimeout: 3 * time.Second,
		PQCMaxKeyAge: 10 * time.Minute, // the default: 2 x the round interval
	}
	cfgB := &config.Config{
		ListenAddress: addrB, ServerAddress: addrA, ArnikaID: "3",
		ArnikaPSK: psk, MaxClockSkew: time.Minute,
		PQCRoundInterval: 5 * time.Minute, PQCRoundTimeout: 3 * time.Second,
		PQCMaxKeyAge: 10 * time.Minute, // the default: 2 x the round interval
	}

	// The role is fixed here rather than derived from the PSK, so the test does
	// not depend on which side IsPrimary happens to elect for this round.
	start := func(cfg *config.Config, initiator bool) *pqchpke.Repository {
		t.Helper()
		id := 2
		if !initiator {
			id = 3
		}
		dirOut, dirIn := auth.DirectionFor(id)
		send, recv, err := pqcDial(cfg, dirOut, dirIn)
		if err != nil {
			t.Fatalf("pqcDial: %v", err)
		}
		repo, err := pqchpke.NewRepository(slog.New(slog.DiscardHandler), send, recv,
			func(uint32) bool { return initiator },
			cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge)
		if err != nil {
			t.Fatalf("NewRepository: %v", err)
		}
		result := make(chan transport.KeyIDRequest, 1)
		done := make(chan bool)
		go func() {
			_ = transport.Serve(transport.ServerConfig{
				Address: cfg.ListenAddress, PSK: psk, DirOut: dirOut, DirIn: dirIn,
				KeyIDs: result, Done: done, PQC: repo.HandleFrame,
				RateLimit: 10000, RateWindow: time.Minute, MaxClockSkew: time.Minute,
				Log: slog.New(slog.DiscardHandler),
			})
		}()
		return repo
	}

	repoA := start(cfgA, true)
	repoB := start(cfgB, false)
	time.Sleep(200 * time.Millisecond) // both listeners up

	// A five-minute round interval means a key inside a few seconds can only
	// have come from the startup round.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go repoA.Run(ctx)
	go repoB.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		keyA, errA := repoA.GetNewKey()
		keyB, errB := repoB.GetNewKey()
		if errA == nil && errB == nil {
			if !bytes.Equal(keyA, keyB) {
				t.Fatal("the two peers agreed different keys over real sockets")
			}
			if len(keyA) != 32 {
				t.Fatalf("agreed key is %d bytes, want 32", len(keyA))
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no PQC key agreed over real sockets within 15s")
}

// TestPQCRequiredModeSurvivesIndependentCadences is the in-process stand-in for
// the two-peer integration scenario: two real sockets, the production role
// derivation, the derived per-IP rate limit, and INTERVAL != PQC_ROUND_INTERVAL
// with PQC_MAX_KEY_AGE at its default of twice the round interval.
//
// The assertion is the one a PQC-requiring mode depends on: once a key exists,
// GetNewKey must never report staleness again. Before PQC_MAX_KEY_AGE was
// derived from PQC_ROUND_INTERVAL, this configuration left the key stale for
// most of every healthy round, and each rotation in that window invalidated the
// tunnel.
//
// The rate limit is the calculated default rather than a large constant, so a
// budget too small for a live pair shows up here as failed rounds and then as
// staleness. Healthy traffic sits well below the budget by design - the budget
// covers worst-case retries - so the deterministic proof that it admits the
// maximum legitimate sequence is TestRateBudgetAdmitsMaximumLegitimateTraffic,
// not this test.
func TestPQCRequiredModeSurvivesIndependentCadences(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	addrA, addrB := freeUDPPort(t), freeUDPPort(t)

	// QKD rotates at 5s while PQC rounds run at 1s: the cadences the PRD calls
	// out as independent. The maximum key age is the derived default.
	newCfg := func(listen, peer, id string) *config.Config {
		return &config.Config{
			ListenAddress: listen, ServerAddress: peer, ArnikaID: id,
			ArnikaPSK: psk, MaxClockSkew: time.Minute,
			Interval:         5 * time.Second,
			PQCEnabled:       true,
			PQCRoundInterval: time.Second,
			PQCRoundTimeout:  250 * time.Millisecond,
			PQCMaxKeyAge:     2 * time.Second,
			RateWindow:       time.Minute,
			Mode:             "AtLeastPqcRequired",
		}
	}
	cfgA := newCfg(addrA, addrB, "2")
	cfgB := newCfg(addrB, addrA, "3")

	limit := transport.RateBudget(cfgA)
	start := func(cfg *config.Config, id int) *pqchpke.Repository {
		t.Helper()
		dirOut, dirIn := auth.DirectionFor(id)
		send, recv, err := pqcDial(cfg, dirOut, dirIn)
		if err != nil {
			t.Fatalf("pqcDial: %v", err)
		}
		// The production role derivation, so the two peers alternate initiator
		// and responder across rounds instead of one side always answering.
		repo, err := pqchpke.NewRepository(slog.New(slog.DiscardHandler), send, recv,
			func(round uint32) bool { return cfg.IsPrimary(uint64(round)) },
			cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge)
		if err != nil {
			t.Fatalf("NewRepository: %v", err)
		}
		result := make(chan transport.KeyIDRequest, transport.QKDQueueDepth)
		done := make(chan bool)
		go func() {
			_ = transport.Serve(transport.ServerConfig{
				Address: cfg.ListenAddress, PSK: psk, DirOut: dirOut, DirIn: dirIn,
				KeyIDs: result, Done: done, PQC: repo.HandleFrame,
				RateLimit: limit, RateWindow: cfg.RateWindow, MaxClockSkew: cfg.MaxClockSkew,
				Log: slog.New(slog.DiscardHandler),
			})
		}()
		return repo
	}

	repoA := start(cfgA, 2)
	repoB := start(cfgB, 3)
	time.Sleep(200 * time.Millisecond) // both listeners up

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go repoA.Run(ctx)
	go repoB.Run(ctx)

	// Long enough for several rounds on both cadences, so a key that only
	// survives one round would be caught.
	const runFor = 5 * time.Second
	deadline := time.Now().Add(runFor)
	haveKey := false
	for time.Now().Before(deadline) {
		_, errA := repoA.GetNewKey()
		_, errB := repoB.GetNewKey()
		switch {
		case !haveKey:
			haveKey = errA == nil && errB == nil
		case errA != nil || errB != nil:
			// A PQC-requiring mode invalidates the tunnel here.
			t.Fatalf("a peer lost its usable key mid-run: a=%v b=%v", errA, errB)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !haveKey {
		t.Fatalf("no PQC key agreed within %s", runFor)
	}
}

// freeUDPPort asks the kernel for an unused port and hands it back.
//
// A copy of the transport package's own helper: test helpers are not shared
// across package boundaries, and eight lines are cheaper than exporting a
// testing-only function from transport.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}
