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

func TestPQCAgreementOverRealSockets(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	addrA, addrB := freeUDPPort(t), freeUDPPort(t)
	const startupRoundOnlyInterval = 5 * time.Minute

	cfgA := &config.Config{
		ListenAddress: addrA, ServerAddress: addrB, ArnikaID: "2",
		ArnikaPSK: psk, MaxClockSkew: time.Minute,
		PQCRoundInterval: startupRoundOnlyInterval, PQCRoundTimeout: 3 * time.Second,
		PQCMaxKeyAge: 2 * startupRoundOnlyInterval,
	}
	cfgB := &config.Config{
		ListenAddress: addrB, ServerAddress: addrA, ArnikaID: "3",
		ArnikaPSK: psk, MaxClockSkew: time.Minute,
		PQCRoundInterval: startupRoundOnlyInterval, PQCRoundTimeout: 3 * time.Second,
		PQCMaxKeyAge: 2 * startupRoundOnlyInterval,
	}

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
	time.Sleep(200 * time.Millisecond)

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

func TestPQCRequiredModeKeyNeverGoesStaleAtIndependentCadencesAndTheCalculatedRateLimit(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	addrA, addrB := freeUDPPort(t), freeUDPPort(t)
	const roundInterval = time.Second

	newCfg := func(listen, peer, id string) *config.Config {
		return &config.Config{
			ListenAddress: listen, ServerAddress: peer, ArnikaID: id,
			ArnikaPSK: psk, MaxClockSkew: time.Minute,
			Interval:         5 * time.Second,
			PQCEnabled:       true,
			PQCRoundInterval: roundInterval,
			PQCRoundTimeout:  250 * time.Millisecond,
			PQCMaxKeyAge:     2 * roundInterval,
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
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go repoA.Run(ctx)
	go repoB.Run(ctx)

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
			t.Fatalf("a peer lost its usable key mid-run: a=%v b=%v", errA, errB)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !haveKey {
		t.Fatalf("no PQC key agreed within %s", runFor)
	}
}

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
