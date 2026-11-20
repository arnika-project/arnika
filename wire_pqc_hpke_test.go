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

func startPQCPeer(t *testing.T, cfg *config.Config, rateLimit int) *pqchpke.Repository {
	t.Helper()
	dirOut, dirIn := auth.DirectionFor(cfg.IsPrimary())
	send, recv, err := pqcLink(cfg, dirOut, dirIn)
	if err != nil {
		t.Fatalf("pqcLink: %v", err)
	}
	repo, err := pqchpke.NewRepository(slog.New(slog.DiscardHandler), send, recv,
		func(uint32) bool { return cfg.IsPrimary() },
		cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	if !cfg.IsPrimary() {
		done := make(chan bool)
		t.Cleanup(func() { close(done) })
		go func() {
			_ = transport.Serve(transport.ServerConfig{
				Address: cfg.ListenAddress, PSK: cfg.ArnikaPSK, DirOut: dirOut, DirIn: dirIn,
				KeyIDs: make(chan transport.KeyIDRequest, transport.QKDQueueDepth), Done: done, PQC: repo.HandleFrame,
				RateLimit: rateLimit, RateWindow: time.Minute, MaxClockSkew: cfg.MaxClockSkew,
				Log: slog.New(slog.DiscardHandler),
			})
		}()
	}
	return repo
}

func TestPQCAgreementOverRealSockets(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	addrB := freeUDPPort(t)
	const startupRoundOnlyInterval = 5 * time.Minute
	newCfg := func(listen, server string) *config.Config {
		return &config.Config{
			ListenAddress: listen, ServerAddress: server,
			ArnikaPSK: psk, MaxClockSkew: time.Minute,
			PQCRoundInterval: startupRoundOnlyInterval, PQCRoundTimeout: 3 * time.Second,
			PQCMaxKeyAge: 2 * startupRoundOnlyInterval,
		}
	}
	repoA := startPQCPeer(t, newCfg("", addrB), 10000)
	repoB := startPQCPeer(t, newCfg(addrB, ""), 10000)
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
	addrB := freeUDPPort(t)
	const roundInterval = time.Second

	newCfg := func(listen, server string) *config.Config {
		return &config.Config{
			ListenAddress: listen, ServerAddress: server,
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
	cfgB := newCfg(addrB, "")
	repoA := startPQCPeer(t, newCfg("", addrB), transport.RateBudget(cfgB))
	repoB := startPQCPeer(t, cfgB, transport.RateBudget(cfgB))
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

func TestPQCRecvSurvivesAnICMPError(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	dirOut, dirIn := auth.DirectionFor(true)
	send, recv, err := pqcDial(&config.Config{ServerAddress: peerAddr.String(), ArnikaPSK: psk, MaxClockSkew: time.Minute}, dirOut, dirIn)
	if err != nil {
		t.Fatalf("pqcDial: %v", err)
	}

	if err := send([]byte("hello")); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 2048)
	_, initiator, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = peer.Close()
	if err := send([]byte("refused")); err != nil {
		t.Fatalf("send: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	peer, err = net.ListenUDP("udp", peerAddr)
	if err != nil {
		t.Fatalf("relisten: %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	enc, err := auth.Encrypt(psk, []byte("reply"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	reply := (&auth.Packet{Type: auth.PacketPQC, Timestamp: time.Now().Unix(), Payload: enc}).Marshal(psk, dirIn)
	if _, err := peer.WriteToUDP(reply, initiator); err != nil {
		t.Fatalf("reply: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	frame, err := recv(time.Now().Add(time.Second))
	if err != nil || string(frame) != "reply" {
		t.Fatalf("recv = %q, %v; want the authenticated reply despite the ICMP error", frame, err)
	}
}
