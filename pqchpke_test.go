package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/arnika-project/arnika/auth"
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
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
		PQCMaxKeyAge: time.Minute,
	}
	cfgB := &config.Config{
		ListenAddress: addrB, ServerAddress: addrA, ArnikaID: "3",
		ArnikaPSK: psk, MaxClockSkew: time.Minute,
		PQCRoundInterval: 5 * time.Minute, PQCRoundTimeout: 3 * time.Second,
		PQCMaxKeyAge: time.Minute,
	}

	// The role is fixed here rather than derived from the PSK, so the test does
	// not depend on which side IsPrimary happens to elect for this round.
	start := func(cfg *config.Config, initiator bool) *repositories.PQCHPKERepository {
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
		repo, err := repositories.NewPQCHPKERepository("PQC-HPKE[e2e]", send, recv,
			func(uint32) bool { return initiator },
			cfg.PQCRoundInterval, cfg.PQCRoundTimeout, cfg.PQCMaxKeyAge)
		if err != nil {
			t.Fatalf("NewPQCHPKERepository: %v", err)
		}
		result := make(chan string, 1)
		done := make(chan bool)
		go udpServer(cfg.ListenAddress, psk, dirOut, dirIn, result, done,
			repo.HandleFrame, 10000, time.Minute, time.Minute)
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
