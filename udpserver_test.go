package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/arnika-project/arnika/auth"
)

// freeUDPPort asks the kernel for an unused port and hands it back.
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
	_ = c.Close()
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// TestPQCFloodDoesNotStallQKDPath asserts the property the non-blocking send in
// udpServer exists for: a peer flooding PacketPQC while nothing consumes
// pqcInbound must not prevent a PacketData packet from being delivered.
func TestPQCFloodDoesNotStallQKDPath(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	// Peer signs with its outbound label; the server verifies with dirIn.
	peerOut, peerIn := auth.DirectionFor(9999)
	srvOut, srvIn := peerIn, peerOut

	addr := freeUDPPort(t)
	result := make(chan string, 1)
	done := make(chan bool)
	// Deliberately tiny and never drained, so the queue fills immediately.
	pqcInbound := make(chan []byte, 2)

	go udpServer(addr, psk, srvOut, srvIn, result, done, pqcInbound,
		10000, time.Minute, time.Minute)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	send := func(typ auth.PacketType, payload []byte) {
		t.Helper()
		enc, err := auth.Encrypt(psk, payload)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		pkt := &auth.Packet{Type: typ, Timestamp: time.Now().Unix(), Payload: enc}
		if _, err := conn.Write([]byte(base64.StdEncoding.EncodeToString(pkt.Marshal(psk, peerOut)))); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// Wait for the listener to be up before flooding it.
	time.Sleep(100 * time.Millisecond)

	// Flood far past the queue capacity; every excess frame must be dropped,
	// not block the read loop.
	for i := 0; i < 200; i++ {
		send(auth.PacketPQC, []byte("pqc frame"))
	}

	// The QKD path must still work.
	send(auth.PacketData, []byte("the-key-id"))

	select {
	case got := <-result:
		if got != "the-key-id" {
			t.Fatalf("result = %q, want %q", got, "the-key-id")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PacketData was not delivered: the PQC flood stalled the QKD path")
	}
}

// TestUnknownPacketTypeIsDroppedSilently asserts an unknown type produces no
// reply and no delivery.
func TestUnknownPacketTypeIsDroppedSilently(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	peerOut, peerIn := auth.DirectionFor(9999)
	srvOut, srvIn := peerIn, peerOut

	addr := freeUDPPort(t)
	result := make(chan string, 1)
	done := make(chan bool)
	pqcInbound := make(chan []byte, 8)

	go udpServer(addr, psk, srvOut, srvIn, result, done, pqcInbound,
		10000, time.Minute, time.Minute)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	time.Sleep(100 * time.Millisecond)

	pkt := &auth.Packet{Type: auth.PacketType('Z'), Timestamp: time.Now().Unix()}
	if _, err := conn.Write([]byte(base64.StdEncoding.EncodeToString(pkt.Marshal(psk, peerOut)))); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("server replied with %d bytes to an unknown packet type; the port must stay dark", n)
	}

	select {
	case got := <-result:
		t.Fatalf("unknown type was delivered to the QKD path: %q", got)
	default:
	}
}
