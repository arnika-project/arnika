package main

import (
	"bytes"
	"fmt"
	"net"
	"sync/atomic"
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

// testPeer dials a server started by these tests and speaks the wire format.
type testPeer struct {
	t               *testing.T
	conn            net.Conn
	psk             []byte
	peerOut, peerIn auth.Direction
	result          chan string
}

func startTestServer(t *testing.T, handle pqcHandler) *testPeer {
	t.Helper()
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	// Peer signs with its outbound label; the server verifies with dirIn.
	peerOut, peerIn := auth.DirectionFor(9999)
	srvOut, srvIn := peerIn, peerOut

	addr := freeUDPPort(t)
	result := make(chan string, 1)
	done := make(chan bool)
	go udpServer(addr, psk, srvOut, srvIn, result, done, handle,
		10000, time.Minute, time.Minute)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Wait for the listener to be up.
	time.Sleep(100 * time.Millisecond)
	p := &testPeer{t: t, conn: conn, psk: psk, peerOut: peerOut, peerIn: peerIn}
	p.result = result
	return p
}

func (p *testPeer) send(typ auth.PacketType, payload []byte) {
	p.t.Helper()
	enc, err := auth.Encrypt(p.psk, payload)
	if err != nil {
		p.t.Fatalf("encrypt: %v", err)
	}
	pkt := &auth.Packet{Type: typ, Timestamp: time.Now().Unix(), Payload: enc}
	if _, err := p.conn.Write(pkt.Marshal(p.psk, p.peerOut)); err != nil {
		p.t.Fatalf("write: %v", err)
	}
}

// TestPQCFloodDoesNotStallQKDPath asserts the property the inline PQC handler
// must keep: PQC frames are handled on the read loop, so a peer flooding
// PacketPQC must not prevent a PacketData packet from being delivered. It fails
// if anyone ever puts a wait inside the handler or its reply.
func TestPQCFloodDoesNotStallQKDPath(t *testing.T) {
	var handled atomic.Int64
	p := startTestServer(t, func(frame []byte, reply func([]byte) error) error {
		handled.Add(1)
		return nil
	})

	for i := 0; i < 200; i++ {
		p.send(auth.PacketPQC, []byte("pqc frame"))
	}
	p.send(auth.PacketData, []byte("the-key-id"))

	select {
	case got := <-p.result:
		if got != "the-key-id" {
			t.Fatalf("result = %q, want %q", got, "the-key-id")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PacketData was not delivered: the PQC flood stalled the QKD path")
	}
	if handled.Load() == 0 {
		t.Fatal("no PQC frame reached the handler")
	}
}

// TestPQCReplyReachesTheSender asserts the reply path: the responder answers on
// the listening socket, back to the source address, which is what lets the
// initiator's dialled socket read the reply synchronously.
func TestPQCReplyReachesTheSender(t *testing.T) {
	p := startTestServer(t, func(frame []byte, reply func([]byte) error) error {
		return reply(append([]byte("echo:"), frame...))
	})

	p.send(auth.PacketPQC, []byte("ping"))

	if err := p.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := p.conn.Read(buf)
	if err != nil {
		t.Fatalf("no reply from the PQC handler: %v", err)
	}
	// The reply is signed with the server's outbound label, which is the
	// peer's inbound one.
	pkt, err := auth.UnmarshalPacket(p.psk, buf[:n], p.peerIn)
	if err != nil {
		t.Fatalf("reply failed verification: %v", err)
	}
	if pkt.Type != auth.PacketPQC {
		t.Fatalf("reply type = %q, want %q", pkt.Type, auth.PacketPQC)
	}
	frame, err := auth.Decrypt(p.psk, pkt.Payload)
	if err != nil {
		t.Fatalf("reply failed decryption: %v", err)
	}
	if !bytes.Equal(frame, []byte("echo:ping")) {
		t.Fatalf("reply payload = %q", frame)
	}
}

// TestPQCPacketDroppedWithoutHandler asserts a binary with PQC disabled stays
// dark on PQC traffic rather than answering it.
func TestPQCPacketDroppedWithoutHandler(t *testing.T) {
	p := startTestServer(t, nil)

	p.send(auth.PacketPQC, []byte("pqc frame"))

	if err := p.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := p.conn.Read(buf); err == nil {
		t.Fatalf("server replied with %d bytes although no PQC reader is wired", n)
	}
}

// TestUnknownPacketTypeIsDroppedSilently asserts an unknown type produces no
// reply and no delivery.
func TestUnknownPacketTypeIsDroppedSilently(t *testing.T) {
	p := startTestServer(t, func([]byte, func([]byte) error) error { return nil })

	pkt := &auth.Packet{Type: auth.PacketType('Z'), Timestamp: time.Now().Unix()}
	if _, err := p.conn.Write(pkt.Marshal(p.psk, p.peerOut)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := p.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := p.conn.Read(buf); err == nil {
		t.Fatalf("server replied with %d bytes to an unknown packet type; the port must stay dark", n)
	}

	select {
	case got := <-p.result:
		t.Fatalf("unknown type was delivered to the QKD path: %q", got)
	default:
	}
}
