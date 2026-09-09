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
	done            chan bool
}

func startTestServer(t *testing.T, handle pqcHandler) *testPeer {
	t.Helper()
	return startTestServerQueue(t, handle, 1)
}

// startTestServerQueue starts a server whose QKD queue holds queueDepth key
// ids, so a test can fill it deterministically.
func startTestServerQueue(t *testing.T, handle pqcHandler, queueDepth int) *testPeer {
	t.Helper()
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	// Peer signs with its outbound label; the server verifies with dirIn.
	peerOut, peerIn := auth.DirectionFor(9999)
	srvOut, srvIn := peerIn, peerOut

	addr := freeUDPPort(t)
	result := make(chan string, queueDepth)
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
	p.done = done
	return p
}

// ackWithin reports whether an ACK arrives inside d.
func (p *testPeer) ackWithin(d time.Duration) bool {
	p.t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		p.t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := p.conn.Read(buf)
	if err != nil {
		return false
	}
	pkt, err := auth.UnmarshalPacket(p.psk, buf[:n], p.peerIn)
	if err != nil {
		p.t.Fatalf("reply failed verification: %v", err)
	}
	return pkt.Type == auth.PacketAck
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

// TestBlockedQKDWorkerDoesNotStallPQCPath covers AC-2.1: with the QKD worker
// stuck in a KMS request the queue fills, and the read loop must keep servicing
// PQC frames on the same socket. Before the bounded queue the read loop blocked
// on the unbuffered hand-off and no PQC frame was seen for the duration of the
// outage, which is longer than any PQC round timeout.
func TestBlockedQKDWorkerDoesNotStallPQCPath(t *testing.T) {
	pqcSeen := make(chan struct{}, 1)
	p := startTestServerQueue(t, func([]byte, func([]byte) error) error {
		select {
		case pqcSeen <- struct{}{}:
		default:
		}
		return nil
	}, 2)

	// Nothing drains p.result: that is a worker blocked in a KMS request. Send
	// more identifiers than the queue holds so the read loop meets a full one.
	for i := 0; i < 5; i++ {
		p.send(auth.PacketData, []byte(fmt.Sprintf("key-id-%d", i)))
	}
	p.send(auth.PacketPQC, []byte("pqc frame"))

	select {
	case <-pqcSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("no PQC frame reached the handler: a full QKD queue stalled the read loop")
	}
}

// TestFullQKDQueueIsNotAcknowledged covers AC-2.2. The ACK is the sender's only
// signal that it need not retry, so an identifier the queue could not take must
// stay unacknowledged.
func TestFullQKDQueueIsNotAcknowledged(t *testing.T) {
	p := startTestServerQueue(t, nil, 1)

	p.send(auth.PacketData, []byte("accepted"))
	if !p.ackWithin(2 * time.Second) {
		t.Fatal("the first key id was not acknowledged")
	}
	if got := <-p.result; got != "accepted" {
		t.Fatalf("queued key id = %q", got)
	}

	// Refill the single slot, then send one more with no room left.
	p.send(auth.PacketData, []byte("fills-the-queue"))
	if !p.ackWithin(2 * time.Second) {
		t.Fatal("the second key id was not acknowledged")
	}
	p.send(auth.PacketData, []byte("rejected"))
	if p.ackWithin(500 * time.Millisecond) {
		t.Fatal("a key id the full queue rejected was acknowledged anyway")
	}

	// The read loop is still alive: draining the queue lets the retry through.
	if got := <-p.result; got != "fills-the-queue" {
		t.Fatalf("queued key id = %q", got)
	}
	p.send(auth.PacketData, []byte("rejected"))
	if !p.ackWithin(2 * time.Second) {
		t.Fatal("the retry was not acknowledged after the queue drained")
	}
}

// TestRunQKDWorkerProcessesInReceiveOrder covers AC-2.3. A pool of workers
// would install PSKs in the reverse of the order the peer sent the identifiers.
func TestRunQKDWorkerProcessesInReceiveOrder(t *testing.T) {
	const n = 32
	queue := make(chan string, n)
	for i := 0; i < n; i++ {
		queue <- fmt.Sprintf("key-id-%02d", i)
	}
	done := make(chan bool)
	defer close(done)

	seen := make(chan string, n)
	go runQKDWorker(done, queue, func(keyID string) { seen <- keyID })

	for i := 0; i < n; i++ {
		want := fmt.Sprintf("key-id-%02d", i)
		select {
		case got := <-seen:
			if got != want {
				t.Fatalf("position %d: got %q, want %q", i, got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d identifiers were processed", i, n)
		}
	}
}

// TestRunQKDWorkerStopsOnShutdown covers AC-2.4: the worker must not outlive
// the server that feeds it, whether the queue is empty, full, or being served.
func TestRunQKDWorkerStopsOnShutdown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		queued int
	}{
		{"idle", 0},
		{"work queued", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queue := make(chan string, 4)
			for i := 0; i < tc.queued; i++ {
				queue <- "key-id"
			}
			done := make(chan bool)
			exited := make(chan struct{})
			go func() {
				defer close(exited)
				runQKDWorker(done, queue, func(string) {})
			}()

			close(done)
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				t.Fatal("runQKDWorker did not return after shutdown: goroutine leak")
			}
		})
	}
}

// TestLogThrottle asserts the packet-path warnings cannot become a logging
// denial of service, and that the zero value stays permissive.
func TestLogThrottle(t *testing.T) {
	tr := logThrottle{interval: time.Hour}
	if !tr.allow() {
		t.Fatal("the first call must be allowed")
	}
	for i := 0; i < 1000; i++ {
		if tr.allow() {
			t.Fatalf("call %d slipped through the throttle", i)
		}
	}

	var zero logThrottle
	for i := 0; i < 3; i++ {
		if !zero.allow() {
			t.Fatal("the zero value must allow every call")
		}
	}
}
