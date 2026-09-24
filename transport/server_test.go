package transport

import (
	"bytes"
	"fmt"
	"log/slog"
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
	result          chan KeyIDRequest
	done            chan bool
}

func startTestServer(t *testing.T, handle PQCHandler) *testPeer {
	t.Helper()
	return startTestServerQueue(t, handle, 1)
}

// startTestServerQueue starts a server whose QKD queue holds queueDepth key
// ids, so a test can fill it deterministically.
func startTestServerQueue(t *testing.T, handle PQCHandler, queueDepth int) *testPeer {
	t.Helper()
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	// Peer signs with its outbound label; the server verifies with dirIn.
	peerOut, peerIn := auth.DirectionFor(9999)
	srvOut, srvIn := peerIn, peerOut

	addr := freeUDPPort(t)
	result := make(chan KeyIDRequest, queueDepth)
	done := make(chan bool)
	go func() {
		_ = Serve(ServerConfig{
			Address: addr, PSK: psk, DirOut: srvOut, DirIn: srvIn,
			KeyIDs: result, Done: done, PQC: handle,
			RateLimit: 10000, RateWindow: time.Minute, MaxClockSkew: time.Minute,
			Log: slog.New(slog.DiscardHandler),
		})
	}()

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

// ackWithin returns the key id of an ACK arriving inside d.
func (p *testPeer) ackWithin(d time.Duration) (string, bool) {
	p.t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		p.t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := p.conn.Read(buf)
	if err != nil {
		return "", false
	}
	pkt, err := auth.UnmarshalPacket(p.psk, buf[:n], p.peerIn)
	if err != nil {
		p.t.Fatalf("reply failed verification: %v", err)
	}
	if pkt.Type != auth.PacketAck {
		return "", false
	}
	keyID, err := auth.Decrypt(p.psk, pkt.Payload)
	if err != nil {
		p.t.Fatalf("ACK failed decryption: %v", err)
	}
	return string(keyID), true
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
		if got.KeyID != "the-key-id" {
			t.Fatalf("result = %q, want %q", got.KeyID, "the-key-id")
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
		t.Fatalf("unknown type was delivered to the QKD path: %q", got.KeyID)
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

func TestFullQKDQueueDropsTheKeyIDUntilItDrains(t *testing.T) {
	p := startTestServerQueue(t, nil, 1)

	p.send(auth.PacketData, []byte("fills-the-queue"))
	for deadline := time.Now().Add(2 * time.Second); len(p.result) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the first key id was not queued")
		}
	}
	p.send(auth.PacketData, []byte("rejected"))
	if _, acked := p.ackWithin(300 * time.Millisecond); acked {
		t.Fatal("a key id the full queue rejected was acknowledged")
	}

	if got := <-p.result; got.KeyID != "fills-the-queue" {
		t.Fatalf("queued key id = %q", got.KeyID)
	}
	select {
	case got := <-p.result:
		t.Fatalf("the rejected key id was queued anyway: %q", got.KeyID)
	default:
	}

	p.send(auth.PacketData, []byte("rejected"))
	select {
	case got := <-p.result:
		if got.KeyID != "rejected" {
			t.Fatalf("queued key id = %q", got.KeyID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the resend was not queued after the queue drained")
	}
}

func TestServerAcksOnlyWhenTheWorkerDoesAndNamesTheKeyID(t *testing.T) {
	p := startTestServer(t, nil)

	p.send(auth.PacketData, []byte("the-key-id"))
	var req KeyIDRequest
	select {
	case req = <-p.result:
	case <-time.After(2 * time.Second):
		t.Fatal("the key id was not queued")
	}
	if _, acked := p.ackWithin(300 * time.Millisecond); acked {
		t.Fatal("the key id was acknowledged before the worker installed it")
	}

	req.Ack()
	keyID, acked := p.ackWithin(2 * time.Second)
	if !acked {
		t.Fatal("no ACK after the worker acknowledged")
	}
	if keyID != "the-key-id" {
		t.Fatalf("ACK names key id %q, want %q", keyID, "the-key-id")
	}
}

func TestRunKeyIDWorkerAnswersAResendFromTheFirstOutcome(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed bool
		wantAcks  int64
	}{
		{"installed", true, 2},
		{"failed", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var installs, acks atomic.Int64
			ack := func() { acks.Add(1) }
			queue := make(chan KeyIDRequest, 3)
			queue <- KeyIDRequest{KeyID: "resent", Ack: ack}
			queue <- KeyIDRequest{KeyID: "resent", Ack: ack}
			queue <- KeyIDRequest{KeyID: "end", Ack: func() {}}
			done := make(chan bool)
			defer close(done)
			finished := make(chan struct{})
			go RunKeyIDWorker(done, queue, func(keyID string) bool {
				if keyID == "end" {
					close(finished)
					return false
				}
				installs.Add(1)
				return tc.installed
			})

			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("the worker did not reach the last request")
			}
			if got := installs.Load(); got != 1 {
				t.Fatalf("installs = %d, want 1", got)
			}
			if got := acks.Load(); got != tc.wantAcks {
				t.Fatalf("acks = %d, want %d", got, tc.wantAcks)
			}
		})
	}
}

func startFakePeer(t *testing.T, ackFor func(attempt int, keyID string) (ack string, reply bool)) ClientConfig {
	t.Helper()
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	clientOut, clientIn := auth.DirectionFor(9999)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for attempt := 1; ; attempt++ {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt, err := auth.UnmarshalPacket(psk, buf[:n], clientOut)
			if err != nil {
				t.Errorf("DATA failed verification: %v", err)
				return
			}
			keyID, err := auth.Decrypt(psk, pkt.Payload)
			if err != nil {
				t.Errorf("DATA failed decryption: %v", err)
				return
			}
			ack, reply := ackFor(attempt, string(keyID))
			if !reply {
				continue
			}
			enc, err := auth.Encrypt(psk, []byte(ack))
			if err != nil {
				t.Errorf("encrypt: %v", err)
				return
			}
			out := &auth.Packet{Type: auth.PacketAck, Timestamp: time.Now().Unix(), Payload: enc}
			_, _ = conn.WriteToUDP(out.Marshal(psk, clientIn), from)
		}
	}()
	return ClientConfig{
		Address: conn.LocalAddr().String(), PSK: psk, DirOut: clientOut, DirIn: clientIn,
		KeyID: "the-key-id", Timeout: 100 * time.Millisecond, Deadline: time.Now().Add(time.Second),
		MaxClockSkew: time.Minute, Log: slog.New(slog.DiscardHandler),
	}
}

func TestSendKeyIDResendsAfterALostDataPacket(t *testing.T) {
	c := startFakePeer(t, func(attempt int, keyID string) (string, bool) { return keyID, attempt > 1 })
	if err := SendKeyID(c); err != nil {
		t.Fatalf("SendKeyID: %v", err)
	}
}

func TestSendKeyIDIgnoresAnAckForAnotherKeyID(t *testing.T) {
	c := startFakePeer(t, func(int, string) (string, bool) { return "another-key-id", true })
	if err := SendKeyID(c); err == nil {
		t.Fatal("SendKeyID took an ACK for another key id")
	}
}

func TestSendKeyIDWaitsUntilTheDeadlineWithinTheDataPacketBudget(t *testing.T) {
	var attempts atomic.Int64
	c := startFakePeer(t, func(int, string) (string, bool) {
		attempts.Add(1)
		return "", false
	})
	start := time.Now()
	if err := SendKeyID(c); err == nil {
		t.Fatal("SendKeyID succeeded without an ACK")
	}
	if took := time.Since(start); took < 900*time.Millisecond {
		t.Fatalf("SendKeyID gave up after %s, before its deadline", took)
	}
	if got := attempts.Load(); got != udpClientMaxAttempts {
		t.Fatalf("DATA packets = %d, want %d", got, udpClientMaxAttempts)
	}
}

func TestSendKeyIDWaitsForASlowInstallWithoutReinstalling(t *testing.T) {
	p := startTestServerQueue(t, nil, QKDQueueDepth)
	done := make(chan bool)
	t.Cleanup(func() { close(done) })
	var installs atomic.Int64
	go RunKeyIDWorker(done, p.result, func(string) bool {
		installs.Add(1)
		time.Sleep(700 * time.Millisecond)
		return true
	})

	err := SendKeyID(ClientConfig{
		Address: p.conn.RemoteAddr().String(), PSK: p.psk, DirOut: p.peerOut, DirIn: p.peerIn,
		KeyID: "slow", Timeout: 100 * time.Millisecond, Deadline: time.Now().Add(3 * time.Second),
		MaxClockSkew: time.Minute, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("SendKeyID: %v", err)
	}
	if got := installs.Load(); got != 1 {
		t.Fatalf("installs = %d, want 1", got)
	}
}

// TestRunQKDWorkerProcessesInReceiveOrder covers AC-2.3. A pool of workers
// would install PSKs in the reverse of the order the peer sent the identifiers.
func TestRunQKDWorkerProcessesInReceiveOrder(t *testing.T) {
	const n = 32
	queue := make(chan KeyIDRequest, n)
	for i := 0; i < n; i++ {
		queue <- KeyIDRequest{KeyID: fmt.Sprintf("key-id-%02d", i), Ack: func() {}}
	}
	done := make(chan bool)
	defer close(done)

	seen := make(chan string, n)
	go RunKeyIDWorker(done, queue, func(keyID string) bool {
		seen <- keyID
		return true
	})

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
			queue := make(chan KeyIDRequest, 4)
			for i := 0; i < tc.queued; i++ {
				queue <- KeyIDRequest{KeyID: fmt.Sprintf("key-id-%d", i), Ack: func() {}}
			}
			done := make(chan bool)
			exited := make(chan struct{})
			go func() {
				defer close(exited)
				RunKeyIDWorker(done, queue, func(string) bool { return false })
			}()

			close(done)
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				t.Fatal("RunKeyIDWorker did not return after shutdown: goroutine leak")
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
