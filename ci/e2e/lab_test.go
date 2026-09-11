// Package e2e runs Arnika end to end in containers, against whatever Docker the
// machine has. It is the proof of concept for replacing ci/clab-ci.yaml plus
// ci/verify-keys.sh with a suite that runs the same way locally and in CI;
// containerlab cannot, being Linux-only.
//
//	cd ci/e2e && go test -v -timeout 15m ./...
//
// A module of its own, so testcontainers and its dependency tree stay out of
// Arnika's go.mod. That also keeps it out of the root module's ./... , so no
// build tag is needed to hide it from `go test ./...`.
//
// Scope of the PoC: what ci/verify-keys.sh asserts today (both ends install the
// same PSK, traffic crosses the tunnel), in the default MODE. The rotation
// cycles, the missing-source faults and the desync recovery that
// ci/local-darwin/run.sh covers are not here yet.
//
// One Docker network with DNS aliases, not the three point-to-point links
// clab-ci.yaml builds: PSK convergence does not care which link carried the
// traffic, and Arnika resolves hostnames (net.ResolveUDPAddr in udpserver.go),
// so the whole addressing scheme collapses to three names.
// ponytail: single network. Split into one network per link when a test needs
// to prove node-b cannot reach node-a's KMS leg.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// Matches ci/node-a/start.sh, so a PoC failure is never down to a different
	// rotation interval than the suite it reproduces. A Duration, not a string,
	// because the tests wait in multiples of it; %s renders it back as "5s" for
	// Arnika's INTERVAL.
	interval = 5 * time.Second
	wgPort   = "51820"

	simulatorImage = "qkd-simulator:e2e"
	nodeImage      = "arnika-node:e2e"

	// How many rotations to watch, as CYCLES does in ci/local-darwin/run.sh.
	cycles = 3
)

// zeroPSK is 32 zero bytes, which is how WireGuard spells "no preshared key".
var zeroPSK = base64.StdEncoding.EncodeToString(make([]byte, 32))

// TestMain builds the two images the lab runs on, reusing ci/Dockerfile.node and
// ci/Dockerfile.simulator unchanged.
//
// Through the docker CLI, not testcontainers' own FromDockerfile: that posts the
// build context to the engine's legacy build endpoint, which fails with
// "NotFound: content digest ... not found" once Docker uses the containerd image
// store (`docker info` reporting io.containerd.snapshotter.v1, the default on
// Docker Desktop 29). The CLI goes through buildkit. Building here rather than
// per container request also means one build for both nodes, and buildkit's
// cache makes a second run seconds.
func TestMain(m *testing.M) {
	// Ryuk is testcontainers' own reaper container. It never becomes reachable
	// here: testcontainers cannot find its mapped port ("port 8080/tcp not
	// found"), so Ryuk hits its own 1m connection timeout and exits, and the
	// run dies with it. Plain `docker run` of the same image works and the
	// engine maps ports correctly, so this looks like the same Docker 29 / API
	// 1.55 mismatch as the build above, but that is unconfirmed.
	// Every container and network below is registered for teardown with
	// CleanupContainer/CleanupNetwork, so t.Cleanup already covers the normal
	// path; the reaper only adds a safety net for a hard-killed test process.
	// ponytail: reaper off. Revisit when testcontainers catches up to Docker 29.
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	for _, img := range [][2]string{
		{simulatorImage, "ci/Dockerfile.simulator"},
		{nodeImage, "ci/Dockerfile.node"},
	} {
		cmd := exec.Command("docker", "build", "-q", "-f", img[1], "-t", img[0], ".")
		cmd.Dir = "../.." // the repo root: both Dockerfiles COPY from it
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s\n", img[0], err, out)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

type node struct {
	name string
	ctr  testcontainers.Container
	priv string
	pub  string
	wgIP string // its address on the tunnel
	sae  string // its SAE name at the KMS
	id   string // ARNIKA_ID, which doubles as the transport port
	peer *node
}

// exec runs a shell command in the node and returns its combined output.
// Multiplexed strips the 8-byte docker stream headers; without it every
// captured string carries control bytes and no comparison holds.
func (n *node) exec(t *testing.T, format string, args ...any) string {
	t.Helper()
	cmd := fmt.Sprintf(format, args...)
	code, r, err := n.ctr.Exec(context.Background(), []string{"sh", "-c", cmd}, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("%s: exec %q: %v", n.name, cmd, err)
	}
	out, _ := io.ReadAll(r)
	if code != 0 {
		t.Fatalf("%s: %q exited %d: %s", n.name, cmd, code, out)
	}
	return string(out)
}

// psk reads the preshared key WireGuard currently holds for the peer. Empty and
// "(none)" both mean "not configured", and the caller must not treat either as a
// key: a rotation check would count "nothing" as a change and report a rotation
// that never happened.
func (n *node) psk(t *testing.T) string {
	t.Helper()
	fields := strings.Fields(n.exec(t, "wg show wg0 preshared-keys"))
	if len(fields) < 2 || fields[1] == "(none)" {
		return ""
	}
	return fields[1]
}

func startLab(t *testing.T) (*node, *node, testcontainers.Container) {
	t.Helper()
	ctx := context.Background()

	net, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	testcontainers.CleanupNetwork(t, net)

	kms := start(t, ctx, testcontainers.ContainerRequest{
		Image:          simulatorImage,
		Networks:       []string{net.Name},
		NetworkAliases: map[string][]string{net.Name: {"qkd-simulator"}},
		Env:            map[string]string{"LISTEN": "0.0.0.0:8080", "DEBUG": "true"},
		WaitingFor:     wait.ForLog("[CONF] listen address"),
	})
	t.Logf("KMS simulator listening, DEBUG=true")

	// ci/node-a/start.sh points both nodes at SAE CONSB. These use one SAE each,
	// as ci/local-darwin/run.sh does: both work, and per-node is the honest one.
	// First place to look if the PoC comes back red on QKD.
	a := &node{name: "node-a", wgIP: "172.16.0.1", sae: "CONSA", id: "9998"}
	b := &node{name: "node-b", wgIP: "172.16.0.2", sae: "CONSB", id: "9999"}
	a.peer, b.peer = b, a
	nodes := []*node{a, b}

	for _, n := range nodes {
		n.ctr = start(t, ctx, testcontainers.ContainerRequest{
			Image:          nodeImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {n.name}},
			// ponytail: privileged. Narrow to CAP_NET_ADMIN plus /dev/net/tun
			// once the suite is real; it is one flag against a class of setup
			// failures that all surface as "wg0 does not exist".
			Privileged: true,
		})
	}

	t.Logf("both nodes up on network %s", net.Name)

	// Keys come from the image's own wg, like ci/setup-keys.sh, which keeps this
	// module down to a single dependency.
	for _, n := range nodes {
		n.priv = strings.TrimSpace(n.exec(t, "wg genkey"))
		n.pub = strings.TrimSpace(n.exec(t, "printf '%%s' %q | wg pubkey", n.priv))
	}

	// The tunnel first: Arnika writes the PSK to wg0, so wg0 has to exist before
	// it starts. Same order as ci/node-a/start.sh.
	for _, n := range nodes {
		n.exec(t, `set -e
			printf '%%s' %q > /tmp/wg.key
			ip link add dev wg0 type wireguard
			ip addr add %s/24 dev wg0
			wg set wg0 private-key /tmp/wg.key listen-port %s
			wg set wg0 peer %q allowed-ips %s/32 endpoint %s:%s
			ip link set wg0 up`,
			n.priv, n.wgIP, wgPort, n.peer.pub, n.peer.wgIP, n.peer.name, wgPort)
		t.Logf("%s: wg0 %s/24, peer %s[%s] at %s:%s",
			n.name, n.wgIP, n.peer.name, tail(n.peer.pub), n.peer.name, wgPort)
	}

	// The 60 lines of log merging in ci/local-darwin/run.sh exist to get this,
	// and t.Log gives it for free: the logs that produced a failure, printed with
	// the failure, and nothing at all when the test passes.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, n := range nodes {
			t.Logf("--- %s arnika.log ---\n%s", n.name, n.exec(t, "tail -n 40 /tmp/arnika.log"))
			t.Logf("--- %s wg ---\n%s", n.name, n.exec(t, "wg show wg0"))
		}
	})

	return a, b, kms
}

// startArnika starts a peer on each node. Separate from startLab so the tunnel
// can be put to the test on its own first: the pretest below has to run before
// anything writes a PSK behind its back.
func startArnika(t *testing.T, nodes ...*node) {
	t.Helper()

	// The transport PSK, shared by both peers. ci/node-*/start.sh hardcodes one;
	// a fresh one per run stops a stale copy from ever being why a run passed.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("generate transport PSK: %v", err)
	}
	transportPSK := base64.StdEncoding.EncodeToString(seed[:])

	for _, n := range nodes {
		// nohup, because the exec that starts it returns immediately and a bare
		// background job would go with it.
		n.exec(t, `nohup env \
			LISTEN_ADDRESS=0.0.0.0:%s SERVER_ADDRESS=%s:%s ARNIKA_ID=%s \
			INTERVAL=%s DEBUG=true ARNIKA_PSK=%q \
			KMS_URL=http://qkd-simulator:8080/api/v1/keys/%s \
			WIREGUARD_INTERFACE=wg0 WIREGUARD_PEER_PUBLIC_KEY=%q \
			arnika >> /tmp/arnika.log 2>&1 &`,
			n.id, n.peer.name, n.peer.id, n.id,
			interval, transportPSK, n.sae, n.peer.pub)
		t.Logf("%s: arnika started, ARNIKA_ID=%s SAE=%s INTERVAL=%s peer=%s:%s",
			n.name, n.id, n.sae, interval, n.peer.name, n.peer.id)
	}
}

func start(t *testing.T, ctx context.Context, req testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	// A 1s stop timeout, because PID 1 in these containers is `sleep infinity`
	// and PID 1 gets no default SIGTERM handler: every container would sit out
	// Docker's full 10s grace period and be killed anyway. Nothing here needs a
	// graceful shutdown, the run is over.
	testcontainers.CleanupContainer(t, c, testcontainers.StopTimeout(time.Second))
	if err != nil {
		t.Fatalf("start %v: %v", req.NetworkAliases, err)
	}
	return c
}

// waitFor polls cond once a second until it holds or d elapses, reporting how
// long it took and whether it held at all. Stands in for wait_for in
// ci/local-darwin/run.sh.
func waitFor(d time.Duration, cond func() bool) (time.Duration, bool) {
	began := time.Now()
	for time.Since(began) < d {
		if cond() {
			return time.Since(began).Round(100 * time.Millisecond), true
		}
		time.Sleep(time.Second)
	}
	return d, false
}

// logLines is the current length of the node's Arnika log, to be passed to
// loggedSince as a mark. The log is appended to across a whole run, so an
// assertion about "did it log X" has to mean "since this point" or an earlier
// phase's line answers for this one.
func (n *node) logLines(t *testing.T) int {
	t.Helper()
	var n2 int
	fmt.Sscan(strings.TrimSpace(n.exec(t, "wc -l < /tmp/arnika.log")), &n2)
	return n2
}

// loggedSince reports whether pattern appears in the node's Arnika log after
// line mark.
func (n *node) loggedSince(t *testing.T, mark int, pattern string) bool {
	t.Helper()
	out := n.exec(t, "tail -n +%d /tmp/arnika.log | grep -c %q || true", mark+1, pattern)
	return strings.TrimSpace(out) != "0"
}

// setPSK installs psk for the peer, leaving the rest of the peer's config alone.
func (n *node) setPSK(t *testing.T, psk string) {
	t.Helper()
	n.exec(t, "printf '%%s' %q | wg set wg0 peer %q preshared-key /dev/stdin", psk, n.peer.pub)
}

// resetSession drops the peer and adds it back, which throws away the current
// session so the next packet has to complete a fresh handshake. Without it a
// preshared key cannot be put to the test on demand: a live session survives a
// key change, because the key is only used in the handshake. Same reasoning as
// reset_session in ci/local-darwin/run.sh.
func (n *node) resetSession(t *testing.T, psk string) {
	t.Helper()
	n.exec(t, `set -e
		wg set wg0 peer %q remove
		printf '%%s' %q | wg set wg0 peer %q allowed-ips %s/32 endpoint %s:%s \
			persistent-keepalive 10 preshared-key /dev/stdin`,
		n.peer.pub, psk, n.peer.pub, n.peer.wgIP, n.peer.name, wgPort)
}

// handshaked reports whether the peer has completed a handshake. Right after
// resetSession the timestamp is 0, so this only turns true on a fresh one, which
// is what makes it a verdict on the preshared key in play.
func (n *node) handshaked(t *testing.T) bool {
	t.Helper()
	fields := strings.Fields(n.exec(t, "wg show wg0 latest-handshakes"))
	return len(fields) >= 2 && fields[1] != "0"
}

// waitHandshake pings the peer to provoke a handshake and reports whether one
// completed within d. The ping is only a way to put a packet into the
// interface; its reply is not what is being judged.
func (n *node) waitHandshake(t *testing.T, d time.Duration) bool {
	t.Helper()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); {
		n.exec(t, "ping -c1 -W1 %s > /dev/null 2>&1 || true", n.peer.wgIP)
		if n.handshaked(t) {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

// tail shortens a key to its last 6 characters, the way keytail does in
// ci/local-darwin/run.sh: enough to tell two keys apart in a log line without
// putting whole keys in the output.
func tail(key string) string {
	if len(key) <= 6 {
		return key
	}
	return "…" + key[len(key)-6:]
}

// count reports how many lines of the node's Arnika log match pattern. grep -c
// exits 1 on zero matches and still prints "0", hence the || true.
func (n *node) count(t *testing.T, pattern string) string {
	t.Helper()
	return strings.TrimSpace(n.exec(t, "grep -c %q /tmp/arnika.log || true", pattern))
}

// pretest exercises WireGuard on its own, before Arnika touches anything.
//
// The mismatched-key step is the point of it. Without a check that is known to
// fail on a broken tunnel, every green tick below could be a false pass: a ping
// that succeeds because it never went through wg0 at all looks exactly like a
// working tunnel. This is ci/local-darwin/run.sh's section 2, reduced to the one
// step that establishes that.
func pretest(t *testing.T, a, b *node) {
	t.Helper()

	a.setPSK(t, zeroPSK)
	b.setPSK(t, zeroPSK)
	a.resetSession(t, zeroPSK)
	if !a.waitHandshake(t, 20*time.Second) {
		t.Fatal("no handshake without a preshared key: WireGuard itself is not working")
	}
	t.Log("handshake completed with no preshared key")

	// Only node-b's key is changed, so the two ends hold different keys and the
	// handshake has to fail. If it succeeds, these checks cannot tell a working
	// tunnel from a broken one and everything below is worthless.
	mismatch := make([]byte, 32)
	if _, err := rand.Read(mismatch); err != nil {
		t.Fatalf("generate mismatched key: %v", err)
	}
	b.setPSK(t, base64.StdEncoding.EncodeToString(mismatch))
	a.resetSession(t, zeroPSK)
	if a.waitHandshake(t, 15*time.Second) {
		t.Fatal("the ends handshaked while holding different preshared keys: " +
			"this test cannot tell a working tunnel from a broken one")
	}
	t.Log("mismatched preshared keys break the tunnel, as they must")

	// Back to a defined state for Arnika, which overwrites the key anyway but
	// would otherwise inherit a dead session.
	b.setPSK(t, zeroPSK)
	a.resetSession(t, zeroPSK)
}

// TestArnika is ci/verify-keys.sh with the pretest ci/local-darwin/run.sh puts
// in front of it: prove the tunnel check can fail, then let Arnika rotate the
// PSK and watch both ends stay in step.
func TestArnika(t *testing.T) {
	a, b, kms := startLab(t)

	if !t.Run("pretest", func(t *testing.T) { pretest(t, a, b) }) {
		t.Fatal("WireGuard is not working on its own, Arnika was not tested")
	}

	startArnika(t, a, b)

	var psk string
	t.Run("both ends install the same PSK", func(t *testing.T) {
		// Two reads straddling a rotation give one mismatched snapshot that is
		// not a real failure, so this polls for agreement instead of asserting
		// on the first pair it sees.
		var pa, pb string
		began := time.Now()
		for deadline := began.Add(90 * time.Second); time.Now().Before(deadline); {
			pa, pb = a.psk(t), b.psk(t)
			t.Logf("  %5s  node-a %-7s node-b %-7s",
				time.Since(began).Round(100*time.Millisecond), tail(pa), tail(pb))
			if pa != "" && pa == pb {
				break
			}
			time.Sleep(2 * time.Second)
		}
		switch {
		case pa == "" || pb == "":
			// Stop the whole test. Everything below compares against this key,
			// and a rotation check would count any key at all as a change from
			// nothing, reporting a rotation that never happened.
			t.Fatalf("no PSK installed within 90s: node-a=%q node-b=%q", pa, pb)
		case pa != pb:
			t.Fatalf("ends hold different PSKs: node-a=%q node-b=%q", pa, pb)
		}
		psk = pa
		t.Logf("both ends hold %s after %s", psk, time.Since(began).Round(100*time.Millisecond))
	})
	if psk == "" {
		t.FailNow()
	}

	t.Run("the PSK rotates in step", func(t *testing.T) {
		prev := psk
		for cycle := 1; cycle <= cycles; cycle++ {
			var cur, other string
			began := time.Now()
			for deadline := began.Add(30 * time.Second); time.Now().Before(deadline); {
				if cur = a.psk(t); cur != "" && cur != prev {
					break
				}
				time.Sleep(time.Second)
			}
			if cur == "" || cur == prev {
				t.Fatalf("cycle %d/%d: the PSK did not change within 30s (still %s)",
					cycle, cycles, tail(prev))
			}
			if other = b.psk(t); cur != other {
				t.Fatalf("cycle %d/%d: the ends diverged, node-a %s, node-b %s",
					cycle, cycles, tail(cur), tail(other))
			}
			t.Logf("cycle %d/%d: rotated to %s after %s, both ends match",
				cycle, cycles, tail(cur), time.Since(began).Round(100*time.Millisecond))
			prev = cur
		}
	})

	// The contract under test, and the only place the three MODES differ: in the
	// happy path they all behave identically, so a mode only shows its hand when
	// a key source disappears.
	//
	// This runs in the default MODE, QkdAndPqcRequired, which requires QKD. A
	// required source going away does not freeze the PSK, it invalidates the
	// tunnel: main.go answers with "[STOP] configure random PSK to invalidate
	// WireGuard session", so each end lands on its own random key and they
	// diverge. Fail-closed, and the same thing source_check asserts with
	// psks_differ in ci/local-darwin/run.sh.
	// ponytail: hardcoded to the default mode's contract. Becomes a table over
	// MODES, keyed on IsQKDRequired/IsPQCRequired, when the matrix lands.
	t.Run("QKD gone: the tunnel is invalidated, then recovers", func(t *testing.T) {
		ctx := context.Background()
		before := a.psk(t)
		mark := a.logLines(t)

		stopTimeout := time.Second
		if err := kms.Stop(ctx, &stopTimeout); err != nil {
			t.Fatalf("stop the KMS: %v", err)
		}
		// The false pass run.sh guards with kmsdown-noreq: if anything is still
		// serving QKD, every verdict below is meaningless.
		if kms.IsRunning() {
			t.Fatal("the KMS container is still running, so this check would prove nothing")
		}
		t.Log("KMS stopped, no QKD reachable for either peer")

		// The pretest established that different keys break the tunnel, so
		// divergence here *is* the proof that the tunnel is dead.
		took, ok := waitFor(25*time.Second, func() bool {
			pa, pb := a.psk(t), b.psk(t)
			return pa != "" && pb != "" && pa != pb
		})
		if !ok {
			t.Errorf("both ends stayed on one key without QKD; MODE=QkdAndPqcRequired must invalidate the tunnel")
		} else {
			t.Logf("ends invalidated onto different keys after %s, node-a %s, node-b %s",
				took, tail(a.psk(t)), tail(b.psk(t)))
		}

		// Not a tautology next to the check above: it proves Arnika refused on
		// purpose because its mode said so, rather than the keys drifting apart
		// for some unrelated reason.
		if took, ok := waitFor(10*time.Second, func() bool {
			return a.loggedSince(t, mark, "no QKD key received")
		}); !ok {
			t.Error("node-a never logged \"no QKD key received\", so the divergence was not a mode decision")
		} else {
			t.Logf("node-a logged the decision after %s: mode requires QKD, none received", took)
		}

		if err := kms.Start(ctx); err != nil {
			t.Fatalf("restart the KMS: %v", err)
		}
		t.Log("KMS back up")

		// Recovery is both ends agreeing again on a key that is not the one
		// they started from, which is psks_agree_new in run.sh.
		took, ok = waitFor(60*time.Second, func() bool {
			pa, pb := a.psk(t), b.psk(t)
			return pa != "" && pa == pb && pa != before
		})
		if !ok {
			t.Errorf("the pair did not get back in step within 60s of the KMS returning: node-a %s, node-b %s",
				tail(a.psk(t)), tail(b.psk(t)))
		} else {
			t.Logf("both ends back in step after %s on %s", took, tail(a.psk(t)))
		}
	})

	t.Run("the tunnel carries traffic", func(t *testing.T) {
		// A real reply, unlike ci/local-darwin/run.sh, which has to read
		// transfer counters because both of its ends sit on one host. These are
		// separate containers, so a reply that comes back is proof that both
		// directions decrypted.
		out := a.exec(t, "ping -c3 -W2 %s", b.wgIP)
		if !strings.Contains(out, "3 received") {
			t.Errorf("tunnel does not carry traffic after %d rotations:\n%s", cycles, out)
		}
		t.Logf("tunnel %s -> %s:\n%s", a.wgIP, b.wgIP, out)
	})

	// What each peer actually did, counted from its own log. Mirrors the
	// per-mode log summary at the end of run_mode in ci/local-darwin/run.sh.
	for _, n := range []*node{a, b} {
		t.Logf("%s: %s PQC exchanges, %s PSK writes, %s warnings/errors", n.name,
			n.count(t, "agreed a fresh PQC key"),
			n.count(t, "PSK configured on WireGuard interface"),
			n.count(t, `level=WARN\|level=ERROR`))
	}
}
