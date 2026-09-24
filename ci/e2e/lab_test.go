// Package e2e runs Arnika end to end in containers, against whatever Docker the
// machine has. It replaces ci/clab-ci.yaml plus ci/verify-keys.sh with a suite
// that runs the same way locally and in CI; containerlab cannot, being
// Linux-only.
//
//	cd ci/e2e && go test -v -timeout 15m ./...
//
// A module of its own, so testcontainers and its dependency tree stay out of
// Arnika's go.mod. That also keeps it out of the root module's ./... , so no
// build tag is needed to hide it from `go test ./...`.
//
// It is ci/local-darwin/run.sh in Go: the WireGuard pre-test, the rotation
// cycles, the three missing-source faults with their recoveries and the
// deliberate desync, once per MODE. The numbered checks there map onto subtest
// names here, and the README's section x.n numbering onto MODE/name.
//
// The three modes run as parallel subtests, one lab each: they share nothing, a
// lab being a network, a KMS and two nodes of its own, and in parallel a whole
// run takes under two minutes rather than the five it takes in turn. The cost is
// that `go test -v` interleaves the three, one "=== NAME" line per switch, which
// is why every line this suite prints carries its lab's name in its own colour.
// For one mode after the other instead, with no interleaving at all:
//
//	go test -v -parallel 1 -timeout 15m ./...
//
// One Docker network with DNS aliases, not the three point-to-point links
// clab-ci.yaml builds: PSK convergence does not care which link carried the
// traffic, and Arnika resolves hostnames (net.ResolveUDPAddr in udpserver.go),
// so the whole addressing scheme collapses to three names.
// ponytail: single network. Split into one network per link when a test needs
// to prove node-b cannot reach node-a's KMS leg.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tclog "github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// Matches ci/node-a/start.sh, so a failure is never down to a different
	// rotation interval than the suite it reproduces. A Duration, not a string,
	// because the tests wait in multiples of it; %s renders it back as "5s" for
	// Arnika's INTERVAL.
	interval = 5 * time.Second
	wgPort   = "51820"

	simulatorImage = "qkd-simulator:e2e"
	nodeImage      = "arnika-node:e2e"

	// How many rotations to watch, as CYCLES does in ci/local-darwin/run.sh.
	cycles = 3

	// A frozen KMS never answers, so a fetch fails only once the HTTP client
	// gives up: at the 10s default with 5 retries that is over a minute per
	// fetch, far past the windows the fault checks wait out. The pair is
	// restarted with these instead, roughly 2s per fetch. The stopped-KMS phase
	// needs no override, a refused connection returns at once.
	frozenKMSEnv = "KMS_HTTP_TIMEOUT=1s KMS_BACKOFF_MAX_RETRIES=1"

	// Every PQC attempt then dies on its deadline waiting for the peer's answer,
	// which has to cross the socket, so the initiating peer never agrees a key
	// and GetNewKey has nothing to return. 1ns and not 1ms because an attempt
	// between two containers can finish inside a millisecond.
	noPQCEnv = "PQC_ROUND_TIMEOUT=1ns"
)

// zeroPSK is 32 zero bytes, which is how WireGuard spells "no preshared key".
var zeroPSK = base64.StdEncoding.EncodeToString(make([]byte, 32))

// A mode is a statement about which key source may be absent, from
// IsQKDRequired/IsPQCRequired in config/config.go. Arnika answers a missing
// *required* source by invalidating the tunnel with a random PSK (setPSK in
// main.go), and each end draws its own, so the two ends landing on different
// keys is the signal. A missing *optional* source must instead leave rotation
// running, both ends in step on the other source.
//
// EitherQkdOrPqcRequired is left out for the same reason MODES in
// ci/local-darwin/run.sh leaves it out: both sources are optional to it, so the
// fault checks have nothing to assert for it that the other three do not cover.
type mode struct {
	name        string
	qkdRequired bool
	pqcRequired bool
	color       string
}

var modes = []mode{
	{"QkdAndPqcRequired", true, true, cyan},
	{"AtLeastQkdRequired", true, false, yellow},
	{"AtLeastPqcRequired", false, true, magenta},
}

// One colour per mode, so a line can be traced back to its lab while the three
// run at once: the interleaving of parallel subtests is what makes the output
// hard to follow, not the lines themselves. NO_COLOR turns it off
// (https://no-color.org), and so does a terminal that says it cannot colour.
const (
	cyan    = "\033[36m"
	yellow  = "\033[33m"
	magenta = "\033[35m"
	green   = "\033[32m"
	red     = "\033[31m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	reset   = "\033[0m"
)

var colorless = os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"

// c is a style, or nothing at all where colour is unwanted. Every escape goes
// through it, so NO_COLOR takes the whole palette out in one place.
func c(style string) string {
	if colorless {
		return ""
	}
	return style
}

// prefix names the lab on every line it prints, in its own colour and padded so
// the narration lines up in one column whoever wrote it.
func (m mode) prefix() string {
	name := fmt.Sprintf("%-10s ", strings.TrimSuffix(m.name, "Required"))
	return c(m.color) + name + c(reset)
}

// decision is the line Arnika logs about its own reasoning when source is gone,
// from the branches of setPSK. The PSK state alone cannot say the mode reasoned
// correctly, only that something happened, so every fault check asserts both.
//
// The QKD-optional case comes from runPQCSetPSKLoop rather than from setPSK's
// own fallback warning: with QKD optional and PQC on, shouldSetPSKOnQKDFailure
// is false, so a failed fetch never reaches setPSK at all and the PQC-only loop
// is what carries the rotation.
func (m mode) decision(source string) string {
	switch {
	case source == "qkd" && m.qkdRequired:
		return "no QKD key received"
	case source == "qkd":
		return "no QKD key, installing a PQC-only PSK"
	case m.pqcRequired:
		return "failed to retrieve the PQC key"
	default:
		return "no PQC key, falling back to the QKD key"
	}
}

func (m mode) requires(source string) bool {
	if source == "qkd" {
		return m.qkdRequired
	}
	return m.pqcRequired
}

// TestMain builds the two images the lab runs on, reusing ci/Dockerfile.node and
// ci/Dockerfile.simulator unchanged.
//
// Through the docker CLI, not testcontainers' own FromDockerfile: that posts the
// build context to the engine's legacy build endpoint, which fails with
// "NotFound: content digest ... not found" once Docker uses the containerd image
// store (`docker info` reporting io.containerd.snapshotter.v1, the default on
// Docker Desktop 29). The CLI goes through buildkit. Building here rather than
// per container request also means one build for every lab, and buildkit's
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

	// testcontainers narrates every container it touches, five stderr lines each
	// and a banner on top, which is a hundred lines of docker bookkeeping around
	// the handful of lines that say what the lab did. Its own log goes nowhere,
	// and each step reports itself in one line through t.Log instead.
	tclog.SetDefault(tclog.NewNoopLogger())

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

// A lab is one mode's world: its own network, KMS and pair of nodes, so three of
// them can run at once without sharing a name, an address or a key.
type lab struct {
	mode mode
	// root is the mode's own *testing.T. Containers are torn down on it and not
	// on the caller's: a KMS replaced inside a subtest has to outlive that
	// subtest, and registering the cleanup on the subtest's t would take the new
	// simulator away with it the moment the phase ended.
	root *testing.T
	net  *testcontainers.DockerNetwork
	kms  testcontainers.Container
	a, b *node
	psk  string // the transport PSK both peers authenticate with
	// prefix tags every line this lab prints, see mode.prefix.
	prefix string
	// buf holds the lines of the phase in progress, see lab.flush.
	buf bytes.Buffer
}

// Lines are collected per lab and written a phase at a time, rather than as
// they happen: three labs printing line by line is what made a parallel run
// unreadable in the first place. A phase is the right unit for it, seconds
// rather than minutes, so a run still shows progress while it goes.
//
// One lab writes its buffer from one goroutine, the mode's own, so the buffer
// needs no lock. The write does: a block can be larger than a pipe writes
// atomically, and two labs flushing at once would tear each other apart.
var flushing sync.Mutex

func (l *lab) print(line string) { l.buf.WriteString(line) }

func (l *lab) flush() {
	if l.buf.Len() == 0 {
		return
	}
	flushing.Lock()
	defer flushing.Unlock()
	os.Stdout.Write(l.buf.Bytes())
	l.buf.Reset()
}

func (l *lab) nodes() []*node { return []*node{l.a, l.b} }

// run executes a shell command in the node and returns its exit code and
// combined output. Multiplexed strips the 8-byte docker stream headers; without
// it every captured string carries control bytes and no comparison holds.
func (n *node) run(t *testing.T, format string, args ...any) (int, string) {
	t.Helper()
	cmd := fmt.Sprintf(format, args...)
	code, r, err := n.ctr.Exec(context.Background(), []string{"sh", "-c", cmd}, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("%s: exec %q: %v", n.name, cmd, err)
	}
	out, _ := io.ReadAll(r)
	return code, string(out)
}

// exec is run for a command that has to succeed.
func (n *node) exec(t *testing.T, format string, args ...any) string {
	t.Helper()
	code, out := n.run(t, format, args...)
	if code != 0 {
		t.Fatalf("%s: %q exited %d: %s", n.name, fmt.Sprintf(format, args...), code, out)
	}
	return out
}

// psk reads the preshared key WireGuard currently holds for the peer. Empty and
// "(none)" both mean "not configured", and the caller must not treat either as a
// key: a rotation check would count "nothing" as a change and report a rotation
// that never happened.
func (n *node) psk(t *testing.T) string {
	t.Helper()
	return n.pskOf(t, n.peer.pub)
}

// pskOf reads the preshared key held for one named peer. By public key and not
// by the first row `wg show` prints: an interface can carry more than one peer,
// which is the whole point of the second-peer phase, and the order of the rows
// is the kernel's to choose.
func (n *node) pskOf(t *testing.T, pub string) string {
	t.Helper()
	out := strings.TrimSpace(n.exec(t,
		"wg show wg0 preshared-keys | awk -v k=%q '$1 == k {print $2}'", pub))
	if out == "(none)" {
		return ""
	}
	return out
}

func startLab(t *testing.T, m mode) *lab {
	t.Helper()
	ctx := context.Background()

	net, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	testcontainers.CleanupNetwork(t, net)

	l := &lab{mode: m, root: t, net: net, prefix: m.prefix()}
	// Registered before anything else, so it runs after every other cleanup:
	// whatever they print, the summary and the log dump of a failure included,
	// is still in the buffer at that point.
	t.Cleanup(l.flush)
	l.rule("lab")
	l.startKMS(t, "")

	// ci/node-a/start.sh points both nodes at SAE CONSB. These use one SAE each,
	// as ci/local-darwin/run.sh does: both work, and per-node is the honest one.
	// First place to look if a run comes back red on QKD.
	l.a = &node{name: "node-a", wgIP: "172.16.0.1", sae: "CONSA", id: "9998"}
	l.b = &node{name: "node-b", wgIP: "172.16.0.2", sae: "CONSB", id: "9999"}
	l.a.peer, l.b.peer = l.b, l.a

	for _, n := range l.nodes() {
		n.ctr = l.start(t, ctx, testcontainers.ContainerRequest{
			Image:          nodeImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {n.name}},
			// ponytail: privileged. Narrow to CAP_NET_ADMIN plus /dev/net/tun
			// once the suite is real; it is one flag against a class of setup
			// failures that all surface as "wg0 does not exist".
			Privileged: true,
		})
	}

	// Keys come from the image's own wg, like ci/setup-keys.sh, which keeps this
	// module down to a single dependency.
	for _, n := range l.nodes() {
		n.priv = strings.TrimSpace(n.exec(t, "wg genkey"))
		n.pub = strings.TrimSpace(n.exec(t, "printf '%%s' %q | wg pubkey", n.priv))
	}

	// The tunnel first: Arnika writes the PSK to wg0, so wg0 has to exist before
	// it starts. Same order as ci/node-a/start.sh.
	for _, n := range l.nodes() {
		n.exec(t, `set -e
			printf '%%s' %q > /tmp/wg.key
			ip link add dev wg0 type wireguard
			ip addr add %s/24 dev wg0
			wg set wg0 private-key /tmp/wg.key listen-port %s
			wg set wg0 peer %q allowed-ips %s/32 endpoint %s:%s
			ip link set wg0 up`,
			n.priv, n.wgIP, wgPort, n.peer.pub, n.peer.wgIP, n.peer.name, wgPort)
	}
	l.step("lab up: node-a[%s] %s and node-b[%s] %s, wg0 on port %s",
		l.a.id, l.a.wgIP, l.b.id, l.b.wgIP, wgPort)

	// The transport PSK, shared by both peers and by every restart within the
	// lab. ci/node-*/start.sh hardcodes one; a fresh one per run stops a stale
	// copy from ever being why a run passed.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("generate transport PSK: %v", err)
	}
	l.psk = base64.StdEncoding.EncodeToString(seed[:])

	// The 60 lines of log merging in ci/local-darwin/run.sh exist to get this,
	// and t.Log gives it for free: the logs that produced a failure, printed with
	// the failure, and nothing at all when the test passes.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, n := range l.nodes() {
			// run and not exec: a failure this early has no Arnika log to show,
			// and a cleanup that fails on that takes the rest of the dump,
			// node-b's included, down with it.
			_, log := n.run(t, "tail -n 40 /tmp/arnika.log")
			_, wg := n.run(t, "wg show wg0")
			l.say("--- %s arnika.log ---\n%s", n.name, log)
			l.say("--- %s wg ---\n%s", n.name, wg)
		}
	})

	return l
}

// startKMS brings up the simulator, optionally with the named SAE frozen: those
// then accept and log every request and never answer one (see KMS.md). FREEZE is
// read once at startup, so switching it is a new container rather than a signal.
//
// The wait strategy is the freeze assertion itself, ci/local-darwin/run.sh's
// x.8: the simulator reports what it froze on its own [CONF] line, and a FREEZE
// value it does not recognise is silently ignored, which would leave a healthy
// KMS behind a check expecting a broken one.
func (l *lab) startKMS(t *testing.T, freeze string) {
	t.Helper()
	summary := freeze
	if summary == "" {
		summary = "none"
	}
	l.kms = l.start(t, context.Background(), testcontainers.ContainerRequest{
		Image:          simulatorImage,
		Networks:       []string{l.net.Name},
		NetworkAliases: map[string][]string{l.net.Name: {"qkd-simulator"}},
		Env:            map[string]string{"LISTEN": "0.0.0.0:8080", "DEBUG": "true", "FREEZE": freeze},
		WaitingFor:     wait.ForLog("frozen SAE=" + summary),
	})
	l.step("KMS up, frozen SAE=%s", summary)
}

// kmsLogged counts what the simulator itself recorded. Its log is the only
// witness to what reached it, which is the point of the frozen phase.
func (l *lab) kmsLogged(t *testing.T, pattern string) int {
	t.Helper()
	r, err := l.kms.Logs(context.Background())
	if err != nil {
		t.Fatalf("read the KMS log: %v", err)
	}
	defer r.Close()
	out, _ := io.ReadAll(r)
	return strings.Count(string(out), pattern)
}

// replaceKMS swaps the simulator for one with a different FREEZE setting.
func (l *lab) replaceKMS(t *testing.T, freeze string) {
	t.Helper()
	if err := l.kms.Terminate(context.Background()); err != nil {
		t.Fatalf("terminate the KMS: %v", err)
	}
	l.startKMS(t, freeze)
}

// startPeers starts a peer on each node, with extra appended to the environment
// verbatim so a phase can shorten a timeout or break a key source. The logs are
// appended to across restarts, like ci/local-darwin/run.sh's, so a mark taken
// before a restart still means "since here".
func (l *lab) startPeers(t *testing.T, extra string) {
	t.Helper()
	for _, n := range l.nodes() {
		l.startPeer(t, n, l.psk, extra)
	}
	started := "peers started, INTERVAL=" + interval.String()
	if extra != "" {
		started += " " + extra
	}
	l.step("%s", started)
}

// startPeer starts one peer with a transport PSK of its own, which is what lets
// a phase give the two ends different ones.
func (l *lab) startPeer(t *testing.T, n *node, psk, extra string) {
	t.Helper()
	// nohup, because the exec that starts it returns immediately and a bare
	// background job would go with it.
	n.exec(t, `nohup env \
		LISTEN_ADDRESS=0.0.0.0:%s SERVER_ADDRESS=%s:%s ARNIKA_ID=%s \
		INTERVAL=%s MODE=%s LOG_LEVEL=debug ARNIKA_PSK=%q \
		KMS_URL=http://qkd-simulator:8080/api/v1/keys/%s \
		WIREGUARD_INTERFACE=wg0 WIREGUARD_PEER_PUBLIC_KEY=%q \
		%s \
		arnika >> /tmp/arnika.log 2>&1 &`,
		n.id, n.peer.name, n.peer.id, n.id,
		interval, l.mode.name, psk, n.sae, n.peer.pub, extra)
}

// running reports whether a live arnika is in the node. It reads ps rather than
// pgrep because a stopped one lingers: PID 1 here is `sleep infinity`, which
// never reaps an orphan, so every exited arnika stays behind as a zombie and
// answers pgrep for the rest of the run. Only the state column tells the two
// apart.
func (n *node) running(t *testing.T) bool {
	t.Helper()
	code, _ := n.run(t, `ps -o stat,comm | awk '$2 == "arnika" && $1 !~ /Z/ {live = 1} END {exit !live}'`)
	return code == 0
}

// stopPeers takes both peers away so a fault or a desync can be observed at all:
// at INTERVAL a running pair heals one faster than a check can measure it.
func (l *lab) stopPeers(t *testing.T) {
	t.Helper()
	for _, n := range l.nodes() {
		n.run(t, "pkill -x arnika") // exits 1 when there is nothing to signal
		if _, ok := waitFor(10*time.Second, func() bool { return !n.running(t) }); !ok {
			t.Fatalf("%s: arnika is still running 10s after SIGTERM", n.name)
		}
	}
	l.step("peers stopped")
}

func (l *lab) start(t *testing.T, ctx context.Context, req testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	// A 1s stop timeout, because PID 1 in these containers is `sleep infinity`
	// and PID 1 gets no default SIGTERM handler: every container would sit out
	// Docker's full 10s grace period and be killed anyway. Nothing here needs a
	// graceful shutdown, the run is over.
	testcontainers.CleanupContainer(l.root, c, testcontainers.StopTimeout(time.Second))
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

// agreeNew reports whether both ends hold one key that is not before, which is
// psks_agree_new in ci/local-darwin/run.sh: the shape of every recovery.
func (l *lab) agreeNew(t *testing.T, before string) bool {
	pa, pb := l.a.psk(t), l.b.psk(t)
	return pa != "" && pa == pb && pa != before
}

// diverged reports whether the two ends hold different keys, which is how an
// invalidation shows: each end draws its own random PSK.
func (l *lab) diverged(t *testing.T) bool {
	pa, pb := l.a.psk(t), l.b.psk(t)
	return pa != "" && pb != "" && pa != pb
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
	out := strings.TrimSpace(n.exec(t,
		"wg show wg0 latest-handshakes | awk -v k=%q '$1 == k {print $2}'", n.peer.pub))
	return out != "" && out != "0"
}

// waitHandshake pings the peer to provoke a handshake and reports whether one
// completed within d. The ping is only a way to put a packet into the
// interface; its reply is not what is being judged.
func (n *node) waitHandshake(t *testing.T, d time.Duration) bool {
	t.Helper()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); {
		n.run(t, "ping -c1 -W1 %s", n.peer.wgIP)
		if n.handshaked(t) {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

// pings reports whether the peer answers over the tunnel. A real reply, unlike
// ci/local-darwin/run.sh, which has to read transfer counters because both of
// its ends sit on one host. These are separate containers, so a reply that comes
// back is proof that both directions decrypted.
func (n *node) pings(t *testing.T) (bool, string) {
	t.Helper()
	code, out := n.run(t, "ping -c3 -W2 %s", n.peer.wgIP)
	return code == 0 && strings.Contains(out, "3 received"), out
}

// say prints one line of narration, tagged with the lab and indented to sit
// where the testing package puts its own log lines.
//
// Straight to stdout, and not through t.Log or t.Output, for two reasons. t.Log
// stamps "lab_test.go:123:" on every line, which is worth having on a failure
// and in the way of a narration: these lines say what the lab did, not where the
// code that did it lives. And both of them escape control bytes on the way out
// (escapeMarkers in testing.go, Go 1.26), which turns every ESC into two and
// leaves a terminal printing "[36m" instead of colouring the line.
//
// The cost is that these lines belong to the package rather than to the subtest
// that wrote them, so -json output carries them without a Test field. The lab
// name each one leads with is what makes that readable anyway.
func (l *lab) say(format string, args ...any) {
	l.print("    " + l.prefix + "  " + fmt.Sprintf(format, args...) + "\n")
}

// step is something the lab did, dimmed: it is the background a verdict stands
// against, not a result.
func (l *lab) step(format string, args ...any) {
	l.print("    " + l.prefix + c(dim) + "· " + fmt.Sprintf(format, args...) + c(reset) + "\n")
}

// ok is a check that held. The tick is what the eye looks for, so the text next
// to it stays plain.
func (l *lab) ok(format string, args ...any) {
	l.print("    " + l.prefix + c(green) + "✓ " + c(reset) + fmt.Sprintf(format, args...) + "\n")
}

// rule heads a phase, so a run reads as a sequence of phases rather than as one
// stream of lines.
func (l *lab) rule(name string) {
	if fill := 58 - len(name); fill > 0 {
		name += " " + strings.Repeat("─", fill)
	}
	l.print("    " + l.prefix + c(bold) + "── " + name + c(reset) + "\n")
}

// phase runs one named subtest under a rule of its own.
func (l *lab) phase(t *testing.T, name string, fn func(t *testing.T)) bool {
	return t.Run(name, func(t *testing.T) {
		defer l.flush()
		l.rule(name)
		fn(t)
	})
}

// faultPhase is a phase that runs against a deliberately broken state. It is
// marked the way ci/local-darwin/run.sh marks it, because the distinction
// matters when reading a result: these pass because something is broken, and
// the warnings and errors they leave in Arnika's log are the point of them.
func (l *lab) faultPhase(t *testing.T, name string, fn func(t *testing.T)) bool {
	return t.Run(name, func(t *testing.T) {
		defer l.flush()
		l.rule(name + " [intentional]")
		fn(t)
	})
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

// randomPSK is a key no peer can hold, for the pre-test's mismatch and the
// desync.
func randomPSK(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate a random key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// pretest exercises WireGuard on its own, before Arnika touches anything. It is
// section 2 of ci/local-darwin/run.sh.
//
// The mismatched-key step is the point of it. Without a check that is known to
// fail on a broken tunnel, every green tick below could be a false pass: a ping
// that succeeds because it never went through wg0 at all looks exactly like a
// working tunnel.
func (l *lab) pretest(t *testing.T) {
	t.Helper()
	a, b := l.a, l.b

	a.setPSK(t, zeroPSK)
	b.setPSK(t, zeroPSK)
	a.resetSession(t, zeroPSK)
	if !a.waitHandshake(t, 20*time.Second) {
		t.Fatal("no handshake without a preshared key: WireGuard itself is not working")
	}
	if ok, out := a.pings(t); !ok {
		t.Fatalf("no payload crosses the tunnel without a preshared key:\n%s", out)
	}
	l.ok("handshake and payload with no preshared key")

	// The same key on both ends: still a working tunnel, and the control for the
	// mismatch below, which differs from it in one thing only.
	shared := randomPSK(t)
	a.setPSK(t, shared)
	b.setPSK(t, shared)
	a.resetSession(t, shared)
	if !a.waitHandshake(t, 20*time.Second) {
		t.Fatalf("no handshake with a matching preshared key %s on both ends", tail(shared))
	}
	if ok, out := a.pings(t); !ok {
		t.Fatalf("no payload crosses with a matching preshared key:\n%s", out)
	}
	l.ok("handshake and payload with %s on both ends", tail(shared))

	// Only node-b's key is changed, so the two ends hold different keys and the
	// handshake has to fail. If it succeeds, these checks cannot tell a working
	// tunnel from a broken one and everything below is worthless.
	b.setPSK(t, randomPSK(t))
	a.resetSession(t, shared)
	if a.waitHandshake(t, 15*time.Second) {
		t.Fatal("the ends handshaked while holding different preshared keys: " +
			"this test cannot tell a working tunnel from a broken one")
	}
	if ok, out := a.pings(t); ok {
		t.Fatalf("payload decrypted at the far end while the keys differ, "+
			"so a broken tunnel is invisible here:\n%s", out)
	}
	l.ok("mismatched preshared keys break the tunnel, as they must")

	// Back to a defined state for Arnika, which overwrites the key anyway but
	// would otherwise inherit a dead session.
	b.setPSK(t, zeroPSK)
	a.setPSK(t, zeroPSK)
	a.resetSession(t, zeroPSK)
	if !a.waitHandshake(t, 20*time.Second) {
		t.Fatal("the tunnel did not come back after the pre-test")
	}
	l.ok("the tunnel is up again and Arnika can take over")
}

// sourceCheck takes one key source away and holds the mode to its contract, then
// gives the source back and requires the pair to recover. It is x.8 to x.18 of
// ci/local-darwin/run.sh.
//
// how says which of the two QKD faults this is, and they are different faults:
//
//	freeze - the simulator is replaced with one whose SAE are frozen. It accepts
//	         and logs every request as usual and never answers one, so a fetch
//	         fails on the client's own timeout. That is a hung KMS, or one whose
//	         key pool is exhausted and never resolves, and the requests Arnika
//	         made into the failure are all in the KMS log as [FREEZE].
//	down   - the simulator is stopped. Nothing is listening, so every connection
//	         is refused outright and no request ever reaches a KMS: the KMS is
//	         not merely unresponsive, it is absent. It fails fast rather than on
//	         a timeout, which is a different code path in kmsRequest.
//
// Both must produce the same answer from the mode, and neither is a substitute
// for the other: freeze is the one that leaves a KMS-side record, down is the
// one that proves the mode does not need a KMS to be reachable to decide.
//
// PQC is taken away with PQC_ROUND_TIMEOUT=1ns. The responding peer may still
// answer a frame or two of its own, since both its frames are already queued
// when it starts, so it can hold a key the initiator never confirmed. That is
// why the log is read on node-a: its even ARNIKA_ID makes it the PQC initiator
// (repositories/pqc-hpke.go), and therefore the end whose decision is
// deterministic. Swap the IDs' parity and this has to follow.
func (l *lab) sourceCheck(t *testing.T, source, how string) {
	ctx := context.Background()
	l.stopPeers(t)
	// With the peers down, so a rotation cannot slip between this read and the
	// stop: see wrongPSKCheck, where the same race turns into a false failure.
	before := l.a.psk(t)
	mark := l.a.logLines(t)

	extra := ""
	switch {
	case how == "down":
		stopTimeout := time.Second
		if err := l.kms.Stop(ctx, &stopTimeout); err != nil {
			t.Fatalf("stop the KMS: %v", err)
		}
		l.step("KMS stopped")
	case source == "qkd":
		l.replaceKMS(t, "CONSA,CONSB")
		extra = frozenKMSEnv
	default:
		extra = noPQCEnv
	}
	l.startPeers(t, extra)

	required := l.mode.requires(source)
	if required {
		// The pre-test established that different keys break the tunnel, so
		// divergence here is the proof that the tunnel is dead.
		if took, ok := waitFor(25*time.Second, func() bool { return l.diverged(t) }); !ok {
			t.Errorf("no %s and %s requires it, yet both ends stayed on one key: the tunnel was not invalidated",
				source, l.mode.name)
		} else {
			l.ok("ends invalidated onto different keys after %s, node-a %s, node-b %s",
				took, tail(l.a.psk(t)), tail(l.b.psk(t)))
		}
	} else {
		if took, ok := waitFor(25*time.Second, func() bool { return l.agreeNew(t, before) }); !ok {
			t.Errorf("no %s and %s has it optional, yet the pair stopped rotating in step: node-a %s, node-b %s",
				source, l.mode.name, tail(l.a.psk(t)), tail(l.b.psk(t)))
		} else {
			l.ok("rotation carried on without %s, both ends in step on %s after %s",
				source, tail(l.a.psk(t)), took)
		}
	}

	// Polled, not grepped once: Arnika logs the decision just before it writes
	// the PSK, so the PSK can be visible here a moment before the line that
	// explains it. Not a tautology next to the check above either: it proves
	// Arnika acted because its mode said so, rather than the keys drifting apart
	// for some unrelated reason.
	pattern := l.mode.decision(source)
	if took, ok := waitFor(10*time.Second, func() bool { return l.a.loggedSince(t, mark, pattern) }); !ok {
		t.Errorf("node-a never logged %q, so what happened was not a mode decision", pattern)
	} else {
		l.ok("node-a logged the decision after %s: %q", took, pattern)
	}

	if how == "freeze" {
		// The reason QKD gets two faults rather than one: a frozen KMS is the
		// one that keeps a record of the requests Arnika made into the failure.
		// Without reading it back, this phase cannot tell "the peers asked and
		// got nothing" from "the peers never asked", and those are different
		// failures with the same PSK state.
		if requests := l.kmsLogged(t, "[FREEZE]"); requests == 0 {
			t.Error("the frozen KMS logged no request, so nothing says the peers ever reached it")
		} else {
			l.ok("the frozen KMS accepted %d request(s) and answered none", requests)
		}
	}

	// Checked at the end of the window rather than the start, so it covers the
	// whole phase, and not the tautology it looks like: a stale simulator from
	// an earlier run holding the alias would leave the pair quietly talking to a
	// KMS while this check believed there was none, and every verdict above
	// would then mean nothing.
	if how == "down" {
		if code, out := l.a.run(t, "curl -s -m 2 -o /dev/null -w '%%{http_code}' http://qkd-simulator:8080/api/v1/keys/%s/status", l.a.sae); code == 0 {
			t.Errorf("something answered at qkd-simulator with the KMS stopped (HTTP %s)", strings.TrimSpace(out))
		} else {
			l.ok("nothing answered at qkd-simulator for the whole window")
		}
	}

	l.stopPeers(t)
	switch {
	case how == "down":
		if err := l.kms.Start(ctx); err != nil {
			t.Fatalf("restart the KMS: %v", err)
		}
		l.step("KMS back")
	case source == "qkd":
		l.replaceKMS(t, "")
	}
	l.startPeers(t, "")

	if took, ok := waitFor(45*time.Second, func() bool { return l.agreeNew(t, before) }); !ok {
		t.Errorf("the pair did not get back in step once %s was available again: node-a %s, node-b %s",
			source, tail(l.a.psk(t)), tail(l.b.psk(t)))
	} else {
		l.ok("both ends back in step after %s on %s", took, tail(l.a.psk(t)))
	}
}

// desyncCheck is the intentional failure test, x.19 to x.23. Without it a green
// run only shows that the checks can pass, not that they would notice a dead
// tunnel, which is the failure the suite exists to catch. The pre-test proves
// the apparatus works before Arnika starts; this proves it still works with
// Arnika driving, in this mode.
//
// The peers are stopped first because at INTERVAL a running pair resyncs faster
// than the check can measure, and started again afterwards because putting it
// back is the other half of the test: it also covers a peer starting up against
// an interface whose key is wrong.
func (l *lab) desyncCheck(t *testing.T) {
	bad := randomPSK(t)

	l.stopPeers(t)
	before := l.a.psk(t)
	l.b.setPSK(t, bad)
	l.a.resetSession(t, before)
	l.step("node-a keeps %s, node-b now holds %s", tail(before), tail(bad))

	if l.a.waitHandshake(t, 12*time.Second) {
		t.Error("the two ends handshaked while holding different keys")
	} else {
		l.ok("no handshake while the keys differ, the break is real")
	}
	if ok, out := l.a.pings(t); ok {
		t.Errorf("payload decrypted on a desynced tunnel, so a break is invisible here:\n%s", out)
	}

	l.startPeers(t, "")
	took, ok := waitFor(45*time.Second, func() bool { return l.agreeNew(t, bad) })
	if !ok {
		t.Errorf("the peers did not resync a PSK written behind their backs: node-a %s, node-b %s",
			tail(l.a.psk(t)), tail(l.b.psk(t)))
		return
	}
	l.ok("both ends back on one key after %s (%s)", took, tail(l.a.psk(t)))
	if !l.a.waitHandshake(t, 25*time.Second) {
		t.Error("the keys match again but there was no handshake in 25s")
	}
}

// secondPeerCheck puts a second peer on node-a's interface, which is the shape
// that broke the netlink key writer in #42: the lookup returned an error on the
// first peer that did not match the configured one, so it passed only on an
// interface carrying exactly one peer. A node with two neighbours could not have
// its PSK written at all, and every rotation ended in an invalidated tunnel.
//
// Nothing else in this suite can see that, because a lab node has one peer and
// the broken form was right by coincidence there. The decoy has no endpoint and
// an address of its own, so it changes nothing but the length of the peer list.
func (l *lab) secondPeerCheck(t *testing.T) {
	decoy := strings.TrimSpace(l.a.exec(t, "wg genkey | wg pubkey"))
	mark := l.a.logLines(t)
	l.a.exec(t, "wg set wg0 peer %q allowed-ips 172.16.0.99/32", decoy)
	defer l.a.exec(t, "wg set wg0 peer %q remove", decoy)
	// Read with the decoy already in place: the peers keep rotating here, and a
	// baseline from before it would let a write that never saw the second peer
	// satisfy the check.
	before := l.a.psk(t)
	l.step("node-a's wg0 carries a second peer, %s", tail(decoy))

	if took, ok := waitFor(4*interval, func() bool { return l.agreeNew(t, before) }); !ok {
		t.Errorf("the PSK stopped rotating with a second peer on the interface: node-a %s, node-b %s",
			tail(l.a.psk(t)), tail(l.b.psk(t)))
	} else {
		l.ok("the PSK still rotates with two peers on the interface, %s after %s",
			tail(l.a.psk(t)), took)
	}

	// The specific failure of #42, in Arnika's own words, rather than only its
	// consequence above: SetPSK returning "peer not found" surfaces here.
	if l.a.loggedSince(t, mark, "failed to configure the PSK on the WireGuard interface") {
		t.Error("node-a could not write the PSK while a second peer was on the interface")
	}

	// And it has to land on the peer it names, not on whichever comes first.
	if psk := l.a.pskOf(t, decoy); psk != "" {
		t.Errorf("the second peer was given the preshared key %s, so the write went to the wrong peer", tail(psk))
	} else {
		l.ok("the second peer was left without a key of its own")
	}
}

// wrongPSKCheck starts one peer with a transport PSK the other does not share.
//
// ARNIKA_PSK authenticates the peer protocol: every packet carries an HMAC over
// it, and transport.Serve drops what does not verify before decrypting anything
// (auth.UnmarshalPacket in server.go). So a peer that does not hold it can carry
// neither a key_id nor a PQC frame, and the two ends can never arrive at one
// key. That is the security property of the transport, and this is the only
// check in the suite that puts it to the test rather than assuming it.
//
// The assertion is that the ends never agree, not that the victim's key stands
// still: node-b keeps rotating on its own throughout, either on its own QKD key
// or onto a random one where the mode invalidates. What must not happen is the
// two of them meeting on one key.
func (l *lab) wrongPSKCheck(t *testing.T) {
	l.stopPeers(t)
	// The baseline is read with the peers down, never while they still run. A
	// rotation landing between the read and the stop would leave the pair
	// agreeing on a key this phase then counts as fresh, and the check below
	// would fail on an agreement reached before the impostor even started. It
	// is a narrow window on an idle machine and a wide one under load, which is
	// exactly how it showed up in CI and not here.
	//
	// Both ends still hold the key they recovered onto in the phase before, so
	// the question is not whether they agree now but whether they ever arrive
	// at a fresh agreement while one of them cannot authenticate.
	before := l.a.psk(t)
	mark := l.b.logLines(t)
	l.startPeer(t, l.a, randomPSK(t), "")
	l.startPeer(t, l.b, l.psk, "")
	l.step("node-a restarted with a transport PSK node-b does not share")

	window := 3 * interval
	switch took, agreed := waitFor(window, func() bool { return l.agreeNew(t, before) }); {
	case agreed:
		t.Errorf("the ends met on the fresh key %s after %s although node-a cannot authenticate to node-b",
			tail(l.a.psk(t)), took)
	case !l.diverged(t):
		// Both ends keep rotating on their own throughout, on their own QKD key
		// or onto a random one where the mode invalidates, so they have to come
		// apart. Both still holding the key from the phase before would mean
		// neither wrote anything, and then nothing above was put to the test.
		t.Errorf("neither end moved in %s, so nothing here says they could not sync: both hold %s",
			window, tail(before))
	default:
		l.ok("the ends came apart and never met on a fresh key in %s, node-a %s, node-b %s",
			window, tail(l.a.psk(t)), tail(l.b.psk(t)))
	}

	// Not the same statement: above says they did not agree, this says node-b
	// refused on purpose. Without it a pair that simply never talked, a crashed
	// peer or a wrong port, would pass the check above.
	if _, ok := waitFor(10*time.Second, func() bool {
		return l.b.loggedSince(t, mark, "reason=authentication")
	}); !ok {
		t.Error("node-b never rejected a packet for authentication, so nothing says it was asked")
	} else {
		l.ok("node-b rejected what node-a sent: packet rejected, reason=authentication")
	}

	l.stopPeers(t)
	l.startPeers(t, "")
	if took, ok := waitFor(45*time.Second, func() bool { return l.agreeNew(t, before) }); !ok {
		t.Errorf("the pair did not come back together on the shared transport PSK: node-a %s, node-b %s",
			tail(l.a.psk(t)), tail(l.b.psk(t)))
	} else {
		l.ok("both ends back on one key after %s with the shared PSK restored", took)
	}
}

// TestArnika runs the whole suite once per MODE: prove the tunnel check can
// fail, let Arnika rotate the PSK, take each key source away in turn, then break
// the tunnel on purpose and require the pair to put it back.
func TestArnika(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			testMode(t, m)
		})
	}
}

func testMode(t *testing.T, m mode) {
	l := startLab(t, m)

	if !l.phase(t, "pretest", l.pretest) {
		t.Fatal("WireGuard is not working on its own, Arnika was not tested")
	}

	l.startPeers(t, "")

	var psk string
	l.phase(t, "both ends install the same PSK", func(t *testing.T) {
		// Two reads straddling a rotation give one mismatched snapshot that is
		// not a real failure, so this polls for agreement instead of asserting
		// on the first pair it sees.
		var pa, pb string
		began := time.Now()
		for deadline := began.Add(90 * time.Second); time.Now().Before(deadline); {
			pa, pb = l.a.psk(t), l.b.psk(t)
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
		l.ok("both ends hold %s after %s", tail(psk), time.Since(began).Round(100*time.Millisecond))
	})
	if psk == "" {
		t.FailNow()
	}

	l.phase(t, "the tunnel carries traffic on the first installed key", func(t *testing.T) {
		if ok, out := l.a.pings(t); !ok {
			t.Errorf("no traffic over the tunnel on the first key:\n%s", out)
		} else {
			l.ok("payload crosses the tunnel and decrypts at the far end")
		}
	})

	l.phase(t, "the PSK rotates in step", func(t *testing.T) {
		prev := psk
		for cycle := 1; cycle <= cycles; cycle++ {
			var cur, other string
			began := time.Now()
			for deadline := began.Add(30 * time.Second); time.Now().Before(deadline); {
				if cur = l.a.psk(t); cur != "" && cur != prev {
					break
				}
				time.Sleep(time.Second)
			}
			if cur == "" || cur == prev {
				t.Fatalf("cycle %d/%d: the PSK did not change within 30s (still %s)",
					cycle, cycles, tail(prev))
			}
			if other = l.b.psk(t); cur != other {
				t.Fatalf("cycle %d/%d: the ends diverged, node-a %s, node-b %s",
					cycle, cycles, tail(cur), tail(other))
			}
			l.ok("cycle %d/%d: rotated to %s after %s, both ends match",
				cycle, cycles, tail(cur), time.Since(began).Round(100*time.Millisecond))
			prev = cur
		}
	})

	l.phase(t, "the tunnel still carries traffic after the rotations", func(t *testing.T) {
		if ok, out := l.a.pings(t); !ok {
			t.Errorf("tunnel does not carry traffic after %d rotations:\n%s", cycles, out)
		} else {
			l.ok("payload still crosses after %d rotations", cycles)
		}
	})

	// ci/verify-keys.sh's transport health check. At this INTERVAL the derived
	// rate limit is far above what two peers exchange, so a rejection here is
	// legitimate traffic being dropped; a full QKD queue means the read loop
	// refused a key_id its peer then had to retry; a stale PQC key means a
	// tunnel invalidated over key age. None of the three may happen to a
	// healthy pair.
	//
	// Asserted here and not at the end, because the log is still only the happy
	// path at this point: the fault phases below can produce all three, and
	// legitimately so.
	l.phase(t, "the transport stays healthy through the rotations", func(t *testing.T) {
		for _, n := range l.nodes() {
			for _, pattern := range []string{"rate limited", "QKD queue full", "key stale"} {
				if hits := n.count(t, pattern); hits != "0" {
					t.Errorf("%s logged %q %s time(s) with nothing broken", n.name, pattern, hits)
				}
			}
		}
		l.ok("no rate limiting, no full queue, no stale key on either peer")
	})

	l.phase(t, "a second peer on the interface", l.secondPeerCheck)

	// The contract under test, and the only place the modes differ: in the happy
	// path they all behave identically, so a mode only shows its hand when a key
	// source disappears.
	l.faultPhase(t, "the KMS hangs", func(t *testing.T) { l.sourceCheck(t, "qkd", "freeze") })
	l.faultPhase(t, "the KMS is not running", func(t *testing.T) { l.sourceCheck(t, "qkd", "down") })
	l.faultPhase(t, "PQC cannot agree a key", func(t *testing.T) { l.sourceCheck(t, "pqc", "") })

	l.faultPhase(t, "a PSK written behind their backs", l.desyncCheck)
	l.faultPhase(t, "a peer with the wrong ARNIKA_PSK", l.wrongPSKCheck)

	l.phase(t, "the tunnel carries traffic at the end", func(t *testing.T) {
		if ok, out := l.a.pings(t); !ok {
			t.Errorf("the tunnel does not carry traffic at the end of the run:\n%s", out)
		} else {
			l.ok("payload crosses the tunnel after every fault this run caused")
		}
	})

	// What each peer actually did, counted from its own log. Mirrors the
	// per-mode log summary at the end of run_mode in ci/local-darwin/run.sh.
	l.rule("log summary")
	for _, n := range l.nodes() {
		l.say("%s: %s PQC exchanges, %s PSK writes", n.name,
			n.count(t, "agreed a fresh PQC key"),
			n.count(t, "PSK configured on WireGuard interface"))
		l.trouble(t, n)
	}
}

// expectedTrouble is every warning and error a green run can leave behind, and
// the fault phase that asks for it. Arnika logs nothing above INFO while a
// rotation is healthy, so this list is exactly the deliberate breakage of this
// suite, seen from the peer's side.
//
// It is the reason the summary reports messages rather than a count: a number
// cannot say whether the warnings under it were the ones this run asked for.
var expectedTrouble = map[string]string{
	"KMS request failed, retrying":                                     "the KMS was frozen, then stopped",
	"failed to retrieve a QKD key":                                     "the PRIMARY's fetch, with the KMS gone",
	"failed to retrieve the QKD key for the peer's key_id":             "the BACKUP's fetch, with the KMS gone",
	"no QKD key received":                                              "the mode requires QKD and it was gone",
	"no QKD key, falling back to the PQC key":                          "QKD gone, and optional to the mode",
	"no QKD key, installing a PQC-only PSK":                            "QKD gone for two intervals, PQC carries on",
	"failed to retrieve the PQC key":                                   "PQC_ROUND_TIMEOUT=1ns, and PQC required",
	"no PQC key, falling back to the QKD key":                          "PQC_ROUND_TIMEOUT=1ns, PQC optional",
	"round failed":                                                     "a PQC round hit its deadline or lost its peer",
	"configuring a random PSK to invalidate the WireGuard session":     "the invalidation the line above asked for",
	"no key_id from the peer":                                          "a peer stopped mid-interval by a fault phase",
	"packet rejected":                                                  "a peer with the wrong ARNIKA_PSK, as that phase asked for",
	"packet rejected, ARNIKA_PSK mismatch or the message is corrupted": "the same, one step further in",
	"PQC frame not accepted":                                           "a PQC frame from a peer that cannot authenticate",
	"the peer did not confirm the key_id":                              "the same, seen from the peer that was still up, or a BACKUP whose KMS was gone",
}

// trouble prints the node's warnings and errors by message, each against the
// fault that explains it. Anything this suite did not ask for is called out as
// UNEXPECTED, which is the one thing worth reading in a green run: the counts
// themselves mean nothing when four phases break something on purpose.
func (l *lab) trouble(t *testing.T, n *node) {
	t.Helper()
	// grep -o over msg="..." rather than the whole line, so the same message
	// counts as one however its attributes differ between peers and roles.
	out := strings.TrimSpace(n.exec(t,
		`grep -E 'level=(WARN|ERROR)' /tmp/arnika.log | grep -oE 'msg="[^"]*"' |
			sort | uniq -c | sort -rn | sed 's/^ *\([0-9]*\) msg="\(.*\)"/\1|\2/'`))
	if out == "" {
		l.say("   no warnings or errors")
		return
	}
	type entry struct{ count, msg, why string }
	var entries []entry
	unexpected := 0
	for _, line := range strings.Split(out, "\n") {
		count, msg, _ := strings.Cut(strings.TrimSpace(line), "|")
		why, known := expectedTrouble[msg]
		if !known {
			unexpected++
		}
		entries = append(entries, entry{count, msg, why})
	}
	verdict := c(dim) + "all of them asked for by the phases above" + c(reset)
	if unexpected > 0 {
		verdict = c(red) + fmt.Sprintf("%d of them not asked for by any phase", unexpected) + c(reset)
	}
	l.say("   warnings and errors: %s", verdict)
	for _, e := range entries {
		why := c(red) + "UNEXPECTED" + c(reset)
		if e.why != "" {
			why = c(dim) + e.why + c(reset)
		}
		l.say("   %4sx %-60s %s", e.count, e.msg, why)
	}
}
