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
	interval = 5 * time.Second
	wgPort   = "51820"

	simulatorImage = "qkd-simulator:e2e"
	nodeImage      = "arnika-node:e2e"
	qkdNoneImage   = "arnika-node:qkd-none-e2e"

	cycles = 3

	frozenKMSEnv = "KMS_HTTP_TIMEOUT=1s KMS_BACKOFF_MAX_RETRIES=1"

	noPQCEnv = "PQC_ROUND_TIMEOUT=1ns" // not 1ms: a round between two containers can finish inside a millisecond
)

var zeroPSK = base64.StdEncoding.EncodeToString(make([]byte, 32))

type mode struct {
	name        string
	qkdRequired bool
	pqcRequired bool
	pqcOnly     bool
	qkdNone     bool
	color       string
}

var modes = []mode{
	{name: "QkdAndPqcRequired", qkdRequired: true, pqcRequired: true, color: cyan},
	{name: "AtLeastQkdRequired", qkdRequired: true, color: yellow},
	{name: "AtLeastPqcRequired", pqcRequired: true, color: magenta},
	{name: "AtLeastPqcRequired", pqcRequired: true, qkdNone: true, color: green},
	{name: "PqcOnly", pqcRequired: true, pqcOnly: true, color: green},
}

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

func c(style string) string {
	if colorless {
		return ""
	}
	return style
}

func (m mode) prefix() string {
	label := strings.TrimSuffix(m.name, "Required")
	if m.qkdNone {
		label += "/qkd_none"
	}
	name := fmt.Sprintf("%-20s ", label)
	return c(m.color) + name + c(reset)
}

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

func TestMain(m *testing.M) {
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	tclog.SetDefault(tclog.NewNoopLogger())

	for _, img := range []struct {
		name       string
		dockerfile string
		buildTags  string
	}{
		{name: simulatorImage, dockerfile: "ci/Dockerfile.simulator"},
		{name: nodeImage, dockerfile: "ci/Dockerfile.node"},
		{name: qkdNoneImage, dockerfile: "ci/Dockerfile.node", buildTags: "qkd_none"},
	} {
		args := []string{"build", "-q", "-f", img.dockerfile, "-t", img.name}
		if img.buildTags != "" {
			args = append(args, "--build-arg", "BUILD_TAGS="+img.buildTags)
		}
		args = append(args, ".")
		cmd := exec.Command("docker", args...)
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s\n", img.name, err, out)
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
	wgIP string
	sae  string
	id   string
	peer *node
}

type lab struct {
	mode         mode
	root         *testing.T
	net          *testcontainers.DockerNetwork
	kms          testcontainers.Container
	a, b         *node
	transportPSK string
	prefix       string
	buf          bytes.Buffer
}

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

func (n *node) exec(t *testing.T, format string, args ...any) string {
	t.Helper()
	code, out := n.run(t, format, args...)
	if code != 0 {
		t.Fatalf("%s: %q exited %d: %s", n.name, fmt.Sprintf(format, args...), code, out)
	}
	return out
}

func (n *node) psk(t *testing.T) string {
	t.Helper()
	return n.pskOf(t, n.peer.pub)
}

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
	t.Cleanup(l.flush)
	l.rule("lab")
	l.startKMS(t, "")

	l.a = &node{name: "node-a", wgIP: "172.16.0.1", sae: "CONSA", id: "9998"}
	l.b = &node{name: "node-b", wgIP: "172.16.0.2", sae: "CONSB", id: "9999"}
	l.a.peer, l.b.peer = l.b, l.a

	for _, n := range l.nodes() {
		image := nodeImage
		if m.qkdNone {
			image = qkdNoneImage
		}
		n.ctr = l.start(t, ctx, testcontainers.ContainerRequest{
			Image:          image,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {n.name}},
			Privileged:     true,
		})
	}

	for _, n := range l.nodes() {
		n.priv = strings.TrimSpace(n.exec(t, "wg genkey"))
		n.pub = strings.TrimSpace(n.exec(t, "printf '%%s' %q | wg pubkey", n.priv))
	}

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

	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("generate transport PSK: %v", err)
	}
	l.transportPSK = base64.StdEncoding.EncodeToString(seed[:])

	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, n := range l.nodes() {
			_, log := n.run(t, "tail -n 40 /tmp/arnika.log")
			_, wg := n.run(t, "wg show wg0")
			l.say("--- %s arnika.log ---\n%s", n.name, log)
			l.say("--- %s wg ---\n%s", n.name, wg)
		}
	})

	return l
}

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

func (l *lab) replaceKMS(t *testing.T, freeze string) {
	t.Helper()
	if err := l.kms.Terminate(context.Background()); err != nil {
		t.Fatalf("terminate the KMS: %v", err)
	}
	l.startKMS(t, freeze)
}

func (l *lab) startPeers(t *testing.T, extra string) {
	t.Helper()
	for _, n := range l.nodes() {
		l.startPeer(t, n, l.transportPSK, extra)
	}
	started := "peers started, INTERVAL=" + interval.String()
	if extra != "" {
		started += " " + extra
	}
	l.step("%s", started)
}

func (l *lab) startPeer(t *testing.T, n *node, transportPSK, extra string) {
	t.Helper()
	kmsEnv := fmt.Sprintf("KMS_URL=http://qkd-simulator:8080/api/v1/keys/%s", n.sae)
	if l.mode.qkdNone {
		kmsEnv = ""
	}
	n.exec(t, `nohup env \
		LISTEN_ADDRESS=0.0.0.0:%s SERVER_ADDRESS=%s:%s ARNIKA_ID=%s \
		INTERVAL=%s MODE=%s LOG_LEVEL=debug ARNIKA_PSK=%q \
		%s \
		WIREGUARD_INTERFACE=wg0 WIREGUARD_PEER_PUBLIC_KEY=%q \
		%s \
		arnika >> /tmp/arnika.log 2>&1 &`,
		n.id, n.peer.name, n.peer.id, n.id,
		interval, l.mode.name, transportPSK, kmsEnv, n.peer.pub, extra)
}

func (n *node) running(t *testing.T) bool {
	t.Helper()
	code, _ := n.run(t, `ps -o stat,comm | awk '$2 == "arnika" && $1 !~ /Z/ {live = 1} END {exit !live}'`)
	return code == 0
}

func (l *lab) stopPeers(t *testing.T) {
	t.Helper()
	for _, n := range l.nodes() {
		n.run(t, "pkill -x arnika")
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
	testcontainers.CleanupContainer(l.root, c, testcontainers.StopTimeout(time.Second))
	if err != nil {
		t.Fatalf("start %v: %v", req.NetworkAliases, err)
	}
	return c
}

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

func (l *lab) agreeNew(t *testing.T, before string) bool {
	pa, pb := l.a.psk(t), l.b.psk(t)
	return pa != "" && pa == pb && pa != before
}

func (l *lab) diverged(t *testing.T) bool {
	pa, pb := l.a.psk(t), l.b.psk(t)
	return pa != "" && pb != "" && pa != pb
}

func (n *node) logLines(t *testing.T) int {
	t.Helper()
	var n2 int
	fmt.Sscan(strings.TrimSpace(n.exec(t, "wc -l < /tmp/arnika.log")), &n2)
	return n2
}

func (n *node) loggedSince(t *testing.T, mark int, pattern string) bool {
	t.Helper()
	out := n.exec(t, "tail -n +%d /tmp/arnika.log | grep -c %q || true", mark+1, pattern)
	return strings.TrimSpace(out) != "0"
}

func (n *node) setPSK(t *testing.T, psk string) {
	t.Helper()
	n.exec(t, "printf '%%s' %q | wg set wg0 peer %q preshared-key /dev/stdin", psk, n.peer.pub)
}

func (n *node) resetSession(t *testing.T, psk string) {
	t.Helper()
	n.exec(t, `set -e
		wg set wg0 peer %q remove
		printf '%%s' %q | wg set wg0 peer %q allowed-ips %s/32 endpoint %s:%s \
			persistent-keepalive 10 preshared-key /dev/stdin`,
		n.peer.pub, psk, n.peer.pub, n.peer.wgIP, n.peer.name, wgPort)
}

func (n *node) handshaked(t *testing.T) bool {
	t.Helper()
	out := strings.TrimSpace(n.exec(t,
		"wg show wg0 latest-handshakes | awk -v k=%q '$1 == k {print $2}'", n.peer.pub))
	return out != "" && out != "0"
}

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

func (n *node) pings(t *testing.T) (bool, string) {
	t.Helper()
	code, out := n.run(t, "ping -c3 -W2 %s", n.peer.wgIP)
	return code == 0 && strings.Contains(out, "3 received"), out
}

func (l *lab) say(format string, args ...any) {
	l.print("    " + l.prefix + "  " + fmt.Sprintf(format, args...) + "\n")
}

func (l *lab) step(format string, args ...any) {
	l.print("    " + l.prefix + c(dim) + "· " + fmt.Sprintf(format, args...) + c(reset) + "\n")
}

func (l *lab) ok(format string, args ...any) {
	l.print("    " + l.prefix + c(green) + "✓ " + c(reset) + fmt.Sprintf(format, args...) + "\n")
}

func (l *lab) rule(name string) {
	if fill := 58 - len(name); fill > 0 {
		name += " " + strings.Repeat("─", fill)
	}
	l.print("    " + l.prefix + c(bold) + "── " + name + c(reset) + "\n")
}

func (l *lab) phase(t *testing.T, name string, fn func(t *testing.T)) bool {
	return t.Run(name, func(t *testing.T) {
		defer l.flush()
		l.rule(name)
		fn(t)
	})
}

func (l *lab) faultPhase(t *testing.T, name string, fn func(t *testing.T)) bool {
	return t.Run(name, func(t *testing.T) {
		defer l.flush()
		l.rule(name + " [intentional]")
		fn(t)
	})
}

func tail(key string) string {
	if len(key) <= 6 {
		return key
	}
	return "…" + key[len(key)-6:]
}

func (n *node) count(t *testing.T, pattern string) string {
	t.Helper()
	return strings.TrimSpace(n.exec(t, "grep -c %q /tmp/arnika.log || true", pattern))
}

func randomPSK(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate a random key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

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

	b.setPSK(t, zeroPSK)
	a.setPSK(t, zeroPSK)
	a.resetSession(t, zeroPSK)
	if !a.waitHandshake(t, 20*time.Second) {
		t.Fatal("the tunnel did not come back after the pre-test")
	}
	l.ok("the tunnel is up again and Arnika can take over")
}

func (l *lab) sourceCheck(t *testing.T, source, how string) {
	ctx := context.Background()
	pqcInitiator := l.a
	l.stopPeers(t)
	before := pqcInitiator.psk(t) // after stopPeers: a rotation between this read and the stop would count as fresh
	mark := pqcInitiator.logLines(t)

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

	pattern := l.mode.decision(source)
	if took, ok := waitFor(10*time.Second, func() bool { return pqcInitiator.loggedSince(t, mark, pattern) }); !ok {
		t.Errorf("%s never logged %q, so what happened was not a mode decision", pqcInitiator.name, pattern)
	} else {
		l.ok("%s logged the decision after %s: %q", pqcInitiator.name, took, pattern)
	}

	if how == "freeze" {
		if requests := l.kmsLogged(t, "[FREEZE]"); requests == 0 {
			t.Error("the frozen KMS logged no request, so nothing says the peers ever reached it")
		} else {
			l.ok("the frozen KMS accepted %d request(s) and answered none", requests)
		}
	}

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

func (l *lab) secondPeerCheck(t *testing.T) {
	decoy := strings.TrimSpace(l.a.exec(t, "wg genkey | wg pubkey"))
	mark := l.a.logLines(t)
	l.a.exec(t, "wg set wg0 peer %q allowed-ips 172.16.0.99/32", decoy)
	defer l.a.exec(t, "wg set wg0 peer %q remove", decoy)
	before := l.a.psk(t)
	l.step("node-a's wg0 carries a second peer, %s", tail(decoy))

	if took, ok := waitFor(4*interval, func() bool { return l.agreeNew(t, before) }); !ok {
		t.Errorf("the PSK stopped rotating with a second peer on the interface: node-a %s, node-b %s",
			tail(l.a.psk(t)), tail(l.b.psk(t)))
	} else {
		l.ok("the PSK still rotates with two peers on the interface, %s after %s",
			tail(l.a.psk(t)), took)
	}

	if l.a.loggedSince(t, mark, "failed to configure the PSK on the WireGuard interface") {
		t.Error("node-a could not write the PSK while a second peer was on the interface")
	}

	if psk := l.a.pskOf(t, decoy); psk != "" {
		t.Errorf("the second peer was given the preshared key %s, so the write went to the wrong peer", tail(psk))
	} else {
		l.ok("the second peer was left without a key of its own")
	}
}

func (l *lab) wrongPSKCheck(t *testing.T) {
	l.stopPeers(t)
	before := l.a.psk(t) // after stopPeers: a rotation between this read and the stop would count as fresh
	mark := l.b.logLines(t)
	l.startPeer(t, l.a, randomPSK(t), "")
	l.startPeer(t, l.b, l.transportPSK, "")
	l.step("node-a restarted with a transport PSK node-b does not share")

	window := 3 * interval
	switch took, agreed := waitFor(window, func() bool { return l.agreeNew(t, before) }); {
	case agreed:
		t.Errorf("the ends met on the fresh key %s after %s although node-a cannot authenticate to node-b",
			tail(l.a.psk(t)), took)
	case !l.diverged(t):
		t.Errorf("neither end moved in %s, so nothing here says they could not sync: both hold %s",
			window, tail(before))
	default:
		l.ok("the ends came apart and never met on a fresh key in %s, node-a %s, node-b %s",
			window, tail(l.a.psk(t)), tail(l.b.psk(t)))
	}

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

func TestArnika(t *testing.T) {
	for _, m := range modes {
		name := m.name
		if m.qkdNone {
			name += "_qkd_none"
		}
		t.Run(name, func(t *testing.T) {
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

	l.phase(t, "the transport stays healthy through the rotations, before any fault phase", func(t *testing.T) {
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

	if !m.pqcOnly && !m.qkdNone {
		l.faultPhase(t, "the KMS hangs", func(t *testing.T) { l.sourceCheck(t, "qkd", "freeze") })
		l.faultPhase(t, "the KMS is not running", func(t *testing.T) { l.sourceCheck(t, "qkd", "down") })
	}
	l.faultPhase(t, "PQC cannot agree a key", func(t *testing.T) { l.sourceCheck(t, "pqc", "") })
	if m.pqcOnly || m.qkdNone {
		l.phase(t, "no KMS requests", l.noKMSRequestsCheck)
	}

	l.faultPhase(t, "a PSK written behind their backs", l.desyncCheck)
	l.faultPhase(t, "a peer with the wrong ARNIKA_PSK", l.wrongPSKCheck)

	l.phase(t, "the tunnel carries traffic at the end", func(t *testing.T) {
		if ok, out := l.a.pings(t); !ok {
			t.Errorf("the tunnel does not carry traffic at the end of the run:\n%s", out)
		} else {
			l.ok("payload crosses the tunnel after every fault this run caused")
		}
	})

	l.rule("log summary")
	for _, n := range l.nodes() {
		l.say("%s: %s PQC exchanges, %s PSK writes", n.name,
			n.count(t, "agreed a fresh PQC key"),
			n.count(t, "PSK configured on WireGuard interface"))
		l.trouble(t, n)
	}
}

func (l *lab) noKMSRequestsCheck(t *testing.T) {
	t.Helper()
	if requests := l.kmsLogged(t, "[REQ] method="); requests != 0 {
		t.Errorf("%s caused %d KMS HTTP request(s), want none", l.mode.name, requests)
	} else {
		l.ok("KMS received no HTTP requests")
	}
	if l.mode.qkdNone {
		for _, n := range l.nodes() {
			if count := n.count(t, "NOT COMPILED IN (build tag qkd_none)"); count == "0" {
				t.Errorf("%s did not report that the qkd_none binary has no QKD reader", n.name)
			}
		}
	}
	for _, n := range l.nodes() {
		for _, message := range []string{
			"requesting a new QKD key",
			"requesting the QKD key for the peer's key_id",
		} {
			if count := n.count(t, message); count != "0" {
				t.Errorf("%s logged %s KMS-request attempts for %q", n.name, count, message)
			}
		}
	}
}

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

func (l *lab) trouble(t *testing.T, n *node) {
	t.Helper()
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
