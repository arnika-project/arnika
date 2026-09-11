package wgmikrotik

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testMikrotikUser    = "arnika"
	testMikrotikPass    = "s3cret"
	testMikrotikIface   = "wg0"
	testMikrotikPeerKey = "abcPeerPublicKeyBase64Value000000000000000="
	testMikrotikPeerID  = "*3"
)

// fakeRouterOS is a minimal stand-in for the RouterOS v7 REST API exposing the
// WireGuard peers collection. It records the last "print" query and PATCH it
// received.
type fakeRouterOS struct {
	peers          []map[string]string
	lastPrintQuery []string
	lastPatchID    string
	lastPatchPSK   string
	printCalls     int
	patchCalls     int
	sawBasicAuth   bool
}

func (f *fakeRouterOS) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); ok && user == testMikrotikUser && pass == testMikrotikPass {
			f.sawBasicAuth = true
		}
		const base = "/rest/interface/wireguard/peers"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base+"/print":
			// RouterOS REST has no `find`; the client emulates the CLI's
			// `[find public-key=...]` with a server-side `.query`. Return only
			// the peers whose public-key matches that query term.
			f.printCalls++
			body, _ := io.ReadAll(r.Body)
			var q struct {
				Proplist []string `json:".proplist"`
				Query    []string `json:".query"`
			}
			if err := json.Unmarshal(body, &q); err != nil {
				t.Errorf("print body is not valid JSON: %v", err)
			}
			f.lastPrintQuery = q.Query
			want := ""
			for _, term := range q.Query {
				if strings.HasPrefix(term, "public-key=") {
					want = strings.TrimPrefix(term, "public-key=")
				}
			}
			matched := []map[string]string{}
			for _, p := range f.peers {
				if want == "" || p["public-key"] == want {
					matched = append(matched, p)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(matched)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, base+"/"):
			f.patchCalls++
			f.lastPatchID = strings.TrimPrefix(r.URL.Path, base+"/")
			body, _ := io.ReadAll(r.Body)
			var payload map[string]string
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Errorf("PATCH body is not valid JSON: %v", err)
			}
			f.lastPatchPSK = payload["preshared-key"]
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}
}

func newTestRepo(t *testing.T, fake *fakeRouterOS) (*Repository, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(fake.handler(t))
	repo := NewRepository(srv.URL, testMikrotikUser, testMikrotikPass, testMikrotikIface, testMikrotikPeerKey, srv.Client())
	return repo, srv
}

func TestWireguardMikrotikRepository_SetPSK(t *testing.T) {
	fake := &fakeRouterOS{peers: []map[string]string{
		{".id": "*1", "interface": "wg0", "public-key": "someOtherPeerKey="},
		{".id": testMikrotikPeerID, "interface": testMikrotikIface, "public-key": testMikrotikPeerKey},
	}}
	repo, srv := newTestRepo(t, fake)
	defer srv.Close()

	const psk = "TESTpresharedKeyBase64Value00000000000000000="
	if err := repo.SetPSK(psk); err != nil {
		t.Fatalf("SetPSK returned error: %v", err)
	}
	if !fake.sawBasicAuth {
		t.Error("expected request to carry HTTP Basic auth with configured credentials")
	}
	if fake.printCalls != 1 {
		t.Fatalf("expected exactly 1 print call to resolve the peer id, got %d", fake.printCalls)
	}
	wantQuery := "public-key=" + testMikrotikPeerKey
	foundQuery := false
	for _, term := range fake.lastPrintQuery {
		if term == wantQuery {
			foundQuery = true
		}
	}
	if !foundQuery {
		t.Errorf("expected id lookup to filter server-side with %q, got .query %v", wantQuery, fake.lastPrintQuery)
	}
	if fake.patchCalls != 1 {
		t.Fatalf("expected exactly 1 PATCH call, got %d", fake.patchCalls)
	}
	if fake.lastPatchID != testMikrotikPeerID {
		t.Errorf("PATCH targeted peer id %q, want %q", fake.lastPatchID, testMikrotikPeerID)
	}
	if fake.lastPatchPSK != psk {
		t.Errorf("PATCH set preshared-key %q, want %q", fake.lastPatchPSK, psk)
	}
}

func TestWireguardMikrotikRepository_SetPSK_PeerNotFound(t *testing.T) {
	fake := &fakeRouterOS{peers: []map[string]string{
		{".id": "*1", "interface": "wg0", "public-key": "someOtherPeerKey="},
	}}
	repo, srv := newTestRepo(t, fake)
	defer srv.Close()

	if err := repo.SetPSK("whatever="); err == nil {
		t.Fatal("expected error when configured peer is absent, got nil")
	}
	if fake.patchCalls != 0 {
		t.Errorf("expected no PATCH when peer is missing, got %d", fake.patchCalls)
	}
}

func TestWireguardMikrotikRepository_InvalidateTunnel(t *testing.T) {
	fake := &fakeRouterOS{peers: []map[string]string{
		{".id": testMikrotikPeerID, "interface": testMikrotikIface, "public-key": testMikrotikPeerKey},
	}}
	repo, srv := newTestRepo(t, fake)
	defer srv.Close()

	if err := repo.InvalidateTunnel(); err != nil {
		t.Fatalf("InvalidateTunnel returned error: %v", err)
	}
	first := fake.lastPatchPSK
	raw, err := base64.StdEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("InvalidateTunnel set a non-base64 preshared-key %q: %v", first, err)
	}
	if len(raw) != 32 {
		t.Errorf("InvalidateTunnel set a %d-byte key, want 32 bytes", len(raw))
	}
	if err := repo.InvalidateTunnel(); err != nil {
		t.Fatalf("second InvalidateTunnel returned error: %v", err)
	}
	if fake.lastPatchPSK == first {
		t.Error("InvalidateTunnel produced identical keys on two calls; expected random keys")
	}
}
