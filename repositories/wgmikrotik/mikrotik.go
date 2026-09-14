// Package wgmikrotik writes the WireGuard PSK to a MikroTik RouterOS device
// through its REST API.
package wgmikrotik

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// peersPath is the RouterOS v7 REST collection for WireGuard peers.
const peersPath = "/rest/interface/wireguard/peers"

// peersPrintPath is the "print" action on the peers collection. The REST API has
// no `find` abstraction, so we emulate the CLI's `[find public-key=...]` by
// POSTing a server-side `.query` here instead of fetching the whole peers table
// and filtering client-side. See docs/wireguard-mikrotik.md.
const peersPrintPath = peersPath + "/print"

// Repository provisions the WireGuard PSK onto a remote
// MikroTik RouterOS device through its REST API (RouterOS v7+). It implements
// the same keyWriterRepository contract as Repository, so it is
// selected via the wireguard_mikrotik build tag without any change to main.go.
type Repository struct {
	baseURL       string // RouterOS base URL, e.g. https://192.168.88.1 (no trailing /rest)
	username      string
	password      string
	interfaceName string
	peerPublicKey string
	conn          *http.Client
}

// mikrotikPeer captures the subset of a RouterOS WireGuard peer we need to
// locate the peer to update. RouterOS keys the internal id as ".id".
type mikrotikPeer struct {
	ID        string `json:".id"`
	Interface string `json:"interface"`
	PublicKey string `json:"public-key"`
}

// NewRepository builds a repository targeting the RouterOS REST
// API at baseURL. The caller supplies the HTTP client so that TLS trust
// (system roots, a pinned CA, or an explicit insecure opt-in) is configured
// once, at the wiring layer, alongside the rest of the transport concerns.
func NewRepository(baseURL, username, password, interfaceName, peerPublicKey string, client *http.Client) *Repository {
	return &Repository{
		baseURL:       strings.TrimRight(baseURL, "/"),
		username:      username,
		password:      password,
		interfaceName: interfaceName,
		peerPublicKey: peerPublicKey,
		conn:          client,
	}
}

// SetPSK resolves the configured peer on the router and updates its
// preshared-key. The peer is re-resolved on every call so the writer stays
// correct across RouterOS restarts that may reassign internal ids.
func (r *Repository) SetPSK(psk []byte) error {
	id, err := r.findPeerID()
	if err != nil {
		return err
	}
	// The base64 encoding lives here and not at the caller: RouterOS takes the
	// key as a JSON string, so this is the one adapter where the PSK has to
	// become an immutable Go string at all. Doing it further up would put that
	// unclearable copy on the heap for the netlink writers too, which never
	// need one.
	body, err := json.Marshal(map[string]string{"preshared-key": base64.StdEncoding.EncodeToString(psk)})
	if err != nil {
		return fmt.Errorf("failed to encode PSK request: %w", err)
	}
	res, err := r.do(http.MethodPatch, peersPath+"/"+id, bytes.NewReader(body))
	if err != nil {
		return err
	}
	return res.Body.Close()
}

// findPeerID returns the RouterOS internal id of the peer matching the
// configured interface and public key. It asks the router to filter by public
// key via a server-side `.query` (the REST equivalent of the CLI's
// `[find public-key=...]`), so only the matching peer is returned rather than
// the entire peers table. The interface is verified on the returned peer,
// guarding against the rare case of the same public key on multiple interfaces.
func (r *Repository) findPeerID() (string, error) {
	query, err := json.Marshal(map[string]any{
		".proplist": []string{".id", "interface", "public-key"},
		".query":    []string{"public-key=" + r.peerPublicKey},
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode RouterOS peer query: %w", err)
	}
	res, err := r.do(http.MethodPost, peersPrintPath, bytes.NewReader(query))
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	var peers []mikrotikPeer
	if err := json.NewDecoder(res.Body).Decode(&peers); err != nil {
		return "", fmt.Errorf("failed to decode RouterOS peers response: %w", err)
	}
	for _, p := range peers {
		if p.PublicKey == r.peerPublicKey && p.Interface == r.interfaceName {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("peer with public key %s not found on interface %s", r.peerPublicKey, r.interfaceName)
}

// do issues an authenticated JSON request to the RouterOS REST API and returns
// the response for any 2xx status, converting non-2xx responses into errors.
func (r *Repository) do(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, r.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to build RouterOS request: %w", err)
	}
	req.SetBasicAuth(r.username, r.password)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := r.conn.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RouterOS request to %s failed: %w", path, err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		_ = res.Body.Close()
		return nil, fmt.Errorf("RouterOS %s %s returned %s: %s", method, path, res.Status, strings.TrimSpace(string(msg)))
	}
	return res, nil
}
