// Package wgmikrotik writes the WireGuard PSK to a MikroTik RouterOS device through its REST API.
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

const peersPath = "/rest/interface/wireguard/peers"

// peersPrintPath takes a server-side .query, the REST stand-in for the CLI's [find public-key=...].
const peersPrintPath = peersPath + "/print"

type Repository struct {
	baseURL       string
	username      string
	password      string
	interfaceName string
	peerPublicKey string
	conn          *http.Client
}

type mikrotikPeer struct {
	ID        string `json:".id"`
	Interface string `json:"interface"`
	PublicKey string `json:"public-key"`
}

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

// SetPSK re-resolves the peer on every call because a RouterOS restart may reassign its .id.
func (r *Repository) SetPSK(psk []byte) error {
	id, err := r.findPeerID()
	if err != nil {
		return err
	}
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
