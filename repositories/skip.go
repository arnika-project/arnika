package repositories

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/secret"
	"strings"
	"time"

	"github.com/arnika-project/arnika/repositories/kms"
)

// SKIPRepository reads keys from a Secure Key Integration Protocol (SKIP)
// Key Provider, draft-cisco-skip-00. It is a managed source: it issues a
// keyId together with the key, and resolves a keyId received from the peer.
type skipResponse struct {
	KeyID string `json:"keyId"`
	// KeyIDLegacy accepts the older spelling some Key Providers emit.
	KeyIDLegacy string `json:"keyID,omitempty"`
	Key         string `json:"key"`
}

func (r skipResponse) id() string {
	if r.KeyID != "" {
		return r.KeyID
	}
	return r.KeyIDLegacy
}

type SKIPRepository struct {
	baseURL          string
	remoteSystemID   string
	maxRetries       int
	backoffBaseDelay time.Duration
	conn             *http.Client
}

func NewSKIPRepository(url string, remoteSystemID string, timeout time.Duration, maxRetries int, backoffBaseDelay time.Duration, auth *kms.Auth) *SKIPRepository {
	tlsConfig, err := auth.TLSConfig()
	if err != nil {
		panic(fmt.Sprintf("[ERROR] failed to configure the SKIP TLS client: %v", err))
	}

	return &SKIPRepository{
		baseURL:          strings.TrimSuffix(url, "/"),
		remoteSystemID:   remoteSystemID,
		maxRetries:       maxRetries,
		backoffBaseDelay: backoffBaseDelay,
		conn: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				Proxy:           http.ProxyFromEnvironment,
			},
		},
	}
}

// skipRequest performs a GET against the Key Provider and returns the keyId
// and the key material from the JSON response.
func (r *SKIPRepository) skipRequest(requestURL string) (string, []byte, error) {
	var res *http.Response
	var err error

	retries := r.maxRetries
	if retries < 0 {
		retries = 0
	}

	delay := r.backoffBaseDelay
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}

	for attempt := 0; attempt <= retries; attempt++ {
		res, err = r.conn.Get(requestURL)
		if err == nil {
			if res.StatusCode == http.StatusBadRequest {
				break
			}
			if res.StatusCode >= 500 {
				_ = res.Body.Close()
				time.Sleep(delay)
				delay *= 2
				continue
			}
			break
		}

		if attempt == retries {
			return "", nil, err
		}
		time.Sleep(delay)
		delay *= 2
	}

	if res == nil {
		return "", nil, fmt.Errorf("[ERROR] failed to connect: %w", err)
	}

	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		bodySnippet, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return "", nil, fmt.Errorf("[ERROR] server returned status: %d, body: %s", res.StatusCode, string(bodySnippet))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", nil, fmt.Errorf("[ERROR] failed to read response: %w", err)
	}
	defer clear(body)

	var skipResp skipResponse
	if err := json.Unmarshal(body, &skipResp); err != nil {
		return "", nil, fmt.Errorf("[ERROR] failed to parse JSON: %w", err)
	}

	keyID := skipResp.id()
	if keyID == "" || skipResp.Key == "" {
		return "", nil, fmt.Errorf("[ERROR] received empty key or keyId from server")
	}

	var rawKey []byte
	var decodeErr error
	secret.Do(func() {
		rawKey, decodeErr = hex.DecodeString(skipResp.Key)
	})
	if decodeErr != nil {
		return "", nil, fmt.Errorf("[ERROR] failed to decode hex key: %v", decodeErr)
	}

	if len(rawKey) != 32 {
		return "", nil, fmt.Errorf("[ERROR] invalid key length: got %d bytes, expected 32", len(rawKey))
	}

	return keyID, rawKey, nil
}

// GetNewKey requests a fresh (keyId, key) pair shared with remoteSystemID.
func (r *SKIPRepository) GetNewKey() (string, []byte, error) {
	requestURL := r.baseURL + "/key?remoteSystemID=" + url.QueryEscape(r.remoteSystemID)
	keyID, key, err := r.skipRequest(requestURL)
	if err != nil {
		return "", nil, fmt.Errorf("[ERROR] failed to get new key: %w", err)
	}
	return keyID, key, nil
}

// GetKeyByID resolves the keyId received from the peer.
func (r *SKIPRepository) GetKeyByID(keyID string) ([]byte, error) {
	if keyID == "" {
		return nil, fmt.Errorf("[ERROR] keyID is empty")
	}
	if len(keyID) > 128 {
		return nil, fmt.Errorf("[ERROR] keyID is too long")
	}
	if _, err := hex.DecodeString(keyID); err != nil {
		return nil, fmt.Errorf("[ERROR] keyID is not a valid hex string")
	}

	requestURL := r.baseURL + "/key/" + url.PathEscape(keyID) + "?remoteSystemID=" + url.QueryEscape(r.remoteSystemID)
	_, key, err := r.skipRequest(requestURL)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to get this key: %w", err)
	}
	return key, nil
}
