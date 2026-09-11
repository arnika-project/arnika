package repositories

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime/secret"
	"strings"
	"time"
)

type skipResponse struct {
	KeyID string `json:"keyID"`
	Key   string `json:"key"`
}

type SKIPRepository struct {
	baseURL          string
	remoteSystemID   string
	maxRetries       int
	backoffBaseDelay time.Duration
	conn             *http.Client
	Managed          bool
}

func NewSKIPRepository(url string, remoteSystemID string, timeout time.Duration, maxRetries int, backoffBaseDelay time.Duration, auth *KMSAuth) *SKIPRepository {
	cleanBaseURL := strings.TrimSuffix(url, "/")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		Proxy: http.ProxyFromEnvironment,
	}
	if auth.IsClientCertAuth() { //Check for files for cert auth
		clientCert, err := tls.LoadX509KeyPair(*auth.cert, *auth.key) //load client cert and  key
		if err != nil {
			log.Fatal(err)
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{clientCert} // Set client cert for TLS auth
		caCert, err := os.ReadFile(*auth.cacert)                        //load plain ca cert
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()        //Create blank pool of trusted certs
		caCertPool.AppendCertsFromPEM(caCert)   //Add our CA
		tr.TLSClientConfig.RootCAs = caCertPool //use this pool for server auth
	}
	return &SKIPRepository{
		baseURL:          cleanBaseURL,
		remoteSystemID:   remoteSystemID,
		maxRetries:       maxRetries,
		backoffBaseDelay: backoffBaseDelay,
		conn: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		Managed: true,
	}
}

// This is main function to proceed skip request
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

	if skipResp.KeyID == "" || skipResp.Key == "" {
		return "", nil, fmt.Errorf("[ERROR] received empty key or keyID from server")
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

	return skipResp.KeyID, rawKey, nil
}

func (r *SKIPRepository) GetNewKey() (string, []byte, error) {
	requestURL := r.baseURL + "/key?remoteSystemID=" + r.remoteSystemID
	keyID, key, err := r.skipRequest(requestURL)

	if err != nil {
		return "", nil, fmt.Errorf("[ERROR] failed to get new key: %w", err)
	}

	return keyID, key, nil
}

func (r *SKIPRepository) GetKeyByID(keyID *string) ([]byte, error) {
	if keyID == nil || *keyID == "" {
		return nil, fmt.Errorf("[ERROR] keyID is nil or empty")
	}

	if len(*keyID) > 128 {
		return nil, fmt.Errorf("[ERROR] keyID is too long")
	}

	if _, err := hex.DecodeString(*keyID); err != nil {
		return nil, fmt.Errorf("[ERROR] keyID is not a valid hex string")
	}

	escapedKeyID := url.PathEscape(*keyID)

	requestURL := r.baseURL + "/key/" + escapedKeyID + "?remoteSystemID=" + r.remoteSystemID
	_, key, err := r.skipRequest(requestURL)

	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to get this key: %w", err)
	}

	return key, nil
}
