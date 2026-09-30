// Package kms reads QKD keys from an ETSI GS QKD 014 key management system.
package kms

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/secret"
	"time"
)

type Auth struct {
	cert   *string
	key    *string
	cacert *string
}

func NewClientCertificateAuth(cert, key, cacert string) *Auth {
	if cert == "" || key == "" || cacert == "" {
		return nil
	}
	return &Auth{
		cert:   &cert,
		key:    &key,
		cacert: &cacert,
	}
}

func (a *Auth) IsClientCertAuth() bool {
	if a == nil {
		return false
	}
	return a.cert != nil && a.key != nil && a.cacert != nil
}

type kmsKey struct {
	ID  string `json:"key_ID"`
	Key string `json:"key"`
}

type kmsResponse struct {
	Keys []kmsKey `json:"keys"`
}

type Repository struct {
	baseURL          string
	maxRetries       int
	backoffBaseDelay time.Duration
	conn             *http.Client
}

func NewRepository(url string, timeout time.Duration, maxRetries int, backoffBaseDelay time.Duration, auth *Auth) *Repository {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{ // never InsecureSkipVerify, see GHSA-rc6v-5rmx-w5mv
			MinVersion: tls.VersionTLS12,
		},
		Proxy: http.ProxyFromEnvironment,
	}
	if auth.IsClientCertAuth() {
		clientCert, err := tls.LoadX509KeyPair(*auth.cert, *auth.key)
		if err != nil {
			slog.Error("failed to load the KMS client certificate", "cert", *auth.cert, "key", *auth.key, "err", err)
			os.Exit(1)
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
		caCert, err := os.ReadFile(*auth.cacert)
		if err != nil {
			slog.Error("failed to read the KMS CA certificate", "cacert", *auth.cacert, "err", err)
			os.Exit(1)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}
	return &Repository{
		baseURL:          url,
		maxRetries:       maxRetries,
		backoffBaseDelay: backoffBaseDelay,
		conn: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
	}
}

func (r *Repository) GetNewKey() (keyID string, key []byte, err error) {
	return r.kmsRequest("/enc_keys?number=1&size=256")
}

func (r *Repository) GetKeyByID(keyID string) (key []byte, err error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID is empty")
	}
	_, key, err = r.kmsRequest("/dec_keys?key_ID=" + keyID)
	return key, err
}

var ErrUnavailable = errors.New("KMS did not deliver a key")

func (r *Repository) kmsRequest(path string) (id string, key []byte, err error) {
	var kmsResp kmsResponse
	var res *http.Response
	var lastStatus int

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		res, err = r.conn.Get(r.baseURL + path)
		if err == nil && res.StatusCode == http.StatusOK {
			break
		}
		if res != nil {
			lastStatus = res.StatusCode
			_ = res.Body.Close()
			res = nil
		}
		if attempt < r.maxRetries {
			delay := r.backoffBaseDelay * time.Duration(1<<uint(attempt))
			if lastStatus != 0 { // never log body or path: dec_keys carries key_ID in its query
				slog.Warn("KMS request failed, retrying",
					"attempt", attempt+1, "status", lastStatus, "retry_in", delay)
			} else {
				slog.Warn("KMS request failed, retrying", "attempt", attempt+1, "retry_in", delay)
			}
			time.Sleep(delay)
		}
	}
	if err != nil {
		return "", nil, err
	}
	if res == nil {
		return "", nil, fmt.Errorf("%w: status %d after %d attempt(s)",
			ErrUnavailable, lastStatus, r.maxRetries+1)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", nil, err
	}
	defer clear(body)
	if err := json.Unmarshal(body, &kmsResp); err != nil {
		return "", nil, fmt.Errorf("cant parse KMS response: %w", err)
	}
	if len(kmsResp.Keys) == 0 || kmsResp.Keys[0].ID == "" || kmsResp.Keys[0].Key == "" {
		return "", nil, fmt.Errorf("unable to fetch key from KMS")
	}

	var rawKey []byte
	secret.Do(func() {
		rawKey, err = base64.StdEncoding.DecodeString(kmsResp.Keys[0].Key)
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode KMS key: %w", err)
	}
	return kmsResp.Keys[0].ID, rawKey, nil
}
