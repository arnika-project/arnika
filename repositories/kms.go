// Package repositories provides data access implementations for keys and external services.
package repositories

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type KMSAuth struct {
	cert   *string
	key    *string
	cacert *string
}

func NewKMSClientCertificateAuth(cert, key, cacert string) *KMSAuth {
	if cert == "" || key == "" || cacert == "" {
		return nil
	}
	return &KMSAuth{
		cert:   &cert,
		key:    &key,
		cacert: &cacert,
	}
}

func (a *KMSAuth) IsClientCertAuth() bool {
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

type HTTPKMSRepository struct {
	baseURL          string
	maxRetries       int
	backoffBaseDelay time.Duration
	conn             *http.Client
	Managed          bool
}

func NewHTTPKMSRepository(url string, timeout time.Duration, maxRetries int, backoffBaseDelay time.Duration, auth *KMSAuth) *HTTPKMSRepository {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Proxy: http.ProxyFromEnvironment,
	}
	if auth.IsClientCertAuth() {
		clientCert, err := tls.LoadX509KeyPair(*auth.cert, *auth.key)
		if err != nil {
			log.Fatal(err)
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
		caCert, err := os.ReadFile(*auth.cacert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}
	return &HTTPKMSRepository{
		baseURL:          url,
		maxRetries:       maxRetries,
		backoffBaseDelay: backoffBaseDelay,
		conn: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		Managed: true,
	}
}

func (r *HTTPKMSRepository) GetNewKey() (keyID string, key string, err error) {
	return r.kmsRequest("/enc_keys?number=1&size=256")
}

func (r *HTTPKMSRepository) GetKeyByID(keyID *string) (key string, err error) {
	if keyID == nil || *keyID == "" {
		return "", fmt.Errorf("keyID is empty")
	}
	_, key, err = r.kmsRequest("/dec_keys?key_ID=" + *keyID)
	return key, err
}

func (r *HTTPKMSRepository) kmsRequest(path string) (id string, key string, err error) {
	var kmsResp kmsResponse
	var res *http.Response

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		res, err = r.conn.Get(r.baseURL + path)
		if err == nil && res.StatusCode == http.StatusOK {
			break
		}
		if attempt < r.maxRetries {
			delay := r.backoffBaseDelay * time.Duration(1<<uint(attempt))
			log.Printf("Attempt %d: Retrying in %s...", attempt+1, delay)
			time.Sleep(delay)
		}
		if res != nil {
			_ = res.Body.Close()
		}
	}
	if err != nil {
		return "", "", err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}
	if err := json.Unmarshal(body, &kmsResp); err != nil {
		return "", "", fmt.Errorf("cant parse KMS response (%s): %w", string(body), err)
	}
	if len(kmsResp.Keys) == 0 || kmsResp.Keys[0].ID == "" || kmsResp.Keys[0].Key == "" {
		return "", "", fmt.Errorf("unable to fetch key from KMS: %s", string(body))
	}
	return kmsResp.Keys[0].ID, kmsResp.Keys[0].Key, nil
}
