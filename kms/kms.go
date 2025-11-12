package kms

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

// Auth holds the configuration for authentication with a KMS server.
//
// cert: the path to the client certificate file.
// key: the path to the client key file.
// cacert: the path to the CA certificate file.
type Auth struct {
	cert   *string
	key    *string
	cacert *string
}

// NewClientCertificateAuth creates a new instance of the Auth struct for client certificate authentication.
//
// Parameters:
// - cert: the path to the client certificate file.
// - key: the path to the client key file.
// - cacert: the path to the CA certificate file.
//
// Returns:
// - *Auth: a pointer to the Auth struct, or nil if any of the parameters are empty.
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

// IsClientCertAuth checks if the Auth struct has a valid client certificate, key, and CA certificate.
//
// Returns:
// - bool: true if all fields are non-nil, false otherwise.
func (a *Auth) IsClientCertAuth() bool {
	if a == nil {
		return false
	}
	return a.cert != nil && a.key != nil && a.cacert != nil
}

// KMSHandler is a client for a kms KMS (Key Management Service)
type KMSHandler struct {
	baseUrl string
	conn    *http.Client
}

// Key is a KMS generated key.
//
// ID is the ID of the key, used to identify it in a KMS system.
// Key is the generated key itself.
type Key struct {
	ID  string `json:"key_ID"`
	Key string `json:"key"`
}

type response struct {
	Keys []Key `json:"keys"`
}

// NewKMSServer creates a new KMSHandler instance for interacting with a KMS server.
//
// Parameters:
// - url: the URL of the KMS server.
// - timeout: the timeout duration for HTTP requests in seconds.
// - kmsAuth: the authentication configuration for the KMS server.
//
// Returns:
// - *KMSHandler: a pointer to the KMSHandler instance.
func NewKMSServer(url string, timeout int, kmsAuth *Auth) *KMSHandler {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Proxy: http.ProxyFromEnvironment,
	}
	// Add certificates
	if kmsAuth.IsClientCertAuth() {
		clientCert, err := tls.LoadX509KeyPair(*kmsAuth.cert, *kmsAuth.key)
		if err != nil {
			log.Fatal(err)
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
		// Load CA cert
		caCert, err := os.ReadFile(*kmsAuth.cacert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}
	return &KMSHandler{
		baseUrl: url,
		conn: &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: tr,
		},
	}
}

// GetNewKey fetches a new key from the KMS.
//
// No parameters.
// Returns a pointer to a Key struct and an error.
func (q *KMSHandler) GetNewKey() (*Key, error) {
	return q.kmsRequest("/enc_keys?number=1&size=256")
}

// GetKeyByID fetches a key from a KMS by its ID.
//
// keyID string
// *Key, error
func (q *KMSHandler) GetKeyByID(keyID string) (*Key, error) {
	return q.kmsRequest("/dec_keys?key_ID=" + keyID)
}

// kmsRequest sends a request to the KMS server and returns the response.
//
// path: the path to send the request to.
// Returns a pointer to a Key struct and an error.
func (q *KMSHandler) kmsRequest(path string) (*Key, error) {
	var response response
	res, err := q.conn.Get(q.baseUrl + path)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("cant parse KMS response (%s): %w", string(body), err)
	}
	if len(response.Keys) == 0 || response.Keys[0].ID == "" || response.Keys[0].Key == "" {
		return nil, fmt.Errorf("unable to fetch key from KMS: %s", string(body))
	}
	return &response.Keys[0], nil
}

// GetID returns the key ID from the KMS generated key.
//
// No parameters.
// Returns a string.
func (k *Key) GetID() string {
	if k == nil {
		return ""
	}
	return k.ID
}

// GetKey returns the KMS generated key.
//
// No parameters.
// Returns a string.
func (k *Key) GetKey() string {
	if k == nil {
		return ""
	}
	return k.Key
}
