package kms

import (
	"net/http"
	"testing"
	"time"
)

func TestNewClientCertificateAuth(t *testing.T) {
	// Test case 1: All parameters are non-empty
	cert := "path/to/cert"
	key := "path/to/key"
	cacert := "path/to/cacert"
	auth := NewClientCertificateAuth(cert, key, cacert)
	if auth == nil {
		t.Errorf("Expected non-nil Auth struct")
	}
	if *auth.cert != cert {
		t.Errorf("Expected cert %s, got %s", cert, *auth.cert)
	}
	if *auth.key != key {
		t.Errorf("Expected key %s, got %s", key, *auth.key)
	}
	if *auth.cacert != cacert {
		t.Errorf("Expected cacert %s, got %s", cacert, *auth.cacert)
	}

	// Test case 2: One of the parameters is empty
	cert = "path/to/cert"
	key = ""
	cacert = "path/to/cacert"
	auth = NewClientCertificateAuth(cert, key, cacert)
	if auth != nil {
		t.Errorf("Expected nil Auth struct")
	}

	// Test case 3: All parameters are empty
	cert = ""
	key = ""
	cacert = ""
	auth = NewClientCertificateAuth(cert, key, cacert)
	if auth != nil {
		t.Errorf("Expected nil Auth struct")
	}
}

func TestIsClientCertAuth(t *testing.T) {
	// Test case 1: Auth struct is nil
	var auth *Auth
	result := auth.IsClientCertAuth()
	expected := false
	if result != expected {
		t.Errorf("Expected %t, but got %t", expected, result)
	}

	// Test case 2: All fields are non-nil
	cert := "path/to/cert"
	key := "path/to/key"
	cacert := "path/to/cacert"
	auth = &Auth{
		cert:   &cert,
		key:    &key,
		cacert: &cacert,
	}
	result = auth.IsClientCertAuth()
	expected = true
	if result != expected {
		t.Errorf("Expected %t, but got %t", expected, result)
	}

	// Test case 3: One of the fields is nil
	cert = "path/to/cert"
	cacert = "path/to/cacert"
	auth = &Auth{
		cert:   &cert,
		cacert: &cacert,
	}
	result = auth.IsClientCertAuth()
	expected = false
	if result != expected {
		t.Errorf("Expected %t, but got %t", expected, result)
	}
}

func TestNewKMSServer(t *testing.T) {
	// Test case 1: Unauthenticated KMS server
	url := "https://kms.example.com"
	timeout := time.Duration(10) * time.Second
	backoffDefault := time.Duration(100) * time.Millisecond
	kmsAuth := &Auth{}
	kmsHandler := NewKMSServer(url, timeout, 3, backoffDefault, kmsAuth)
	if kmsHandler == nil {
		t.Errorf("Expected non-nil KMSHandler")
	}
	if kmsHandler.baseUrl != url {
		t.Errorf("Expected baseUrl %s, got %s", url, kmsHandler.baseUrl)
	}
	if kmsHandler.conn == nil {
		t.Errorf("Expected non-nil conn")
	}
	if kmsHandler.conn.Timeout != timeout {
		t.Errorf("Expected timeout %d, got %d", timeout, kmsHandler.conn.Timeout)
	}
	if kmsHandler.conn.Transport == nil {
		t.Errorf("Expected non-nil Transport")
	}
	if kmsHandler.conn.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify != true {
		t.Errorf("Expected InsecureSkipVerify to be true")
	}
}
