package config

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestUsePQC(t *testing.T) {
	// Test case 1: Config with PQCPSKFile set
	c := &Config{PQCPSKFile: "psk_file"}
	result := c.UsePQC()
	expected := true
	if result != expected {
		t.Errorf("Expected %t, but got %t", expected, result)
	}

	// Test case 2: Config with PQCPSKFile not set
	c = &Config{}
	result = c.UsePQC()
	expected = false
	if result != expected {
		t.Errorf("Expected %t, but got %t", expected, result)
	}
}

func TestParse(t *testing.T) {
	// Test case 1: Missing environment variable
	for _, mandatoryEnvVar := range []string{"LISTEN_ADDRESS", "SERVER_ADDRESS", "KMS_URL", "WIREGUARD_INTERFACE", "WIREGUARD_PEER_PUBLIC_KEY"} {
		_, err := Parse()
		if err == nil {
			t.Errorf("Expected an error for missing %s", mandatoryEnvVar)
		}
		t.Setenv(mandatoryEnvVar, fmt.Sprintf("value_of_%s", mandatoryEnvVar))
	}

	// Mocking environment variables for testing
	t.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080")
	t.Setenv("SERVER_ADDRESS", "127.0.0.1:8081")
	t.Setenv("KMS_URL", "https://example.com")
	t.Setenv("WIREGUARD_INTERFACE", "wg0")
	t.Setenv("WIREGUARD_PEER_PUBLIC_KEY", "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=")
	t.Setenv("MODE", "AtLeastQkdRequired")

	// Test case 2: All environment variables present
	expectedConfig := &Config{
		ListenAddress:          "127.0.0.1:8080",
		ServerAddress:          "127.0.0.1:8081",
		ArnikaID:               "8080",
		ArnikaPSK:              "", // Default value for ArnikaPSK
		Certificate:            "", // Default value for Certificate
		PrivateKey:             "", // Default value for PrivateKey
		CACertificate:          "", // Default value for CACertificate
		ArnikaPeerTimeout:      time.Millisecond * 500, // Actual default value for ArnikaPeerTimeout
		KMSURL:                 "https://example.com",
		KMSHTTPTimeout:         time.Second * 10,        // Actual default value for KMSHTTPTimeout
		KMSBackoffMaxRetries:   5,                       // Actual default value for KMSBackoffMaxRetries
		KMSBackoffBaseDelay:    time.Millisecond * 100,  // Actual default value for KMSBackoffBaseDelay
		KMSRetryInterval:       time.Second * 5,         // Actual default value for KMSRetryInterval
		Interval:               time.Second * 10,        // Actual default value for Interval
		WireGuardInterface:     "wg0",
		WireguardPeerPublicKey: "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=",
		PQCPSKFile:             "", // Default value for PQCPSKFile
		Mode:                   "AtLeastQkdRequired",
		RateLimit:              30,              // Real default value for RateLimit
		RateWindow:             time.Minute,     // Real default value for RateWindow
		MaxClockSkew:           time.Minute,     // Real default value for MaxClockSkew
	}
	result, err := Parse()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// Assert the values of the config struct here
	if !reflect.DeepEqual(result, expectedConfig) {
		t.Errorf("Expected config	%#v, but got %#v", expectedConfig, result)
	}

	// Test case 3: Interval parsing failure
	t.Setenv("INTERVAL", "invalid")
	_, err = Parse()
	if err == nil {
		t.Error("Expected an error for interval parsing failure")
	}
	t.Setenv("INTERVAL", "1m")

	// Test case 4: PQC keyfile check
	t.Setenv("PQC_PSK_FILE", "non_existent_file")
	_, err = Parse()
	if err == nil {
		t.Error("Expected an error for non-existent PQC keyfile")
	}
}

func TestParse_PQCFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	validKey := "dGVzdGtleTEyMzQ1Njc4OTAxMjM0NTY2Nzg5MDE="
	validFile := tmpDir + "/valid.key"
	os.WriteFile(validFile, []byte(validKey), 0600)

	t.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080")
	t.Setenv("SERVER_ADDRESS", "127.0.0.1:8081")
	t.Setenv("KMS_URL", "https://example.com")
	t.Setenv("WIREGUARD_INTERFACE", "wg0")
	t.Setenv("WIREGUARD_PEER_PUBLIC_KEY", "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=")
	t.Setenv("MODE", "AtLeastQkdRequired")

	t.Setenv("PQC_PSK_FILE", validFile)
	_, err := Parse()
	if err != nil {
		t.Errorf("Expected no error for 0600 permissions, got: %v", err)
	}

	insecureFile := tmpDir + "/insecure.key"
	os.WriteFile(insecureFile, []byte(validKey), 0644)
	t.Setenv("PQC_PSK_FILE", insecureFile)
	_, err = Parse()
	if err == nil {
		t.Error("Expected an error for insecure permissions (0644)")
	}

	worldReadableFile := tmpDir + "/world.key"
	os.WriteFile(worldReadableFile, []byte(validKey), 0647)
	t.Setenv("PQC_PSK_FILE", worldReadableFile)
	_, err = Parse()
	if err == nil {
		t.Error("Expected an error for world-readable permissions (0647)")
	}

	groupReadableFile := tmpDir + "/group.key"
	os.WriteFile(groupReadableFile, []byte(validKey), 0660)
	t.Setenv("PQC_PSK_FILE", groupReadableFile)
	_, err = Parse()
	if err == nil {
		t.Error("Expected an error for group-readable permissions (0660)")
	}
}

func TestGetEnvOrDefault(t *testing.T) {
	// Test case 1: environment variable exists
	t.Setenv("TEST_KEY", "test_value")
	result := getEnvOrDefault("TEST_KEY", "default_value")
	expected := "test_value"
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	// Test case 2: environment variable does not exist
	result = getEnvOrDefault("NON_EXISTENT_KEY", "default_value")
	expected = "default_value"
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestGetEnv(t *testing.T) {
	// Test case 1: Testing when the environment variable exists
	t.Setenv("TEST_ENV", "test_value")
	result, err := getEnv("TEST_ENV")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	expected := "test_value"
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	// Test case 2: Testing when the environment variable does not exist
	if err := os.Unsetenv("TEST_ENV"); err != nil {
		t.Fatalf("failed to unset env var: %v", err)
	}
	result, err = getEnv("TEST_ENV")
	expectedError := fmt.Errorf("[ERROR] failed to get environment variable: TEST_ENV")
	if err.Error() != expectedError.Error() {
		t.Errorf("Expected error: %v, but got: %v", expectedError, err)
	}
	if result != "" {
		t.Errorf("Expected empty string, but got %s", result)
	}
}

func TestIsQKDRequired(t *testing.T) {
	// Test case 1: Mode is "QkdAndPqcRequired"
	c := &Config{Mode: "QkdAndPqcRequired"}
	result := c.IsQKDRequired()
	expected := true
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

	// Test case 2: Mode is "AtLeastQkdRequired"
	c = &Config{Mode: "AtLeastQkdRequired"}
	result = c.IsQKDRequired()
	expected = true
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

	// Test case 3: Mode is "AtLeastPqcRequired"
	c = &Config{Mode: "AtLeastPqcRequired"}
	result = c.IsQKDRequired()
	expected = false
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

	// Test case 4: Mode is "EitherQkdOrPqcRequired"
	c = &Config{Mode: "EitherQkdOrPqcRequired"}
	result = c.IsQKDRequired()
	expected = false
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

}

func TestIsPrimary(t *testing.T) {
	psk := "shared-secret-key"
	nodeA := &Config{ArnikaID: "9999", ArnikaPSK: psk}
	nodeB := &Config{ArnikaID: "9998", ArnikaPSK: psk}

	// For each interval, the two nodes must get opposite roles
	for i := uint64(0); i < 100; i++ {
		a := nodeA.IsPrimary(i)
		b := nodeB.IsPrimary(i)
		if a == b {
			t.Fatalf("interval %d: both nodes got the same role (IsPrimary=%v)", i, a)
		}
	}

	// Deterministic: same input → same output
	for i := uint64(0); i < 50; i++ {
		first := nodeA.IsPrimary(i)
		second := nodeA.IsPrimary(i)
		if first != second {
			t.Fatalf("interval %d: IsPrimary is not deterministic", i)
		}
	}
}
