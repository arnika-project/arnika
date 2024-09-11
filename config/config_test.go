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
	// Mocking environment variables for testing
	t.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080")
	t.Setenv("SERVER_ADDRESS", "127.0.0.1:8081")
	t.Setenv("KMS_URL", "https://example.com")
	t.Setenv("WIREGUARD_INTERFACE", "wg0")
	t.Setenv("WIREGUARD_PEER_PUBLIC_KEY", "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=")

	// Test case 1: All environment variables present
	expectedConfig := &Config{
		ListenAddress:          "127.0.0.1:8080",
		ServerAddress:          "127.0.0.1:8081",
		Certificate:            "", // Default value for Certificate
		PrivateKey:             "", // Default value for PrivateKey
		CACertificate:          "", // Default value for CACertificate
		KMSURL:                 "https://example.com",
		Interval:               time.Second * 10, // Default value for Interval
		WireGuardInterface:     "wg0",
		WireguardPeerPublicKey: "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=",
		PQCPSKFile:             "", // Default value for PQCPSKFile
	}
	result, err := Parse()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// Assert the values of the config struct here
	if reflect.DeepEqual(result, expectedConfig) != true {
		t.Errorf("Expected config	%#v, but got %#v", expectedConfig, result)
	}

	// Test case 2: Missing environment variable
	for _, mandatoryEnvVar := range []string{"LISTEN_ADDRESS", "SERVER_ADDRESS", "KMS_URL", "WIREGUARD_INTERFACE", "WIREGUARD_PEER_PUBLIC_KEY"} {
		os.Unsetenv(mandatoryEnvVar)
		_, err = Parse()
		if err == nil {
			t.Errorf("Expected an error for missing %s", mandatoryEnvVar)
		}
		os.Setenv(mandatoryEnvVar, fmt.Sprintf("value_of_%s", mandatoryEnvVar))
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
	os.Unsetenv("TEST_ENV")
	result, err = getEnv("TEST_ENV")
	expectedError := fmt.Errorf("Failed to get environment variable: TEST_ENV")
	if err.Error() != expectedError.Error() {
		t.Errorf("Expected error: %v, but got: %v", expectedError, err)
	}
	if result != "" {
		t.Errorf("Expected empty string, but got %s", result)
	}
}
