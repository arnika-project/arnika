package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUsePQC(t *testing.T) {
	c := &Config{PQCEnabled: true}
	if !c.UsePQC() {
		t.Error("Expected UsePQC to be true when PQCEnabled is set")
	}

	c = &Config{}
	if c.UsePQC() {
		t.Error("Expected UsePQC to be false by default")
	}
}

const testArnikaPSK = "0123456789abcdef0123456789abcdef0123456789ab"

func TestParse_ArnikaPSKValidation(t *testing.T) {
	setValidEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080")
		t.Setenv("SERVER_ADDRESS", "127.0.0.1:8081")
		t.Setenv("KMS_URL", "https://example.com")
		t.Setenv("WIREGUARD_INTERFACE", "wg0")
		t.Setenv("WIREGUARD_PEER_PUBLIC_KEY", "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=")
		t.Setenv("MODE", "AtLeastQkdRequired")
	}

	t.Run("unset is fatal", func(t *testing.T) {
		setValidEnv(t)
		t.Setenv("ARNIKA_PSK", "")
		if _, err := Parse(); err == nil {
			t.Fatal("expected Parse to fail when ARNIKA_PSK is unset")
		}
	})

	t.Run("too short is fatal", func(t *testing.T) {
		setValidEnv(t)
		t.Setenv("ARNIKA_PSK", strings.Repeat("a", minArnikaPSKLen-1))
		if _, err := Parse(); err == nil {
			t.Fatalf("expected Parse to fail for a %d-byte ARNIKA_PSK", minArnikaPSKLen-1)
		}
	})

	t.Run("minimum length accepted", func(t *testing.T) {
		setValidEnv(t)
		t.Setenv("ARNIKA_PSK", strings.Repeat("a", minArnikaPSKLen))
		if _, err := Parse(); err != nil {
			t.Fatalf("expected Parse to accept a %d-byte ARNIKA_PSK, got %v", minArnikaPSKLen, err)
		}
	})
}

func TestRedactSecret(t *testing.T) {
	if got := redactSecret(nil); got != "(unset)" {
		t.Errorf("redactSecret(nil) = %q, want \"(unset)\"", got)
	}
	secret := "super-secret-value"
	got := redactSecret([]byte(secret))
	if strings.Contains(got, secret) {
		t.Errorf("redactSecret leaked the secret: %q", got)
	}
	if want := "(set, 18 bytes)"; got != want {
		t.Errorf("redactSecret(%q) = %q, want %q", secret, got, want)
	}
}

func TestParse(t *testing.T) {
	for _, mandatoryEnvVar := range []string{"LISTEN_ADDRESS", "SERVER_ADDRESS", "WIREGUARD_INTERFACE", "WIREGUARD_PEER_PUBLIC_KEY", "ARNIKA_PSK"} {
		_, err := Parse()
		if err == nil {
			t.Errorf("Expected an error for missing %s", mandatoryEnvVar)
		}
		t.Setenv(mandatoryEnvVar, fmt.Sprintf("value_of_%s", mandatoryEnvVar))
	}

	t.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080")
	t.Setenv("SERVER_ADDRESS", "127.0.0.1:8081")
	t.Setenv("KMS_URL", "https://example.com")
	t.Setenv("WIREGUARD_INTERFACE", "wg0")
	t.Setenv("WIREGUARD_PEER_PUBLIC_KEY", "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=")
	t.Setenv("MODE", "PqcOnly")
	t.Setenv("ARNIKA_PSK", testArnikaPSK)

	expectedConfig := &Config{
		ListenAddress:          "127.0.0.1:8080",
		ServerAddress:          "127.0.0.1:8081",
		ArnikaID:               "8080",
		ArnikaPSK:              []byte(testArnikaPSK),
		Certificate:            "",
		PrivateKey:             "",
		CACertificate:          "",
		ArnikaPeerTimeout:      time.Millisecond * 500,
		KMSURL:                 "https://example.com",
		KMSHTTPTimeout:         time.Second * 10,
		KMSBackoffMaxRetries:   5,
		KMSBackoffBaseDelay:    time.Millisecond * 100,
		KMSRetryInterval:       time.Second * 5,
		Interval:               time.Second * 10,
		WireGuardInterface:     "wg0",
		WireguardPeerPublicKey: "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=",
		PQCEnabled:             true,
		PQCRoundInterval:       time.Second * 10,
		PQCMaxKeyAge:           time.Second * 20,
		PQCRoundTimeout:        time.Millisecond * 2500,
		Mode:                   "PqcOnly",
		RateLimit:              0,
		RateWindow:             time.Minute,
		MaxClockSkew:           time.Minute,
	}
	result, err := Parse()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(result, expectedConfig) {
		t.Errorf("Expected config	%#v, but got %#v", expectedConfig, result)
	}

	t.Setenv("INTERVAL", "invalid")
	_, err = Parse()
	if err == nil {
		t.Error("Expected an error for interval parsing failure")
	}
	t.Setenv("INTERVAL", "1m")

	t.Setenv("PQC_ENABLED", "true")
	t.Setenv("PQC_ROUND_INTERVAL", "10s")
	t.Setenv("PQC_ROUND_TIMEOUT", "10s")
	_, err = Parse()
	if err == nil {
		t.Error("Expected an error when PQC_ROUND_TIMEOUT is not shorter than PQC_ROUND_INTERVAL")
	}
	t.Setenv("PQC_ROUND_TIMEOUT", "2s")
	if _, err = Parse(); err != nil {
		t.Errorf("Expected a valid PQC configuration to parse, got %v", err)
	}
}

func TestGetEnvOrDefault(t *testing.T) {
	t.Setenv("TEST_KEY", "test_value")
	result := getEnvOrDefault("TEST_KEY", "default_value")
	expected := "test_value"
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	result = getEnvOrDefault("NON_EXISTENT_KEY", "default_value")
	expected = "default_value"
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestGetEnv(t *testing.T) {
	t.Setenv("TEST_ENV", "test_value")
	result, err := getEnv("TEST_ENV")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	expected := "test_value"
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

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
	c := &Config{Mode: "QkdAndPqcRequired"}
	result := c.IsQKDRequired()
	expected := true
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

	c = &Config{Mode: "AtLeastQkdRequired"}
	result = c.IsQKDRequired()
	expected = true
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

	c = &Config{Mode: "AtLeastPqcRequired"}
	result = c.IsQKDRequired()
	expected = false
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

	c = &Config{Mode: "EitherQkdOrPqcRequired"}
	result = c.IsQKDRequired()
	expected = false
	if result != expected {
		t.Errorf("Expected %t for Mode=%s, but got %t", expected, c.Mode, result)
	}

}

func TestIsPQCOnly(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{mode: "PqcOnly", want: true},
		{mode: "AtLeastPqcRequired", want: false},
	} {
		c := &Config{Mode: tc.mode}
		if got := c.IsPQCOnly(); got != tc.want {
			t.Errorf("IsPQCOnly for Mode=%s = %t, want %t", tc.mode, got, tc.want)
		}
		if tc.mode == "PqcOnly" && !c.IsPQCRequired() {
			t.Error("PqcOnly must require PQC")
		}
	}
}

func TestIsPrimary(t *testing.T) {
	psk := []byte("shared-secret-key")
	nodeA := &Config{ArnikaID: "9999", ArnikaPSK: psk}
	nodeB := &Config{ArnikaID: "9998", ArnikaPSK: psk}

	for i := uint64(0); i < 100; i++ {
		a := nodeA.IsPrimary(i)
		b := nodeB.IsPrimary(i)
		if a == b {
			t.Fatalf("interval %d: both nodes got the same role (IsPrimary=%v)", i, a)
		}
	}

	for i := uint64(0); i < 50; i++ {
		first := nodeA.IsPrimary(i)
		second := nodeA.IsPrimary(i)
		if first != second {
			t.Fatalf("interval %d: IsPrimary is not deterministic", i)
		}
	}
}

func TestValidateKeySources(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		qkd     bool
		wantErr bool
	}{
		{"both readers, default mode", Config{KMSURL: "https://kms.example", Mode: "QkdAndPqcRequired", PQCEnabled: true}, true, false},
		{"both readers, qkd mode", Config{KMSURL: "https://kms.example", Mode: "AtLeastQkdRequired", PQCEnabled: true}, true, false},
		{"qkd reader without KMS_URL", Config{Mode: "AtLeastQkdRequired", PQCEnabled: true}, true, true},
		{"qkd_none with KMS_URL", Config{KMSURL: "https://kms.example", Mode: "AtLeastPqcRequired", PQCEnabled: true}, false, true},
		{"qkd_none, pqc required", Config{Mode: "AtLeastPqcRequired", PQCEnabled: true}, false, false},
		{"qkd_none, qkd required", Config{Mode: "AtLeastQkdRequired", PQCEnabled: true}, false, true},
		{"qkd_none, both required (the MODE default)", Config{Mode: "QkdAndPqcRequired", PQCEnabled: true}, false, true},
		{"qkd_none, either mode", Config{Mode: "EitherQkdOrPqcRequired", PQCEnabled: true}, false, true},
		{"qkd_none, pqc disabled", Config{Mode: "AtLeastPqcRequired"}, false, true},
		{"PqcOnly without a KMS reader or URL", Config{Mode: "PqcOnly", PQCEnabled: true}, false, false},
		{"PqcOnly with a compiled KMS reader and no URL", Config{Mode: "PqcOnly", PQCEnabled: true}, true, false},
		{"PqcOnly ignores a configured KMS URL", Config{KMSURL: "https://kms.example", Mode: "PqcOnly", PQCEnabled: true}, true, false},
		{"PqcOnly ignores a configured KMS URL without a KMS reader", Config{KMSURL: "https://kms.example", Mode: "PqcOnly", PQCEnabled: true}, false, false},
		{"PqcOnly requires PQC", Config{Mode: "PqcOnly"}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.ValidateKeySources(tc.qkd)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

func TestParse_PQCKeyAge(t *testing.T) {
	setValidEnv := func(t *testing.T, interval, roundInterval, maxKeyAge, roundTimeout string) {
		t.Helper()
		t.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080")
		t.Setenv("SERVER_ADDRESS", "127.0.0.1:8081")
		t.Setenv("KMS_URL", "https://example.com")
		t.Setenv("WIREGUARD_INTERFACE", "wg0")
		t.Setenv("WIREGUARD_PEER_PUBLIC_KEY", "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=")
		t.Setenv("MODE", "QkdAndPqcRequired")
		t.Setenv("ARNIKA_PSK", testArnikaPSK)
		t.Setenv("PQC_ENABLED", "true")
		t.Setenv("INTERVAL", interval)
		t.Setenv("PQC_ROUND_INTERVAL", roundInterval)
		t.Setenv("PQC_MAX_KEY_AGE", maxKeyAge)
		t.Setenv("PQC_ROUND_TIMEOUT", roundTimeout)
	}

	t.Run("unset defaults to twice the round interval", func(t *testing.T) {
		setValidEnv(t, "10s", "120s", "", "10s")
		cfg, err := Parse()
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if want := 240 * time.Second; cfg.PQCMaxKeyAge != want {
			t.Fatalf("PQCMaxKeyAge = %s, want %s", cfg.PQCMaxKeyAge, want)
		}
	})

	t.Run("equal to the round interval is fatal and names both durations", func(t *testing.T) {
		setValidEnv(t, "10s", "120s", "120s", "10s")
		_, err := Parse()
		if err == nil {
			t.Fatal("expected Parse to reject PQC_MAX_KEY_AGE == PQC_ROUND_INTERVAL")
		}
		for _, want := range []string{"2m0s", "PQC_MAX_KEY_AGE", "PQC_ROUND_INTERVAL"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err, want)
			}
		}
	})

	t.Run("shorter than the round interval is fatal", func(t *testing.T) {
		setValidEnv(t, "10s", "120s", "20s", "10s")
		if _, err := Parse(); err == nil {
			t.Fatal("expected Parse to reject a PQC_MAX_KEY_AGE shorter than PQC_ROUND_INTERVAL")
		}
	})

	t.Run("explicit valid value is retained", func(t *testing.T) {
		setValidEnv(t, "10s", "120s", "300s", "10s")
		cfg, err := Parse()
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if want := 300 * time.Second; cfg.PQCMaxKeyAge != want {
			t.Fatalf("PQCMaxKeyAge = %s, want %s", cfg.PQCMaxKeyAge, want)
		}
	})

	t.Run("ignored when PQC is disabled", func(t *testing.T) {
		setValidEnv(t, "10s", "120s", "20s", "10s")
		t.Setenv("PQC_ENABLED", "false")
		t.Setenv("MODE", "AtLeastQkdRequired")
		if _, err := Parse(); err != nil {
			t.Fatalf("Parse must not validate PQC durations with PQC disabled: %v", err)
		}
	})
}

func TestParse_RateLimit(t *testing.T) {
	setValidEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080")
		t.Setenv("SERVER_ADDRESS", "127.0.0.1:8081")
		t.Setenv("KMS_URL", "https://example.com")
		t.Setenv("WIREGUARD_INTERFACE", "wg0")
		t.Setenv("WIREGUARD_PEER_PUBLIC_KEY", "H9adDtDHXhVzSI4QMScbftvQM49wGjmBT1g6dgynsHc=")
		t.Setenv("MODE", "AtLeastQkdRequired")
		t.Setenv("ARNIKA_PSK", testArnikaPSK)
	}

	t.Run("unset leaves zero for the caller to derive", func(t *testing.T) {
		setValidEnv(t)
		cfg, err := Parse()
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.RateLimit != 0 {
			t.Fatalf("RateLimit = %d, want 0 so the protocol budget applies", cfg.RateLimit)
		}
	})

	t.Run("explicit value is retained", func(t *testing.T) {
		setValidEnv(t)
		t.Setenv("RATE_LIMIT", "500")
		cfg, err := Parse()
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.RateLimit != 500 {
			t.Fatalf("RateLimit = %d, want 500", cfg.RateLimit)
		}
	})

	t.Run("non-positive and unparseable values are fatal", func(t *testing.T) {
		for _, v := range []string{"0", "-1", "many"} {
			setValidEnv(t)
			t.Setenv("RATE_LIMIT", v)
			if _, err := Parse(); err == nil {
				t.Fatalf("expected Parse to reject RATE_LIMIT=%q", v)
			}
		}
	})
}
