// Package config handles application configuration loading and validation.
package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// minArnikaPSKLen is the minimum accepted length of ARNIKA_PSK. The
// ~128-bit post-Grover authentication claim assumes 256 bits of real
// entropy, which a human-chosen passphrase does not provide.
const minArnikaPSKLen = 32

// Config contains the configuration values for the arnika service.
type Config struct {
	ListenAddress          string        // LISTEN_ADDRESS, Address to listen on for incoming connections
	ServerAddress          string        // SERVER_ADDRESS, Address of the arnika server
	ArnikaID               string        // ARNIKA_ID, up to 5-digit identifier (defaults to port number from ListenAddress)
	ArnikaPSK              []byte        // ARNIKA_PSK, PSK to authenticate with the other peer
	Certificate            string        // CERTIFICATE, Path to the client certificate file
	PrivateKey             string        // PRIVATE_KEY, Path to the client key file
	CACertificate          string        // CA_CERTIFICATE, Path to the CA certificate file
	ArnikaPeerTimeout      time.Duration // ARNIKA_PEER_TIMEOUT, TCP connection timeout for peer connections
	KMSURL                 string        // KMS_URL, URL of the KMS server
	KMSHTTPTimeout         time.Duration // KMS_HTTP_TIMEOUT, HTTP connection timeout
	KMSBackoffMaxRetries   int           // KMS_BACKOFF_MAX_RETRIES, Maximum number of retries for KMS requests
	KMSBackoffBaseDelay    time.Duration // KMS_BACKOFF_BASE_DELAY, Base delay for KMS request retries, will get exponentially increased
	KMSRetryInterval       time.Duration // KMS_RETRY_INTERVAL, Interval between KMS request retries
	Interval               time.Duration // INTERVAL, Interval between key updates
	WireGuardInterface     string        // WIREGUARD_INTERFACE, Name of the WireGuard interface to configure
	WireguardPeerPublicKey string        // WIREGUARD_PEER_PUBLIC_KEY, Public key of the WireGuard peer
	PQCEnabled             bool          // PQC_ENABLED, Enables the pqc-hpke key agreement with the peer
	PQCRoundInterval       time.Duration // PQC_ROUND_INTERVAL, Period of the PQC key agreement
	PQCRoundTimeout        time.Duration // PQC_ROUND_TIMEOUT, Per-round deadline, must be shorter than PQC_ROUND_INTERVAL
	PQCMaxKeyAge           time.Duration // PQC_MAX_KEY_AGE, Staleness threshold for the agreed PQC key
	Mode                   string        // MODE, Operation mode ("QkdAndPqcRequired", "AtLeastQkdRequired", "AtLeastPqcRequired", "EitherQkdOrPqcRequired")
	RateLimit              int           // RATE_LIMIT, Max requests per IP per window
	RateWindow             time.Duration // RATE_WINDOW, Window duration for rate limiting
	MaxClockSkew           time.Duration // MAX_CLOCK_SKEW, allowed timestamp difference as duration (replay protection)
}

// UsePQC reports whether the PQC key agreement is enabled.
func (c *Config) UsePQC() bool {
	return c.PQCEnabled
}

func (c *Config) IsPQCRequired() bool {
	return c.Mode == "QkdAndPqcRequired" || c.Mode == "AtLeastPqcRequired"
}

// ValidateKeySources rejects a configuration the compiled-in key readers
// cannot serve. Readers are selected by build tag (see KEYCONTROL.md), so a
// binary can lack the reader a MODE demands; catching that here keeps the
// failure at startup instead of at the first rotation, where it would only
// invalidate the tunnel.
//
// Parameters:
//   - qkdCompiled: the wiring constant of the QKD family, true unless the
//     binary was built with qkd_none. Callers pass the constant, never a
//     configuration value.
//
// Returns nil if this binary can serve cfg. Returns an error if KMS_URL is
// missing while a QKD reader is compiled in, if KMS_URL is set while it is
// not, or if MODE or PQC_ENABLED name key material this binary cannot produce.
// Call it directly after Parse, before any key is due.
func (c *Config) ValidateKeySources(qkdCompiled bool) error {
	if qkdCompiled && c.KMSURL == "" {
		return fmt.Errorf("[ERROR] KMS_URL is not set")
	}
	if !qkdCompiled {
		if c.KMSURL != "" {
			return fmt.Errorf("[ERROR] KMS_URL is set but this binary was built without a QKD key reader (build tag qkd_none)")
		}
		// Only AtLeastPqcRequired is servable: a QKD-requiring mode fails every
		// interval, and EitherQkdOrPqcRequired would permit running with no key
		// material at all. Both only ever invalidate the tunnel.
		if c.IsQKDRequired() || !c.IsPQCRequired() {
			return fmt.Errorf("[ERROR] this binary was built without a QKD key reader (build tag qkd_none), which requires MODE=AtLeastPqcRequired, got %s", c.Mode)
		}
		if !c.UsePQC() {
			return fmt.Errorf("[ERROR] this binary was built without a QKD key reader (build tag qkd_none), so PQC_ENABLED must not be false")
		}
	}
	return nil
}

func (c *Config) IsQKDRequired() bool {
	return c.Mode == "QkdAndPqcRequired" || c.Mode == "AtLeastQkdRequired"
}

// IsPrimary computes a deterministic role for the current interval using
// HMAC-SHA256(ArnikaPSK, intervalNum). The first byte of the hash is XORed
// with ArnikaID (parsed as int, truncated to uint8). The node whose result
// has the lowest bit == 0 is PRIMARY for that interval. Because two peers
// with different ArnikaIDs XOR different values, they get opposite results.
func (c *Config) IsPrimary(intervalNum uint64) bool {
	mac := hmac.New(sha256.New, c.ArnikaPSK)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], intervalNum)
	mac.Write(buf[:])
	h := mac.Sum(nil)

	id, _ := strconv.Atoi(c.ArnikaID) // always valid, checked during Parse
	xored := h[0] ^ byte(id)
	return xored&1 == 0
}

func (c *Config) PrintStartupConfig() {
	fmt.Println("=== Arnika Configuration ===")
	fmt.Printf("Arnika Mode:              %s\n", c.Mode)
	fmt.Printf("Arnika Interval:          %s\n", c.Interval)
	fmt.Printf("Arnika ID:                %s\n", c.ArnikaID)
	fmt.Printf("Arnika PSK:               %s\n", redactSecret(c.ArnikaPSK))
	fmt.Printf("Arnika Listen Address:    %s\n", c.ListenAddress)
	fmt.Printf("Arnika Peer Address:      %s\n", c.ServerAddress)
	fmt.Printf("Arnika Peer Timeout:			%s\n", c.ArnikaPeerTimeout)
	if c.KMSURL != "" {
		fmt.Printf("KMS URL:                  %s\n", c.KMSURL)
		fmt.Printf("KMS HTTP Timeout:         %s\n", c.KMSHTTPTimeout)
		fmt.Printf("KMS Backoff Max Retries:  %d\n", c.KMSBackoffMaxRetries)
		fmt.Printf("KMS Backoff Base Delay:   %s\n", c.KMSBackoffBaseDelay)
		fmt.Printf("KMS Retry Interval:       %s\n", c.KMSRetryInterval)
	} else {
		fmt.Println("QKD key reader:           NOT COMPILED IN (build tag qkd_none)")
	}

	if c.Certificate != "" {
		fmt.Printf("Client Certificate:       %s\n", c.Certificate)
	} else {
		fmt.Println("Client Certificate:       (not configured)")
	}
	if c.PrivateKey != "" {
		fmt.Printf("Private Key:              %s\n", c.PrivateKey)
	} else {
		fmt.Println("Private Key:              (not configured)")
	}
	if c.CACertificate != "" {
		fmt.Printf("CA Certificate:           %s\n", c.CACertificate)
	} else {
		fmt.Println("CA Certificate:           (not configured)")
	}
	if c.UsePQC() {
		fmt.Printf("PQC key agreement:        ENABLED (pqc-hpke)\n")
		fmt.Printf("PQC round interval:       %s\n", c.PQCRoundInterval)
		fmt.Printf("PQC round timeout:        %s\n", c.PQCRoundTimeout)
		fmt.Printf("PQC max key age:          %s (%.1f x round interval)\n",
			c.PQCMaxKeyAge, float64(c.PQCMaxKeyAge)/float64(c.PQCRoundInterval))
	} else {
		fmt.Println("PQC key agreement:        DISABLED")
	}

	fmt.Printf("WireGuard Interface:      %s\n", c.WireGuardInterface)
	fmt.Printf("WireGuard Peer PublicKey: %s\n", c.WireguardPeerPublicKey)
	fmt.Printf("Rate Limit:               %d\n", c.RateLimit)
	fmt.Printf("Rate Window:              %s\n", c.RateWindow)
	fmt.Printf("Max Clock Skew:           %s\n", c.MaxClockSkew)
	fmt.Println("============================")
}

// redactSecret keeps secret material out of the startup config dump, which is
// written to stdout and from there into journals and log aggregation.
func redactSecret(b []byte) string {
	if len(b) == 0 {
		return "(unset)"
	}
	return fmt.Sprintf("(set, %d bytes)", len(b))
}

// ZeroSecrets wipes the secret material held on the Config.
//
// ArnikaPSK is a []byte and not a string precisely so that this is possible:
// Go strings are immutable, so a secret held as one stays in the heap for the
// process lifetime with no way to overwrite it.
func (c *Config) ZeroSecrets() {
	clear(c.ArnikaPSK)
}

// Parse parses the configuration values from environment variables and returns a Config pointer.
//
// No parameters.
// Returns a pointer to a Config struct and an error.
func Parse() (*Config, error) {
	config := &Config{}
	var err error
	config.ListenAddress, err = getEnv("LISTEN_ADDRESS")
	if err != nil {
		return nil, err
	}
	config.ServerAddress, err = getEnv("SERVER_ADDRESS")
	if err != nil {
		return nil, err
	}
	// Parse ArnikaID from environment or extract port from ListenAddress
	arnikaIDEnv := os.Getenv("ARNIKA_ID")
	if arnikaIDEnv != "" {
		// Validate that it's a number with less than 6 digits
		if len(arnikaIDEnv) > 5 {
			return nil, fmt.Errorf("[ERROR] ARNIKA_ID must be smaller than 6 digits, got: %s", arnikaIDEnv)
		}
		if _, err := strconv.Atoi(arnikaIDEnv); err != nil {
			return nil, fmt.Errorf("[ERROR] ARNIKA_ID must be a valid number: %w", err)
		}
		config.ArnikaID = arnikaIDEnv
	} else {
		// Extract port from ListenAddress as default
		_, port, err := net.SplitHostPort(config.ListenAddress)
		if err != nil {
			return nil, fmt.Errorf("[ERROR] failed to extract port from LISTEN_ADDRESS: %w", err)
		}
		config.ArnikaID = port
	}
	config.Certificate = getEnvOrDefault("CERTIFICATE", "")
	config.PrivateKey = getEnvOrDefault("PRIVATE_KEY", "")
	config.CACertificate = getEnvOrDefault("CA_CERTIFICATE", "")
	config.KMSURL = getEnvOrDefault("KMS_URL", "")
	kmsHTTPTimeout, err := time.ParseDuration(getEnvOrDefault("KMS_HTTP_TIMEOUT", "10s"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse KMS_HTTP_TIMEOUT: %w", err)
	}
	config.KMSHTTPTimeout = kmsHTTPTimeout
	interval, err := time.ParseDuration(getEnvOrDefault("INTERVAL", "10s"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse INTERVAL: %w", err)
	}
	config.Interval = interval
	config.WireGuardInterface, err = getEnv("WIREGUARD_INTERFACE")
	if err != nil {
		return nil, err
	}
	config.WireguardPeerPublicKey, err = getEnv("WIREGUARD_PEER_PUBLIC_KEY")
	if err != nil {
		return nil, err
	}
	// PQC key material is now agreed with the peer over HPKE and never touches
	// disk, so there is no file path and no permission check.
	config.PQCEnabled = getEnvOrDefault("PQC_ENABLED", "true") == "true"
	config.PQCRoundInterval, err = time.ParseDuration(getEnvOrDefault("PQC_ROUND_INTERVAL", config.Interval.String()))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse PQC_ROUND_INTERVAL: %w", err)
	}
	// Derived from PQC_ROUND_INTERVAL, not INTERVAL: the key ages against the
	// PQC round cadence, so deriving it from the QKD interval made a key stale
	// for most of every healthy round whenever an operator overrode only
	// PQC_ROUND_INTERVAL. Two rounds is one round of loss tolerance.
	config.PQCMaxKeyAge, err = time.ParseDuration(getEnvOrDefault("PQC_MAX_KEY_AGE", (2 * config.PQCRoundInterval).String()))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse PQC_MAX_KEY_AGE: %w", err)
	}
	config.PQCRoundTimeout, err = time.ParseDuration(getEnvOrDefault("PQC_ROUND_TIMEOUT", (config.Interval / 4).String()))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse PQC_ROUND_TIMEOUT: %w", err)
	}
	if config.PQCEnabled {
		if config.PQCRoundInterval <= 0 {
			return nil, fmt.Errorf("[ERROR] PQC_ROUND_INTERVAL must be positive, got %s", config.PQCRoundInterval)
		}
		// A round that outlives its interval would overlap the next one.
		if config.PQCRoundTimeout <= 0 || config.PQCRoundTimeout >= config.PQCRoundInterval {
			return nil, fmt.Errorf("[ERROR] PQC_ROUND_TIMEOUT (%s) must be positive and shorter than PQC_ROUND_INTERVAL (%s)",
				config.PQCRoundTimeout, config.PQCRoundInterval)
		}
		if config.PQCMaxKeyAge <= 0 {
			return nil, fmt.Errorf("[ERROR] PQC_MAX_KEY_AGE must be positive, got %s", config.PQCMaxKeyAge)
		}
		// A key that goes stale within its own round interval is stale for part
		// of every healthy round, and in a PQC-requiring mode each rotation in
		// that window invalidates the tunnel. Reject it rather than let it
		// surface as intermittent handshake failures.
		if config.PQCMaxKeyAge <= config.PQCRoundInterval {
			return nil, fmt.Errorf("[ERROR] PQC_MAX_KEY_AGE (%s) must be longer than PQC_ROUND_INTERVAL (%s)",
				config.PQCMaxKeyAge, config.PQCRoundInterval)
		}
	}
	config.Mode = getEnvOrDefault("MODE", "QkdAndPqcRequired")
	if config.Mode != "QkdAndPqcRequired" && config.Mode != "AtLeastQkdRequired" && config.Mode != "AtLeastPqcRequired" && config.Mode != "EitherQkdOrPqcRequired" {
		return nil, fmt.Errorf("[ERROR] invalid MODE value: %s", config.Mode)
	}
	config.KMSBackoffMaxRetries, err = strconv.Atoi(getEnvOrDefault("KMS_BACKOFF_MAX_RETRIES", "5"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse KMS_BACKOFF_MAX_RETRIES: %w", err)
	}
	kmsBackoffBaseDelay, err := time.ParseDuration(getEnvOrDefault("KMS_BACKOFF_BASE_DELAY", "100ms"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse KMS_BACKOFF_BASE_DELAY: %w", err)
	}
	config.KMSBackoffBaseDelay = kmsBackoffBaseDelay
	config.KMSRetryInterval, err = time.ParseDuration(getEnvOrDefault("KMS_RETRY_INTERVAL", (config.Interval / 2).String()))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse KMS_RETRY_INTERVAL: %w", err)
	}
	if !config.UsePQC() && config.IsPQCRequired() {
		return nil, fmt.Errorf("[ERROR] PQC_ENABLED is false but MODE is %s, which requires a PQC key", config.Mode)
	}
	// ARNIKA_PSK is the sole authentication root for the peer protocol: an
	// unset value makes the HMAC key SHA-256(""), a publicly computable
	// constant, and anyone can then inject valid packets.
	//
	// Held as []byte, not string: every consumer needs bytes, so a string field
	// would mean a fresh, unclearable heap copy of the authentication root on
	// every interval and every PQC round. One conversion here, cleared by
	// ZeroSecrets, replaces all of them.
	config.ArnikaPSK = []byte(getEnvOrDefault("ARNIKA_PSK", ""))
	if len(config.ArnikaPSK) == 0 {
		return nil, fmt.Errorf("[ERROR] ARNIKA_PSK is not set; refusing to start")
	}
	if len(config.ArnikaPSK) < minArnikaPSKLen {
		return nil, fmt.Errorf(
			"[ERROR] ARNIKA_PSK is %d bytes, minimum %d; generate with: openssl rand -base64 32",
			len(config.ArnikaPSK), minArnikaPSKLen)
	}
	config.ArnikaPeerTimeout, err = time.ParseDuration(getEnvOrDefault("ARNIKA_PEER_TIMEOUT", "500ms"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse ARNIKA_PEER_TIMEOUT: %w", err)
	}
	rateLimitStr := getEnvOrDefault("RATE_LIMIT", "30")
	config.RateLimit, err = strconv.Atoi(rateLimitStr)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse RATE_LIMIT: %w", err)
	}
	rateWindowStr := getEnvOrDefault("RATE_WINDOW", "1m")
	config.RateWindow, err = time.ParseDuration(rateWindowStr)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse RATE_WINDOW: %w", err)
	}
	// Parse max clock skew config
	maxClockSkewStr := getEnvOrDefault("MAX_CLOCK_SKEW", "1m")
	maxClockSkew, err := time.ParseDuration(maxClockSkewStr)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse MAX_CLOCK_SKEW: %w", err)
	}
	config.MaxClockSkew = maxClockSkew
	return config, nil
}

// GetEnvOrDefault returns the value of the environment variable named by the key.
// If the variable is not present, returns defaultValue without checking
// the rest of the environment
//
// Parameters:
// - key: the name of the environment variable to retrieve the value from.
// - defaultValue: the default value to return if the environment variable is not present.
//
// Return type:
// - string: the value of the environment variable, or the default value if the
// environment variable is not present.
func getEnvOrDefault(key, defaultValue string) string {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	return v
}

// getEnv retrieves the value of the environment variable named by the key
//
// Parameters:
// - key: the name of the environment variable to retrieve the value from.
//
// Return type:
// - string: the value of the environment variable.
// - error: an error if the environment variable is not present.
func getEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("[ERROR] failed to get environment variable: %s", key)
	}
	return v, nil
}
