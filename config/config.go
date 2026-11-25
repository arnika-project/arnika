// Package config handles application configuration loading and validation.
package config

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"
)

// minArnikaPSKLen is 256 bits, the entropy the ~128-bit post-Grover authentication claim assumes.
const minArnikaPSKLen = 32

// Config contains the configuration values for the arnika service.
type Config struct {
	ListenAddress          string        // LISTEN_ADDRESS, set only on the backup, which listens for the primary
	ServerAddress          string        // SERVER_ADDRESS, set only on the primary: the backup's LISTEN_ADDRESS
	ArnikaPSK              []byte        // ARNIKA_PSK, PSK to authenticate with the other peer
	Certificate            string        // CERTIFICATE, Path to the client certificate file
	PrivateKey             string        // PRIVATE_KEY, Path to the client key file
	CACertificate          string        // CA_CERTIFICATE, Path to the CA certificate file
	ArnikaPeerTimeout      time.Duration // ARNIKA_PEER_TIMEOUT, wait before the first key ID resend, doubled per resend
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
	Mode                   string        // MODE, operation mode ("QkdAndPqcRequired", "AtLeastQkdRequired", "AtLeastPqcRequired", "PqcOnly", "EitherQkdOrPqcRequired")
	RateLimit              int           // RATE_LIMIT, Max requests per IP per window; zero means derive it from protocol traffic
	RateWindow             time.Duration // RATE_WINDOW, Window duration for rate limiting
	MaxClockSkew           time.Duration // MAX_CLOCK_SKEW, allowed timestamp difference as duration (replay protection)
}

func (c *Config) UsePQC() bool {
	return c.PQCEnabled
}

func (c *Config) IsPQCRequired() bool {
	return c.Mode == "QkdAndPqcRequired" || c.Mode == "AtLeastPqcRequired" || c.IsPQCOnly()
}

func (c *Config) IsPQCOnly() bool {
	return c.Mode == "PqcOnly"
}

func (c *Config) ValidateKeySources(qkdCompiled bool) error {
	if c.IsPQCOnly() {
		if !c.UsePQC() {
			return fmt.Errorf("[ERROR] PQC_ENABLED is false but MODE is PqcOnly")
		}
		return nil
	}
	if qkdCompiled && c.KMSURL == "" {
		return fmt.Errorf("[ERROR] KMS_URL is not set")
	}
	if !qkdCompiled {
		if c.KMSURL != "" {
			return fmt.Errorf("[ERROR] KMS_URL is set but this binary was built without a QKD key reader (build tag qkd_none)")
		}
		if c.IsQKDRequired() || !c.IsPQCRequired() { // EitherQkdOrPqcRequired would allow running with no key material
			return fmt.Errorf(
				"[ERROR] this binary was built without a QKD key reader (build tag qkd_none), which requires MODE=AtLeastPqcRequired or PqcOnly, got %s",
				c.Mode,
			)
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

// IsPrimary reports whether this node knows its peer's address, which makes it the one that starts every exchange.
func (c *Config) IsPrimary() bool {
	return c.ServerAddress != ""
}

// Role names this node's fixed role for logs and the startup banner.
func (c *Config) Role() string {
	if c.IsPrimary() {
		return "primary"
	}
	return "backup"
}

func (c *Config) PrintStartupConfig() {
	fmt.Println("=== Arnika Configuration ===")
	fmt.Printf("Arnika Mode:              %s\n", c.Mode)
	fmt.Printf("Arnika Interval:          %s\n", c.Interval)
	fmt.Printf("Arnika Role:              %s\n", c.Role())
	fmt.Printf("Arnika PSK:               %s\n", redactSecret(c.ArnikaPSK))
	if c.IsPrimary() {
		fmt.Printf("Arnika Peer Address:      %s\n", c.ServerAddress)
		fmt.Printf("Arnika Peer Timeout:      %s\n", c.ArnikaPeerTimeout)
	} else {
		fmt.Printf("Arnika Listen Address:    %s\n", c.ListenAddress)
	}
	if c.IsPQCOnly() {
		fmt.Println("QKD key reader:           DISABLED BY MODE (PqcOnly; KMS_URL ignored)")
	} else if c.KMSURL != "" {
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
	if !c.IsPrimary() {
		fmt.Printf("Rate Limit:               %d\n", c.RateLimit)
		fmt.Printf("Rate Window:              %s\n", c.RateWindow)
	}
	fmt.Printf("Max Clock Skew:           %s\n", c.MaxClockSkew)
	fmt.Println("============================")
}

func redactSecret(b []byte) string {
	if len(b) == 0 {
		return "(unset)"
	}
	return fmt.Sprintf("(set, %d bytes)", len(b))
}

// ZeroSecrets wipes ArnikaPSK, which is a []byte because a string could never be overwritten.
func (c *Config) ZeroSecrets() {
	clear(c.ArnikaPSK)
}

func Parse() (*Config, error) {
	config := &Config{}
	var err error
	config.ListenAddress = os.Getenv("LISTEN_ADDRESS")
	config.ServerAddress = os.Getenv("SERVER_ADDRESS")
	if (config.ListenAddress == "") == (config.ServerAddress == "") {
		return nil, fmt.Errorf("[ERROR] set exactly one of SERVER_ADDRESS (on the primary, the backup's address) and LISTEN_ADDRESS (on the backup)")
	}
	config.Certificate = getEnvOrDefault("CERTIFICATE", "")
	config.PrivateKey = getEnvOrDefault("PRIVATE_KEY", "")
	config.CACertificate = getEnvOrDefault("CA_CERTIFICATE", "")
	if certs := []string{config.Certificate, config.PrivateKey, config.CACertificate}; slices.Contains(certs, "") && slices.ContainsFunc(certs, func(v string) bool { return v != "" }) {
		return nil, fmt.Errorf("[ERROR] set all of CERTIFICATE, PRIVATE_KEY and CA_CERTIFICATE for KMS client-certificate authentication, or none of them")
	}
	config.KMSURL = getEnvOrDefault("KMS_URL", "")
	kmsHTTPTimeout, err := time.ParseDuration(getEnvOrDefault("KMS_HTTP_TIMEOUT", "10s"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse KMS_HTTP_TIMEOUT: %w", err)
	}
	if kmsHTTPTimeout <= 0 { // zero would disable the HTTP client timeout, so a hung KMS stalls rotation
		return nil, fmt.Errorf("[ERROR] KMS_HTTP_TIMEOUT must be positive, got %s", kmsHTTPTimeout)
	}
	config.KMSHTTPTimeout = kmsHTTPTimeout
	interval, err := time.ParseDuration(getEnvOrDefault("INTERVAL", "10s"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse INTERVAL: %w", err)
	}
	if interval <= 0 {
		return nil, fmt.Errorf("[ERROR] INTERVAL must be positive, got %s", interval)
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
	config.PQCEnabled = getEnvOrDefault("PQC_ENABLED", "true") == "true"
	config.PQCRoundInterval, err = time.ParseDuration(getEnvOrDefault("PQC_ROUND_INTERVAL", config.Interval.String()))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse PQC_ROUND_INTERVAL: %w", err)
	}
	config.PQCMaxKeyAge, err = time.ParseDuration(getEnvOrDefault("PQC_MAX_KEY_AGE", (2 * config.PQCRoundInterval).String())) // two rounds tolerate one lost round
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
		if config.PQCRoundTimeout <= 0 || config.PQCRoundTimeout >= config.PQCRoundInterval {
			return nil, fmt.Errorf("[ERROR] PQC_ROUND_TIMEOUT (%s) must be positive and shorter than PQC_ROUND_INTERVAL (%s)",
				config.PQCRoundTimeout, config.PQCRoundInterval)
		}
		if config.PQCMaxKeyAge <= 0 {
			return nil, fmt.Errorf("[ERROR] PQC_MAX_KEY_AGE must be positive, got %s", config.PQCMaxKeyAge)
		}
		if config.PQCMaxKeyAge <= config.PQCRoundInterval {
			return nil, fmt.Errorf("[ERROR] PQC_MAX_KEY_AGE (%s) must be longer than PQC_ROUND_INTERVAL (%s)",
				config.PQCMaxKeyAge, config.PQCRoundInterval)
		}
	}
	config.Mode = getEnvOrDefault("MODE", "QkdAndPqcRequired")
	if config.Mode != "QkdAndPqcRequired" && config.Mode != "AtLeastQkdRequired" &&
		config.Mode != "AtLeastPqcRequired" && config.Mode != "PqcOnly" &&
		config.Mode != "EitherQkdOrPqcRequired" {
		return nil, fmt.Errorf("[ERROR] invalid MODE value: %s", config.Mode)
	}
	config.KMSBackoffMaxRetries, err = strconv.Atoi(getEnvOrDefault("KMS_BACKOFF_MAX_RETRIES", "5"))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse KMS_BACKOFF_MAX_RETRIES: %w", err)
	}
	if config.KMSBackoffMaxRetries < 0 { // the request loop would never reach the KMS and report it as unavailable
		return nil, fmt.Errorf("[ERROR] KMS_BACKOFF_MAX_RETRIES must not be negative, got %d", config.KMSBackoffMaxRetries)
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
	if config.KMSRetryInterval <= 0 {
		return nil, fmt.Errorf("[ERROR] KMS_RETRY_INTERVAL must be positive, got %s", config.KMSRetryInterval)
	}
	if !config.UsePQC() && config.IsPQCRequired() {
		return nil, fmt.Errorf("[ERROR] PQC_ENABLED is false but MODE is %s, which requires a PQC key", config.Mode)
	}
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
	if v := os.Getenv("RATE_LIMIT"); v != "" {
		config.RateLimit, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("[ERROR] failed to parse RATE_LIMIT: %w", err)
		}
		if config.RateLimit <= 0 {
			return nil, fmt.Errorf("[ERROR] RATE_LIMIT must be positive, got %d", config.RateLimit)
		}
	}
	rateWindowStr := getEnvOrDefault("RATE_WINDOW", "1m")
	config.RateWindow, err = time.ParseDuration(rateWindowStr)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse RATE_WINDOW: %w", err)
	}
	if config.RateWindow <= 0 {
		return nil, fmt.Errorf("[ERROR] RATE_WINDOW must be positive, got %s", config.RateWindow)
	}
	maxClockSkewStr := getEnvOrDefault("MAX_CLOCK_SKEW", "1m")
	maxClockSkew, err := time.ParseDuration(maxClockSkewStr)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse MAX_CLOCK_SKEW: %w", err)
	}
	if maxClockSkew < time.Second { // timestamps are whole seconds, so less would accept almost nothing
		return nil, fmt.Errorf("[ERROR] MAX_CLOCK_SKEW must be at least 1s, got %s", maxClockSkew)
	}
	config.MaxClockSkew = maxClockSkew
	return config, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	return v
}

func getEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("[ERROR] failed to get environment variable: %s", key)
	}
	return v, nil
}
