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

// Config contains the configuration values for the arnika service.
type Config struct {
	ListenAddress          string        // LISTEN_ADDRESS, Address to listen on for incoming connections
	ServerAddress          string        // SERVER_ADDRESS, Address of the arnika server
	ArnikaID               string        // ARNIKA_ID, up to 5-digit identifier (defaults to port number from ListenAddress)
	ArnikaPSK              string        // ARNIKA_PSK, PSK to authenticate with the other peer
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
	PQCPSKFile             string        // PQC_PSK_FILE, Path to the PQC PSK file
	Mode                   string        // MODE, Operation mode ("QkdAndPqcRequired", "AtLeastQkdRequired", "AtLeastPqcRequired", "EitherQkdOrPqcRequired")
	RateLimit              int           // RATE_LIMIT, Max requests per IP per window
	RateWindow             time.Duration // RATE_WINDOW, Window duration for rate limiting
	MaxClockSkew           time.Duration // MAX_CLOCK_SKEW, allowed timestamp difference as duration (replay protection)
}

// Use PQC returns a boolean indicating whether the PQC PSK file is set in the Config struct.
//
// No parameters.
// Returns a boolean value indicating whether the PQC PSK file is set.
func (c *Config) UsePQC() bool {
	return c.PQCPSKFile != ""
}

func (c *Config) IsPQCRequired() bool {
	return c.Mode == "QkdAndPqcRequired" || c.Mode == "AtLeastPqcRequired"
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
	mac := hmac.New(sha256.New, []byte(c.ArnikaPSK))
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
	fmt.Printf("Arnika PSK:               %s\n", c.ArnikaPSK)
	fmt.Printf("Arnika Listen Address:    %s\n", c.ListenAddress)
	fmt.Printf("Arnika Peer Address:      %s\n", c.ServerAddress)
	fmt.Printf("Arnika Peer Timeout:			%s\n", c.ArnikaPeerTimeout)
	fmt.Printf("KMS URL:                  %s\n", c.KMSURL)
	fmt.Printf("KMS HTTP Timeout:         %s\n", c.KMSHTTPTimeout)
	fmt.Printf("KMS Backoff Max Retries:  %d\n", c.KMSBackoffMaxRetries)
	fmt.Printf("KMS Backoff Base Delay:   %s\n", c.KMSBackoffBaseDelay)
	fmt.Printf("KMS Retry Interval:       %s\n", c.KMSRetryInterval)

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
		fmt.Printf("PQC key provider:         ENABLED\n")
		fmt.Printf("PQC key:                  %s\n", c.PQCPSKFile)
	} else {
		fmt.Println("PQC key provider:        DISABLED")
	}

	fmt.Printf("WireGuard Interface:      %s\n", c.WireGuardInterface)
	fmt.Printf("WireGuard Peer PublicKey: %s\n", c.WireguardPeerPublicKey)
	fmt.Printf("Rate Limit:               %d\n", c.RateLimit)
	fmt.Printf("Rate Window:              %s\n", c.RateWindow)
	fmt.Printf("Max Clock Skew:           %s\n", c.MaxClockSkew)
	fmt.Println("============================")
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
	config.KMSURL, err = getEnv("KMS_URL")
	if err != nil {
		return nil, err
	}
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
	config.PQCPSKFile = getEnvOrDefault("PQC_PSK_FILE", "")
	if config.PQCPSKFile != "" {
		if _, err := os.Stat(config.PQCPSKFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("[ERROR] failed to open PQC PSK file: %w", err)
		}
	}
	config.Mode = getEnvOrDefault("MODE", "AtLeastQkdRequired")
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
		return nil, fmt.Errorf("[ERROR] PQC PSK file missing as MODE is %s", config.Mode)
	}
	config.ArnikaPSK = getEnvOrDefault("ARNIKA_PSK", "")
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
