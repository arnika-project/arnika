package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config contains the configuration values for the arnika service.
type Config struct {
	ListenAddress          string        // LISTEN_ADDRESS, Address to listen on for incoming connections
	ServerAddress          string        // SERVER_ADDRESS, Address of the arnika server
	Certificate            string        // CERTIFICATE, Path to the client certificate file
	PrivateKey             string        // PRIVATE_KEY, Path to the client key file
	CACertificate          string        // CA_CERTIFICATE, Path to the CA certificate file
	KMSURL                 string        // KMS_URL, URL of the KMS server
	KMSHTTPTimeout         time.Duration // KMS_HTTP_TIMEOUT, HTTP connection timeout
	KMSBackouffMaxRetries  int           // KMS_BACKOFF_MAX_RETRIES, Maximum number of retries for KMS requests
	KMSBackoffBaseDelay    time.Duration // KMS_BACKOFF_BASE_DELAY, Base delay for KMS request retries, will get exponentially increased
	KMSRetryInterval       time.Duration // KMS_RETRY_INTERVAL, Interval between KMS request retries
	Interval               time.Duration // INTERVAL, Interval between key updates
	WireGuardInterface     string        // WIREGUARD_INTERFACE, Name of the WireGuard interface to configure
	WireguardPeerPublicKey string        // WIREGUARD_PEER_PUBLIC_KEY, Public key of the WireGuard peer
	PQCPSKFile             string        // PQC_PSK_FILE, Path to the PQC PSK file
	Mode                   string        // MODE, Operation mode ("QkdAndPqcRequired", "AtLeastQkdRequired", "AtLeastPqcRequired", "EitherQkdOrPqcRequired")
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

func (c *Config) PrintStartupConfig() {
	fmt.Println("=== Arnika Configuration ===")
	fmt.Printf("Listen Address:           %s\n", c.ListenAddress)
	fmt.Printf("Server Address:           %s\n", c.ServerAddress)
	fmt.Printf("KMS URL:                  %s\n", c.KMSURL)
	fmt.Printf("KMS HTTP Timeout:         %s\n", c.KMSHTTPTimeout)
	fmt.Printf("KMS Backoff Max Retries:  %d\n", c.KMSBackouffMaxRetries)
	fmt.Printf("KMS Backoff Base Delay:   %s\n", c.KMSBackoffBaseDelay)
	fmt.Printf("KMS Retry Interval:       %s\n", c.KMSRetryInterval)
	fmt.Printf("Key Rotation Interval:    %s\n", c.Interval)
	fmt.Printf("WireGuard Interface:      %s\n", c.WireGuardInterface)
	fmt.Printf("WireGuard Peer PublicKey: %s\n", c.WireguardPeerPublicKey)
	fmt.Printf("Mode:                     %s\n", c.Mode)

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
		fmt.Printf("PQC PSK File:             %s (ENABLED)\n", c.PQCPSKFile)
	} else {
		fmt.Println("PQC PSK File:             (disabled)")
	}
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
	config.Certificate = getEnvOrDefault("CERTIFICATE", "")
	config.PrivateKey = getEnvOrDefault("PRIVATE_KEY", "")
	config.CACertificate = getEnvOrDefault("CA_CERTIFICATE", "")
	config.KMSURL, err = getEnv("KMS_URL")
	if err != nil {
		return nil, err
	}
	kmsHTTPTimeout, err := time.ParseDuration(getEnvOrDefault("KMS_HTTP_TIMEOUT", "10s"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS_HTTP_TIMEOUT: %w", err)
	}
	config.KMSHTTPTimeout = kmsHTTPTimeout
	interval, err := time.ParseDuration(getEnvOrDefault("INTERVAL", "10s"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse INTERVAL: %w", err)
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
			return nil, fmt.Errorf("failed to open PQC PSK file: %w", err)
		}
	}
	config.Mode = getEnvOrDefault("MODE", "QkdAndPqcRequired")
	if config.Mode != "QkdAndPqcRequired" && config.Mode != "AtLeastQkdRequired" && config.Mode != "AtLeastPqcRequired" && config.Mode != "EitherQkdOrPqcRequired" {
		return nil, fmt.Errorf("invalid MODE value: %s", config.Mode)
	}
	config.KMSBackouffMaxRetries, err = strconv.Atoi(getEnvOrDefault("KMS_BACKOFF_MAX_RETRIES", "5"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS_BACKOFF_MAX_RETRIES: %w", err)
	}
	kmsBackoffBaseDelay, err := time.ParseDuration(getEnvOrDefault("KMS_BACKOFF_BASE_DELAY", "100ms"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS_BACKOFF_BASE_DELAY: %w", err)
	}
	config.KMSBackoffBaseDelay = kmsBackoffBaseDelay
	config.KMSRetryInterval, err = time.ParseDuration(getEnvOrDefault("KMS_RETRY_INTERVAL", (config.Interval / 2).String()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS_RETRY_INTERVAL: %w", err)
	}
	if !config.UsePQC() && config.IsPQCRequired() {
		return nil, fmt.Errorf("PQC PSK file must be set when MODE is %s", config.Mode)
	}
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
		return "", fmt.Errorf("Failed to get environment variable: %s", key)
	}
	return v, nil
}
