package config

import (
	"fmt"
	"os"
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
	Interval               time.Duration // INTERVAL, Interval between key updates
	WireGuardInterface     string        // WIREGUARD_INTERFACE, Name of the WireGuard interface to configure
	WireguardPeerPublicKey string        // WIREGUARD_PEER_PUBLIC_KEY, Public key of the WireGuard peer
	PQCPSKFile             string        // PQC_PSK_FILE, Path to the PQC PSK file
}

// Use PQC returns a boolean indicating whether the PQC PSK file is set in the Config struct.
//
// No parameters.
// Returns a boolean value indicating whether the PQC PSK file is set.
func (c *Config) UsePQC() bool {
	return c.PQCPSKFile != ""
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
	interval, err := time.ParseDuration(getEnvOrDefault("INTERVAL", "10s"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse interval: %v", err)
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
			return nil, fmt.Errorf("failed to open PQC PSK file: %v", err)
		}
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
