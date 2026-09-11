//go:build qkd_kms || !qkd_none

// Wiring for the kms key reader (QKD, managed). This file is the default; the
// qkd_none tag replaces it with qkdnone.go, which drops net/http and
// crypto/tls from the binary. See KEYCONTROL.md.

package main

import (
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/kms"
	"github.com/arnika-project/arnika/services"
)

// qkdCompiled reports whether this binary contains a QKD key reader. It is a
// constant, so the key_id flow main.go guards with it is eliminated at compile
// time rather than skipped at runtime.
const qkdCompiled = true

// getQKDService wires the kms key reader against the KMS named by KMS_URL.
//
// Client-certificate authentication is all-or-nothing: NewClientCertificateAuth
// returns nil unless CERTIFICATE, PRIVATE_KEY and CA_CERTIFICATE are all set,
// and the repository then falls back to a plain HTTPS client that validates
// the KMS against the system roots.
//
// Nothing is dialled here, so a KMS that is unreachable or misconfigured
// surfaces on the first key request rather than at startup.
func getQKDService(cfg *config.Config) *services.KeyReaderService {
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsRepo := kms.NewRepository(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	return services.NewKeyReaderService(kmsRepo)
}
