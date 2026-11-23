//go:build qkd_kms || !qkd_none

package main

import (
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
	"github.com/arnika-project/arnika/repositories/kms"
	"github.com/arnika-project/arnika/services"
)

// qkdCompiled is a constant so the compiler drops the key_id flow from qkd_none builds.
const qkdCompiled = true

// getQKDService returns the external key source: ETSI GS QKD 014 by default,
// or SKIP when KMS_PROTOCOL=skip. Both are managed sources and share the same
// key_id flow.
func getQKDService(cfg *config.Config) *services.KeyReaderService {
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	if cfg.UsesSKIP() {
		skipRepo := repositories.NewSKIPRepository(
			cfg.KMSURL,
			cfg.SKIPRemoteSystemID,
			cfg.KMSHTTPTimeout,
			cfg.KMSBackoffMaxRetries,
			cfg.KMSBackoffBaseDelay,
			kmsAuth,
		)
		return services.NewKeyReaderService(skipRepo)
	}
	kmsRepo := kms.NewRepository(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	return services.NewKeyReaderService(kmsRepo)
}
