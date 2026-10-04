//go:build qkd_kms || !qkd_none

package main

import (
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/kms"
	"github.com/arnika-project/arnika/services"
)

// qkdCompiled is a constant so the compiler drops the key_id flow from qkd_none builds.
const qkdCompiled = true

func getQKDService(cfg *config.Config) *services.KeyReaderService {
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsRepo := kms.NewRepository(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	return services.NewKeyReaderService(kmsRepo)
}
