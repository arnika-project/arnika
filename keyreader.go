package main

import (
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
	"github.com/arnika-project/arnika/services"
)

func getQKDService(cfg *config.Config) *services.KeyReaderService {
	kmsAuth := repositories.NewKMSClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsRepo := repositories.NewHTTPKMSRepository(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	return services.NewKeyReaderService(new(services.KeyReaderManaged(kmsRepo)))
}

func getPQCService(cfg *config.Config) *services.KeyReaderService {
	pqcRepo := repositories.NewFilePQCRepository(cfg.PQCPSKFile)
	return services.NewKeyReaderService(new(services.KeyReaderUnmanaged(pqcRepo)))
}
