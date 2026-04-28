package services

type keyWriterRepository interface {
	InvalidateTunnel() error // Invalidate the WireGuard session by setting a random PSK
	SetPSK(psk string) error // Set the PSK on the WireGuard interface
}

type KeyWriterService struct {
	repo keyWriterRepository
}

func NewKeyWriterService(repo keyWriterRepository) *KeyWriterService {
	return &KeyWriterService{repo: repo}
}

func (s *KeyWriterService) InvalidateTunnel() error {

	return s.repo.InvalidateTunnel()
}

func (s *KeyWriterService) SetPSK(psk string) error {
	return s.repo.SetPSK(psk)
}
