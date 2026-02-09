package services

type keyReaderRepository interface {
}

type KeyReaderService struct {
	repo keyReaderRepository
}

func NewKeyReaderService(repo keyReaderRepository) *KeyReaderService {
	return &KeyReaderService{repo: repo}
}
