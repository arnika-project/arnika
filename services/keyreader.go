package services

import "fmt"

type KeyReader interface {
	GetNewKey() (id string, key []byte, err error)
}

type KeyResolver interface {
	GetKeyByID(id string) (key []byte, err error)
}

type KeyReaderService struct {
	repo KeyReader
}

func NewKeyReaderService(repo KeyReader) *KeyReaderService {
	return &KeyReaderService{repo: repo}
}

func (s *KeyReaderService) GetNewKey() (*Key, error) {
	id, key, err := s.repo.GetNewKey()
	if err != nil {
		return nil, err
	}
	return &Key{ID: id, Key: key}, nil
}

func (s *KeyReaderService) GetKeyByID(id string) (*Key, error) {
	resolver, ok := s.repo.(KeyResolver)
	if !ok {
		return nil, fmt.Errorf("this key source issues no key identifiers, so %q cannot be resolved", id)
	}
	key, err := resolver.GetKeyByID(id)
	if err != nil {
		return nil, err
	}
	return &Key{ID: id, Key: key}, nil
}
