// Package services implements business logic for key management operations.
package services

import (
	"github.com/arnika-project/arnika/models"
)

type keyReaderRepository interface {
	*KeyReaderManaged | *KeyReaderUnmanaged
}

type KeyReaderUnmanaged interface {
	GetNewKey() (key []byte, err error)
}

type KeyReaderManaged interface {
	GetNewKey() (keyID string, key []byte, err error)
	GetKeyByID(keyID *string) (key []byte, err error)
}

type KeyReaderService struct {
	repoManaged   KeyReaderManaged
	repoUnmanaged KeyReaderUnmanaged
}

func NewKeyReaderService[T keyReaderRepository](repo T) *KeyReaderService {
	if managedRepo, ok := any(repo).(*KeyReaderManaged); ok && managedRepo != nil {
		return &KeyReaderService{repoManaged: *managedRepo}
	}
	if unmanagedRepo, ok := any(repo).(*KeyReaderUnmanaged); ok && unmanagedRepo != nil {
		return &KeyReaderService{repoUnmanaged: *unmanagedRepo}
	}
	panic("invalid repository type passed to NewKeyReaderService")
}

func (s *KeyReaderService) GetNewKey() (key *models.Key, err error) {
	if s.repoManaged != nil {
		id, keyBytes, err := s.repoManaged.GetNewKey()
		if err != nil {
			return nil, err
		}
		return &models.Key{ID: &id, Key: keyBytes, Type: models.KeyTypeManaged}, nil
	}
	keyBytes, err := s.repoUnmanaged.GetNewKey()
	if err != nil {
		return nil, err
	}
	return &models.Key{Key: keyBytes, Type: models.KeyTypeUnmanaged}, nil
}

func (s *KeyReaderService) GetKeyByID(keyID *string) (*models.Key, error) {
	if s.repoUnmanaged != nil {
		panic("GetKeyByID is not supported for unmanaged keys")
	}
	keyBytes, err := s.repoManaged.GetKeyByID(keyID)
	if err != nil {
		return nil, err
	}
	return &models.Key{ID: keyID, Key: keyBytes, Type: models.KeyTypeManaged}, nil
}
