package services

import "fmt"

// KeyReader is the port every key source implements.
//
// The two kinds of source differ in data, not in type. A source backed by a key
// management system produces an identifier that the peer must present to obtain
// the same key; a source that agrees its key with the peer directly produces
// none, because both sides derive that key independently. Returning the
// identifier as a value rather than splitting the port in two is what lets one
// service serve both without a type switch.
type KeyReader interface {
	// GetNewKey returns fresh key material and the identifier the peer needs to
	// obtain the same key. The identifier is empty for a source that issues
	// none.
	GetNewKey() (id string, key []byte, err error)
}

// KeyResolver is the optional half of the port, implemented only by sources
// that issue identifiers. A source that does not implement it simply has no
// identifiers to resolve, which is a fact about the source and not an error in
// it; GetKeyByID reports that to its caller rather than panicking.
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

// GetKeyByID returns the key the peer identified.
//
// The capability is checked here, at the point of use, in the ordinary Go way.
// The alternative, requiring every source to implement a method most of them
// cannot serve, is what the split port avoids.
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
