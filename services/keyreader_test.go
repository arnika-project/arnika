package services

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// managedReader issues identifiers and can resolve them, like the KMS reader.
type managedReader struct{ id string }

func (m managedReader) GetNewKey() (string, []byte, error) {
	return m.id, []byte("managed-key"), nil
}

func (m managedReader) GetKeyByID(id string) ([]byte, error) {
	if id != m.id {
		return nil, errors.New("unknown id")
	}
	return []byte("managed-key"), nil
}

// unmanagedReader issues no identifiers and implements no KeyResolver, like the
// pqc-hpke reader.
type unmanagedReader struct{}

func (unmanagedReader) GetNewKey() (string, []byte, error) {
	return "", []byte("agreed-key"), nil
}

func TestGetNewKeyCarriesTheIdentifierWhenTheSourceIssuesOne(t *testing.T) {
	key, err := NewKeyReaderService(managedReader{id: "abc"}).GetNewKey()
	if err != nil {
		t.Fatalf("GetNewKey: %v", err)
	}
	if key.ID != "abc" {
		t.Errorf("ID = %q, want %q", key.ID, "abc")
	}

	key, err = NewKeyReaderService(unmanagedReader{}).GetNewKey()
	if err != nil {
		t.Fatalf("GetNewKey: %v", err)
	}
	if key.ID != "" {
		t.Errorf("ID = %q, want empty for a source that issues none", key.ID)
	}
}

// A source with nothing to resolve must report that, not panic and not pretend.
func TestGetKeyByIDOnASourceWithoutIdentifiers(t *testing.T) {
	got, err := NewKeyReaderService(unmanagedReader{}).GetKeyByID("abc")
	if err == nil {
		t.Fatalf("GetKeyByID returned %v, want an error", got)
	}
	if !strings.Contains(err.Error(), "abc") {
		t.Errorf("error %q does not name the identifier that could not be resolved", err)
	}
}

func TestGetKeyByIDOnASourceWithIdentifiers(t *testing.T) {
	key, err := NewKeyReaderService(managedReader{id: "abc"}).GetKeyByID("abc")
	if err != nil {
		t.Fatalf("GetKeyByID: %v", err)
	}
	if key.ID != "abc" || !bytes.Equal(key.Key, []byte("managed-key")) {
		t.Errorf("got %q/%q, want abc/managed-key", key.ID, key.Key)
	}
}
