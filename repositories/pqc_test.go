package repositories

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilePQCRepository_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()

	emptyFile := filepath.Join(tmpDir, "empty.key")
	os.WriteFile(emptyFile, []byte(""), 0644)

	repo := NewFilePQCRepository(emptyFile)
	_, err := repo.GetNewKey()
	if err == nil {
		t.Error("expected error for empty key file, got nil")
	}
}

func TestFilePQCRepository_WhitespaceOnly(t *testing.T) {
	tmpDir := t.TempDir()

	wsFile := filepath.Join(tmpDir, "whitespace.key")
	os.WriteFile(wsFile, []byte("   \n\t  "), 0644)

	repo := NewFilePQCRepository(wsFile)
	_, err := repo.GetNewKey()
	if err == nil {
		t.Error("expected error for whitespace-only key file, got nil")
	}
}

func TestFilePQCRepository_ValidKey(t *testing.T) {
	tmpDir := t.TempDir()

	validKey := "dGVzdGtleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	validFile := filepath.Join(tmpDir, "valid.key")
	os.WriteFile(validFile, []byte(validKey), 0644)

	repo := NewFilePQCRepository(validFile)
	key, err := repo.GetNewKey()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(key) == 0 {
		t.Error("expected non-empty key")
	}
}
