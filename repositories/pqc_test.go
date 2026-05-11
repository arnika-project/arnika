package repositories

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilePQCRepository_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()

	emptyFile := filepath.Join(tmpDir, "empty.key")
	if err := os.WriteFile(emptyFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create empty key file: %v", err)
	}

	repo := NewFilePQCRepository(emptyFile)
	_, err := repo.GetNewKey()
	if err == nil {
		t.Error("expected error for empty key file, got nil")
	}
}

func TestFilePQCRepository_WhitespaceOnly(t *testing.T) {
	tmpDir := t.TempDir()

	wsFile := filepath.Join(tmpDir, "whitespace.key")
	if err := os.WriteFile(wsFile, []byte("   \n\t  "), 0644); err != nil {
		t.Fatalf("failed to create whitespace key file: %v", err)
	}

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
	if err := os.WriteFile(validFile, []byte(validKey), 0644); err != nil {
		t.Fatalf("failed to create valid key file: %v", err)
	}

	repo := NewFilePQCRepository(validFile)
	key, err := repo.GetNewKey()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(key) == 0 {
		t.Error("expected non-empty key")
	}
}
