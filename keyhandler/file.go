package keyhandler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// File writes PSKs to a file on disk.
type File struct {
	path string
}

func NewFile(path string) (*File, error) {
	if path == "" {
		return nil, fmt.Errorf("KEY_OUTPUT_FILE is required when KEY_HANDLER is set to file")
	}
	return &File{path: path}, nil
}

func (f *File) SetKey(psk string) error {
	return os.WriteFile(f.path, []byte(psk+"\n"), 0600)
}

func (f *File) Invalidate() error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}
	return f.SetKey(base64.StdEncoding.EncodeToString(key[:]))
}
