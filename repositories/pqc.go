package repositories

import (
	"encoding/base64"
	"fmt"
	"os"
	"runtime/secret"
	"strings"
)

type FilePQCRepository struct {
	filePath string
	Managed  bool
}

func NewFilePQCRepository(filePath string) *FilePQCRepository {
	return &FilePQCRepository{filePath: filePath}
}

func (r *FilePQCRepository) GetNewKey() ([]byte, error) {
	fileData, err := os.ReadFile(r.filePath)
	if err != nil {
		return nil, err
	}
	defer clear(fileData)

	var rawKey []byte
	secret.Do(func() {
		line := strings.TrimSpace(string(fileData))
		rawKey, err = base64.StdEncoding.DecodeString(line)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decode PQC key: %w", err)
	}
	return rawKey, nil
}
