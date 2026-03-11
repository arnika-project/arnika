package repositories

import (
	"bufio"
	"os"
)

type FilePQCRepository struct {
	filePath string
	Managed  bool
}

func NewFilePQCRepository(filePath string) *FilePQCRepository {
	return &FilePQCRepository{filePath: filePath}
}

func (r *FilePQCRepository) GetNewKey() (string, error) {
	file, err := os.Open(r.filePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	return scanner.Text(), nil
}
