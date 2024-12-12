package services

import (
	"crypto/sha256"
	"github.com/pamelia/git-crypt/pkg/constants"
	"golang.org/x/crypto/pbkdf2"
)

func IsEncrypted(data []byte) bool {
	// Skip leading null bytes
	for len(data) > 0 && data[0] == 0 {
		data = data[1:]
	}

	// Check if the remaining data is long enough to contain the header
	if len(data) < len(constants.FileHeader) {
		return false
	}

	// Compare the file header
	return string(data[:len(constants.FileHeader)]) == string(constants.FileHeader)
}

func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 200000, 32, sha256.New)
}
