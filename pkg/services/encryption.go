package services

import "github.com/pamelia/git-crypt/pkg/constants"

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
