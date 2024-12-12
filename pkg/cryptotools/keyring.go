package cryptotools

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/git"
	"github.com/zalando/go-keyring"
	"os"
)

func GetKey(keyFileName string) ([]byte, error) {
	repo, err := git.GetRepoName()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get working directory: %v", err)
	}
	password, err := keyring.Get("git-crypt", repo)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to retrieve password from keyring: %v", err)
	}

	data, err := os.ReadFile(keyFileName)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read encrypted key from disk: %v", err)
	}

	salt, encryptedKey := data[:16], data[16:]
	derivedKey := DeriveKey(password, salt)
	symmetricKey, err := DecryptData(encryptedKey, derivedKey)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decrypt symmetric key: %v", err)
	}

	return symmetricKey, nil
}
