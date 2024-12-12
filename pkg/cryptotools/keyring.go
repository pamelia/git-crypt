package cryptotools

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/git"
	"github.com/zalando/go-keyring"
	"os"
)

func GetKey(keyFileName string) ([]byte, error) {
	// Get the repo name
	repo, err := git.GetRepoName()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get working directory: %v", err)
	}

	// Attempt to retrieve the password from the keyring
	password, err := keyring.Get("git-crypt", repo)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to retrieve password from keyring: %v", err)
	}

	// Read the encrypted key from disk
	data, err := os.ReadFile(keyFileName)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read encrypted key from disk: %v", err)
	}

	// Extract the salt and encrypted key
	salt, encryptedKey := data[:16], data[16:]

	// Derive the decryption key from the provided password
	derivedKey := DeriveKey(password, salt)

	// Decrypt the encrypted key
	symmetricKey, err := DecryptData(encryptedKey, derivedKey)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decrypt symmetric key: %v", err)
	}

	return symmetricKey, nil
}
