package cryptotools

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/git"
	"github.com/zalando/go-keyring"
	"os"
	"path/filepath"
)

func GetKey(keyFileName string) ([]byte, error) {
	// First, locate the Git repository root.
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %v", err)
	}

	repoRoot, err := git.FindGitRoot(wd)
	if err != nil {
		return nil, fmt.Errorf("failed to find git root: %v", err)
	}

	// The repo name is the base folder of the Git root (for keyring lookups).
	repo := filepath.Base(repoRoot)

	// Retrieve the password from the keyring using the repo name.
	password, err := keyring.Get("git-crypt", repo)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve password from keyring: %v", err)
	}

	// Build a path to keyFileName relative to the repo root.
	keyFilePath := filepath.Join(repoRoot, keyFileName)

	// Read the encrypted key from disk
	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key from disk: %v", err)
	}

	// Extract the salt and encrypted key
	salt, encryptedKey := data[:16], data[16:]

	// Derive the decryption key from the provided password
	derivedKey := DeriveKey(password, salt)

	// Decrypt the encrypted key
	symmetricKey, err := DecryptData(encryptedKey, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt symmetric key: %v", err)
	}

	return symmetricKey, nil
}
