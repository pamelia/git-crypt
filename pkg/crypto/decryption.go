package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/pamelia/git-crypt/pkg/constants"
	"io"
	"os"
)

func DecryptData(encrypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func DecryptFileContent(data, key []byte) ([]byte, error) {
	if IsEncrypted(data) {
		return nil, errors.New("file does not have a valid encryption header")
	}

	// Remove the file header
	encryptedData := data[len(constants.FileHeader):]

	return DecryptData(encryptedData, key)
}

func DecryptStdinStdout(symmetricKey []byte) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %v", err)
	}

	decryptedData, err := DecryptFileContent(data, symmetricKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	_, err = os.Stdout.Write(decryptedData)
	if err != nil {
		return fmt.Errorf("failed to write to stdout: %v", err)
	}

	return nil
}
