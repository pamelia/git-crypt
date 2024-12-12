package cryptotools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/pamelia/git-crypt/pkg/constants"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
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

func EncryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesGCM.Seal(nonce, nonce, data, nil), nil
}

func EncryptFileContent(data, key []byte) ([]byte, error) {
	encryptedData, err := EncryptData(data, key)
	if err != nil {
		return nil, err
	}

	// Prepend the file header to the encrypted data
	return append(constants.FileHeader, encryptedData...), nil
}

func EncryptStdinStdout(symmetricKey []byte) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %v", err)
	}

	encryptedData, err := EncryptFileContent(data, symmetricKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	_, err = os.Stdout.Write(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to write to stdout: %v", err)
	}

	return nil
}

func CheckEncryptionStatus(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	if IsEncrypted(data) {
		return "encrypted", nil
	}
	return "not encrypted", nil
}

func EncryptDecryptFile(inputPath, outputPath, keyfilePath string, encrypt bool) error {
	symmetricKey, err := GetKey(keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to get key: %v", err)
	}

	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	var outputData []byte
	if encrypt {
		outputData, err = EncryptFileContent(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file: %v", err)
		}
	} else {
		outputData, err = DecryptFileContent(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt file: %v", err)
		}
	}

	err = os.WriteFile(outputPath, outputData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	fmt.Printf("File successfully %s and saved to %s\n", map[bool]string{true: "encrypted", false: "decrypted"}[encrypt], outputPath)
	return nil
}
