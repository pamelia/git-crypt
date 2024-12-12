package utils

import (
	"crypto/rand"
	"fmt"
	"github.com/pamelia/git-crypt/pkg/services"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
	"os"
	"path/filepath"
)

func ReadPassword(msg string) (string, error) {
	fmt.Print(msg)
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}

func GeneratePassword() (string, error) {
	passwd, err := ReadPassword("Enter password to encrypt key: ")
	if err != nil {
		return "", err
	}
	passwd2, err := ReadPassword("Confirm password: ")
	if err != nil {
		return "", err
	}
	if passwd != passwd2 {
		return "", fmt.Errorf("passwords do not match")
	}
	return passwd, nil
}

func GenerateRandomBytes(length int) ([]byte, error) {
	generatedBytes := make([]byte, length)
	_, err := rand.Read(generatedBytes)
	return generatedBytes, err
}

func GetWorkingDirectory() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dirName := filepath.Base(wd)
	return dirName, nil
}

func GetKey(keyFileName string) ([]byte, error) {
	repo, err := GetWorkingDirectory()
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
	derivedKey := services.DeriveKey(password, salt)
	symmetricKey, err := services.DecryptData(encryptedKey, derivedKey)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decrypt symmetric key: %v", err)
	}

	return symmetricKey, nil
}

func EncryptDecryptFileMeh(inputPath, outputPath, keyfilePath string, encrypt bool) error {
	symmetricKey, err := GetKey(keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to get key: %v", err)
	}

	// Step 6: Read the input file
	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Step 7: Encrypt or decrypt the file data
	var outputData []byte
	if encrypt {
		outputData, err = services.EncryptFileContent(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file: %v", err)
		}
	} else {
		outputData, err = services.DecryptFileContent(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt file: %v", err)
		}
	}

	// Step 8: Write the output file
	err = os.WriteFile(outputPath, outputData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	fmt.Printf("File successfully %s and saved to %s\n", map[bool]string{true: "encrypted", false: "decrypted"}[encrypt], outputPath)
	return nil
}
