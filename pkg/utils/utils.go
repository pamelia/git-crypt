package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
)

// FileHeader is a predefined marker to identify encrypted files
var FileHeader = []byte("GITCRYPTENCRYPTEDFILE")

func ReadPassword(msg string) (string, error) {
	fmt.Print(msg)
	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
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

func GetHomeDir() (string, error) {
	home := os.Getenv("HOME")
	if home != "" {
		return home, nil
	}

	// If $HOME is not set (e.g., on Windows), fall back to the os/user package
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}

	return currentUser.HomeDir, nil
}

func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
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

func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}

func GetWorkingDirectory() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Extract the base name of the directory
	dirName := filepath.Base(wd)
	return dirName, nil
}

func EncryptDecryptFileMeh(inputPath, outputPath, repo, keyfilePath string, encrypt bool) error {
	// Step 1: Retrieve the password from the keyring
	password, err := keyring.Get("git-crypt", repo)
	if err != nil {
		return fmt.Errorf("failed to retrieve password from keyring: %v", err)
	}

	// Step 2: Read the encrypted key and salt from disk
	data, err := os.ReadFile(keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted key from disk: %v", err)
	}

	// Step 3: Extract the salt and encrypted key
	salt, encryptedKey := data[:16], data[16:]

	// Step 4: Derive the decryption key from the password
	derivedKey := DeriveKey(password, salt)

	// Step 5: Decrypt the symmetric key
	symmetricKey, err := DecryptData(encryptedKey, derivedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt symmetric key: %v", err)
	}

	// Step 6: Read the input file
	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Step 7: Encrypt or decrypt the file data
	var outputData []byte
	if encrypt {
		outputData, err = EncryptData(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file: %v", err)
		}
	} else {
		outputData, err = DecryptData(fileData, symmetricKey)
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

// EncryptDecryptFile encrypts the file if it is not encrypted,
// and decrypts it if it is encrypted.
func EncryptDecryptFile(filePath string, symmetricKey []byte) error {
	// Step 1: Read the input file
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Step 2: Determine if the file is encrypted
	if isEncrypted(fileData) {
		// File is encrypted, decrypt it
		plaintext, err := decryptFileContent(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt file: %v", err)
		}

		// Save the decrypted file
		outputFilePath := filePath + ".decrypted"
		err = ioutil.WriteFile(outputFilePath, plaintext, 0644)
		if err != nil {
			return fmt.Errorf("failed to save decrypted file: %v", err)
		}

		fmt.Printf("File decrypted and saved to %s\n", outputFilePath)
	} else {
		// File is not encrypted, encrypt it
		encryptedData, err := encryptFileContent(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file: %v", err)
		}

		// Save the encrypted file
		outputFilePath := filePath + ".encrypted"
		err = ioutil.WriteFile(outputFilePath, encryptedData, 0644)
		if err != nil {
			return fmt.Errorf("failed to save encrypted file: %v", err)
		}

		fmt.Printf("File encrypted and saved to %s\n", outputFilePath)
	}

	return nil
}

// isEncrypted checks if a file is encrypted based on the header.
func isEncrypted(data []byte) bool {
	return len(data) > len(FileHeader) && bytes.Equal(data[:len(FileHeader)], FileHeader)
}

// encryptFileContent encrypts the file content with a symmetric key and adds the header.
func encryptFileContent(data, key []byte) ([]byte, error) {
	encryptedData, err := EncryptData(data, key)
	if err != nil {
		return nil, err
	}

	// Prepend the file header to the encrypted data
	return append(FileHeader, encryptedData...), nil
}

// decryptFileContent decrypts the file content after verifying the header.
func decryptFileContent(data, key []byte) ([]byte, error) {
	if !isEncrypted(data) {
		return nil, errors.New("file does not have a valid encryption header")
	}

	// Remove the file header
	encryptedData := data[len(FileHeader):]

	// Decrypt the data
	return DecryptData(encryptedData, key)
}
