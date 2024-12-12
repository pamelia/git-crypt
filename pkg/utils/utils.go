package utils

import (
	"bufio"
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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FileHeader is a predefined marker to identify encrypted files
var FileHeader = []byte("GITCRYPT")

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
	derivedKey := DeriveKey(password, salt)
	symmetricKey, err := DecryptData(encryptedKey, derivedKey)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decrypt symmetric key: %v", err)
	}

	return symmetricKey, nil
}

func isEncrypted(data []byte) bool {
	// Skip leading null bytes
	for len(data) > 0 && data[0] == 0 {
		data = data[1:]
	}

	// Check if the remaining data is long enough to contain the header
	if len(data) < len(FileHeader) {
		return false
	}

	// Compare the file header
	return string(data[:len(FileHeader)]) == string(FileHeader)
}

func EncryptFileContent(data, key []byte) ([]byte, error) {
	encryptedData, err := EncryptData(data, key)
	if err != nil {
		return nil, err
	}

	// Prepend the file header to the encrypted data
	return append(FileHeader, encryptedData...), nil
}

func decryptFileContent(data, key []byte) ([]byte, error) {
	if !isEncrypted(data) {
		return nil, errors.New("file does not have a valid encryption header")
	}

	// Remove the file header
	encryptedData := data[len(FileHeader):]

	return DecryptData(encryptedData, key)
}

func DecryptStdinStdout(symmetricKey []byte) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %v", err)
	}

	decryptedData, err := decryptFileContent(data, symmetricKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	_, err = os.Stdout.Write(decryptedData)
	if err != nil {
		return fmt.Errorf("failed to write to stdout: %v", err)
	}

	return nil
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

func checkGitConfig(section string) (bool, error) {
	file, err := os.Open(".git/config")
	if err != nil {
		return false, fmt.Errorf("failed to open .git/config: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == section {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("error reading .git/config: %v", err)
	}

	return false, nil
}

func appendGitConfig() error {
	configContent := `
[filter "git-crypt"]
        smudge = git-crypt smudge
        clean = git-crypt clean
        required = true
`
	file, err := os.OpenFile(".git/config", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open .git/config for appending: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	_, err = file.WriteString(configContent)
	if err != nil {
		return fmt.Errorf("failed to write to .git/config: %v", err)
	}

	return nil
}

func CheckAndFixGitConfig() error {
	filterExists, err := checkGitConfig("[filter \"git-crypt\"]")
	if err != nil {
		return err
	}

	if !filterExists {
		fmt.Println("Appending git-crypt configuration to .git/config...")
		err = appendGitConfig()
		if err != nil {
			return err
		}
		fmt.Println("Configuration appended successfully.")
	} else {
		fmt.Println("git-crypt configuration already exists in .git/config.")
	}

	return nil
}

func getGitCryptFiles() ([]string, error) {
	// Open the .gitattributes file
	file, err := os.Open(".gitattributes")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(".gitattributes file not found")
		}
		return nil, fmt.Errorf("failed to open .gitattributes: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	// Parse .gitattributes for patterns with filter=git-crypt
	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse lines like "*.txt filter=git-crypt"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Check if filter=git-crypt is present
		for _, part := range parts[1:] {
			if strings.Contains(part, "filter=git-crypt") {
				patterns = append(patterns, parts[0])
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading .gitattributes: %v", err)
	}

	// Use Git to list files matching the patterns
	var files []string
	for _, pattern := range patterns {
		cmd := exec.Command("git", "ls-files", "--", pattern)
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to list files for pattern %s: %v", pattern, err)
		}

		// Append the files to the result list
		matchingFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
		files = append(files, matchingFiles...)
	}

	return files, nil
}

func Lock(symmetricKey []byte) error {
	// Get the list of files with the `filter=git-crypt` attribute
	files, err := getGitCryptFiles()
	if err != nil {
		return fmt.Errorf("failed to get git-crypt files: %v", err)
	}

	for _, file := range files {
		fmt.Printf("Locking file %s...\n", file)
		// Read the file content
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", file, err)
		}

		// Skip files that are already encrypted
		if isEncrypted(data) {
			continue
		}

		// Encrypt the file
		encryptedData, err := EncryptFileContent(data, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file %s: %v", file, err)
		}

		// Write the encrypted content back to the file
		err = os.WriteFile(file, encryptedData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write encrypted file %s: %v", file, err)
		}
	}

	// Update Git index to match the working directory
	err = exec.Command("git", "update-index", "--refresh").Run()
	if err != nil {
		return fmt.Errorf("failed to update Git index: %v", err)
	}

	fmt.Println("All files locked successfully.")
	return nil
}

func Unlock(symmetricKey []byte) error {
	// Get the list of files with the `filter=git-crypt` attribute
	files, err := getGitCryptFiles()
	if err != nil {
		return fmt.Errorf("failed to get git-crypt files: %v", err)
	}

	for _, file := range files {
		fmt.Printf("Unlocking file %s...\n", file)
		// Read the file content
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", file, err)
		}

		// Skip files that are already plaintext
		if !isEncrypted(data) {
			fmt.Printf("File %s is already plaintext.\n", file)
			continue
		}

		// Decrypt the file
		plaintext, err := decryptFileContent(data, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt file %s: %v", file, err)
		}

		// Write the plaintext content back to the file
		err = os.WriteFile(file, plaintext, 0644)
		if err != nil {
			return fmt.Errorf("failed to write decrypted file %s: %v", file, err)
		}
	}

	// Update Git index to match the working directory
	err = exec.Command("git", "update-index", "--refresh").Run()
	if err != nil {
		return fmt.Errorf("failed to update Git index: %v", err)
	}

	fmt.Println("All files unlocked successfully.")
	return nil
}

// EncryptDecryptFileMeh encrypts or decrypts a file using the git-crypt tool
// This is a temporary function to test the git-crypt tool
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
		outputData, err = EncryptFileContent(fileData, symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file: %v", err)
		}
	} else {
		outputData, err = decryptFileContent(fileData, symmetricKey)
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

func CheckGitDirectory() error {
	gitPath := ".git"
	info, err := os.Stat(gitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New(".git directory does not exist")
		}
		return fmt.Errorf("failed to stat .git: %w", err)
	}

	if !info.IsDir() {
		return errors.New(".git exists but is not a directory")
	}

	return nil
}

func GetTrackedFiles() ([]string, error) {
	cmd := exec.Command("git", "ls-files")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list tracked files: %v", err)
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	return files, nil
}

func CheckEncryptionStatus(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	if isEncrypted(data) {
		return "encrypted", nil
	}
	return "not encrypted", nil
}
