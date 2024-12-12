package utils

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/pamelia/git-crypt/pkg/services"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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

func GetGitCryptFiles() ([]string, error) {
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

	if services.IsEncrypted(data) {
		return "encrypted", nil
	}
	return "not encrypted", nil
}
