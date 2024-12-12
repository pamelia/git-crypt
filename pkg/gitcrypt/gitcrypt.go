package gitcrypt

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/constants"
	"github.com/pamelia/git-crypt/pkg/crypto"
	"github.com/pamelia/git-crypt/pkg/git"
	"github.com/pamelia/git-crypt/pkg/utils"
	"github.com/zalando/go-keyring"
	"log"
	"os"
	"os/exec"
)

func Init() error {
	// check if .git directory exists
	err := git.CheckGitDirectory()
	if err != nil {
		return err
	}
	// check if key file exists
	keyExists := false
	if _, err := os.Stat(constants.KeyFileName); err == nil {
		keyExists = true
	}
	if keyExists {
		err := InitKeyExists()
		if err != nil {
			return err
		}
	} else {
		err := InitNewKey()
		if err != nil {
			return err
		}
	}
	err = git.CheckAndFixGitConfig()
	if err != nil {
		return err
	}

	return nil
}

func InitKeyExists() error {
	repo, err := git.GetRepoName()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}

	// Attempt to retrieve the password from the keyring
	_, err = keyring.Get("git-crypt", repo)
	if err == nil {
		// Password already exists in the keyring
		fmt.Println("Password found in keyring.")
		return nil
	}

	// Ask for password
	userPassword, err := utils.ReadPassword("Enter password to decrypt key: ")
	if err != nil {
		return err
	}
	fmt.Printf("Ok trying to decrypt key using password %s\n", userPassword)

	// Validate the password by attempting to decrypt the encrypted key file
	data, err := os.ReadFile(constants.KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to read encrypted key file: %v", err)
	}

	// Extract the salt and encrypted key
	salt, encryptedKey := data[:16], data[16:]

	// Derive the decryption key from the provided password
	derivedKey := crypto.DeriveKey(userPassword, salt)

	_, err = crypto.DecryptData(encryptedKey, derivedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %v", err)
	}

	// Save the password to the system keyring
	err = keyring.Set("git-crypt", repo, userPassword)
	if err != nil {
		return fmt.Errorf("failed to save password to keyring: %v", err)
	}

	fmt.Println("Initialization completed successfully.")
	return nil

}

func InitNewKey() error {
	// Step 1: Prompt the user for a password
	password, err := utils.GeneratePassword()
	if err != nil {
		return fmt.Errorf("failed to generate password: %v", err)
	}
	// Step 2: Generate a new symmetric key
	symmetricKey, err := utils.GenerateRandomBytes(32) // 256-bit key
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Step 3: Derive an encryption key from the password
	salt, err := utils.GenerateRandomBytes(16) // 128-bit salt
	if err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}
	derivedKey := crypto.DeriveKey(password, salt)

	// Step 4: Encrypt the symmetric key with the derived key
	encryptedKey, err := crypto.EncryptData(symmetricKey, derivedKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %v", err)
	}

	// Step 5: Save the salt and encrypted key to disk
	dataToSave := append(salt, encryptedKey...)
	err = os.WriteFile(".git-crypt.key", dataToSave, 0600)
	if err != nil {
		return fmt.Errorf("failed to save encrypted key to disk: %v", err)
	}

	// Step 6: Save the password to the system keyring
	repo, err := git.GetRepoName()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}
	err = keyring.Set("git-crypt", repo, password)
	if err != nil {
		return fmt.Errorf("failed to save password to keyring: %v", err)
	}

	fmt.Println("Initialization completed successfully.")
	return nil

}

func Status() error {
	files, err := git.GetTrackedFiles()
	if err != nil {
		return fmt.Errorf("failed to get tracked files: %v", err)
	}

	for _, file := range files {
		status, err := crypto.CheckEncryptionStatus(file)
		if err != nil {
			fmt.Printf("Error checking file %s: %v\n", file, err)
			continue
		}

		fmt.Printf("%13s: %s\n", status, file)
	}

	return nil
}

func Lock() error {
	symmetricKey, err := crypto.GetKey(constants.KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	// Get the list of files with the `filter=git-crypt` attribute
	files, err := git.GetGitCryptFiles()
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
		if crypto.IsEncrypted(data) {
			continue
		}

		// Encrypt the file
		encryptedData, err := crypto.EncryptFileContent(data, symmetricKey)
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

func Unlock() error {
	symmetricKey, err := crypto.GetKey(constants.KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	// Get the list of files with the `filter=git-crypt` attribute
	files, err := git.GetGitCryptFiles()
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
		if !crypto.IsEncrypted(data) {
			fmt.Printf("File %s is already plaintext.\n", file)
			continue
		}

		// Decrypt the file
		plaintext, err := crypto.DecryptFileContent(data, symmetricKey)
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

func Decrypt() {
	symmetricKey, err := crypto.GetKey(constants.KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	err = crypto.DecryptStdinStdout(symmetricKey)
	if err != nil {
		log.Fatalf("Error decrypting stdin/stdout: %v", err)
	}
}

func Encrypt() {
	symmetricKey, err := crypto.GetKey(constants.KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	err = crypto.EncryptStdinStdout(symmetricKey)
	if err != nil {
		log.Fatalf("Error encrypting stdin/stdout: %v", err)
	}
}

func Debug() {
	fmt.Println("Hello from git-crypt debug")

	inputFile := "test.txt"
	inputFileContent := []byte("Hello, world!")
	err := os.WriteFile(inputFile, inputFileContent, 0600)
	if err != nil {
		log.Fatalf("Error writing test file %s: %v", inputFile, err)
	}
	encryptedFile := "test.txt.enc"
	decryptedFile := "test.txt.dec"
	// Encrypt a file
	err = crypto.EncryptDecryptFile(inputFile, encryptedFile, constants.KeyFileName, true) // Encrypt
	if err != nil {
		log.Fatalf("Error encrypting file: %v", err)
	}

	// Decrypt the file
	err = crypto.EncryptDecryptFile(encryptedFile, decryptedFile, constants.KeyFileName, false) // Decrypt
	if err != nil {
		log.Fatalf("Error decrypting file: %v", err)
	}

}
