package gitcrypt

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/constants"
	"github.com/pamelia/git-crypt/pkg/cryptotools"
	"github.com/pamelia/git-crypt/pkg/git"
	"github.com/pamelia/git-crypt/pkg/utils"
	"github.com/zalando/go-keyring"
	"log"
	"os"
	"os/exec"
)

func Init() error {
	// Check if .git directory exists
	err := git.CheckGitDirectory()
	if err != nil {
		return err
	}

	// Check if key file exists
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

	err = git.SetupGitConfig()
	if err != nil {
		return err
	}

	return nil
}

func InitKeyExists() error {
	// Get the repo name
	repo, err := git.GetRepoName()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}

	_, err = keyring.Get("git-crypt", repo)
	if err == nil {
		// Password already exists in the keyring
		fmt.Println("Password found in keyring, skipping initialization.")
		return nil
	}

	userPassword, err := utils.ReadPassword("Enter password to decrypt key: ")
	if err != nil {
		return err
	}

	// Validate the password by attempting to decrypt the encrypted key file
	data, err := os.ReadFile(constants.KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to read encrypted key file: %v", err)
	}

	// Extract the salt and encrypted key
	salt, encryptedKey := data[:16], data[16:]

	// Derive the decryption key from the provided password
	derivedKey := cryptotools.DeriveKey(userPassword, salt)

	// Decrypt the encrypted key
	_, err = cryptotools.DecryptData(encryptedKey, derivedKey)
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
	// Prompt the user for a password
	password, err := utils.GeneratePassword()
	if err != nil {
		return fmt.Errorf("failed to generate password: %v", err)
	}

	// Generate a new symmetric key
	symmetricKey, err := utils.GenerateRandomBytes(32) // 256-bit key
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Derive an encryption key from the password
	salt, err := utils.GenerateRandomBytes(16) // 128-bit salt
	if err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}
	derivedKey := cryptotools.DeriveKey(password, salt)

	// Encrypt the symmetric key with the derived key
	encryptedKey, err := cryptotools.EncryptData(symmetricKey, derivedKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %v", err)
	}

	// Save the salt and encrypted key to disk
	dataToSave := append(salt, encryptedKey...)
	err = os.WriteFile(".git-crypt.key", dataToSave, 0600)
	if err != nil {
		return fmt.Errorf("failed to save encrypted key to disk: %v", err)
	}

	// Get the repo name
	repo, err := git.GetRepoName()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}

	// Save the password to the system keyring
	err = keyring.Set("git-crypt", repo, password)
	if err != nil {
		return fmt.Errorf("failed to save password to keyring: %v", err)
	}

	fmt.Println("Initialization completed successfully.")
	return nil

}

func Status() error {
	// Get the list of tracked files
	files, err := git.GetTrackedFiles()
	if err != nil {
		return fmt.Errorf("failed to get tracked files: %v", err)
	}

	// Check the encryption status of each file
	for _, file := range files {
		status, err := cryptotools.CheckEncryptionStatus(file)
		if err != nil {
			fmt.Printf("Error checking file %s: %v\n", file, err)
			continue
		}

		fmt.Printf("%13s: %s\n", status, file)
	}

	return nil
}

func Lock() error {
	// Get the symmetric key
	symmetricKey, err := cryptotools.GetKey(constants.KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to get key: %v", err)
	}
	// Get the list of files with the `filter=git-crypt` attribute
	files, err := git.GetGitCryptFiles()
	if err != nil {
		return fmt.Errorf("failed to get git-crypt files: %v", err)
	}

	// Lock each file
	for _, file := range files {
		fmt.Printf("Locking file %s...\n", file)
		// Read the file content
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", file, err)
		}

		// Skip files that are already encrypted
		if cryptotools.IsEncrypted(data) {
			continue
		}

		// Encrypt the file
		encryptedData, err := cryptotools.EncryptFileContent(data, symmetricKey)
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
	// Get the symmetric key
	symmetricKey, err := cryptotools.GetKey(constants.KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to get key: %v", err)
	}
	// Get the list of files with the `filter=git-crypt` attribute
	files, err := git.GetGitCryptFiles()
	if err != nil {
		return fmt.Errorf("failed to get git-crypt files: %v", err)
	}

	// Unlock each file
	for _, file := range files {
		fmt.Printf("Unlocking file %s...\n", file)
		// Read the file content
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", file, err)
		}

		// Skip files that are already plaintext
		if !cryptotools.IsEncrypted(data) {
			fmt.Printf("File %s is already plaintext.\n", file)
			continue
		}

		// Decrypt the file
		plaintext, err := cryptotools.DecryptFileContent(data, symmetricKey)
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

func Decrypt() error {
	// Get the symmetric key
	symmetricKey, err := cryptotools.GetKey(constants.KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to get key: %v", err)
	}

	// Decrypt stdin/stdout
	err = cryptotools.DecryptStdinStdout(symmetricKey)
	if err != nil {
		log.Fatalf("Error decrypting stdin/stdout: %v", err)
	}
	return nil
}

func Encrypt() error {
	// Get the symmetric key
	symmetricKey, err := cryptotools.GetKey(constants.KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to get key: %v", err)
	}

	// Encrypt stdin/stdout
	err = cryptotools.EncryptStdinStdout(symmetricKey)
	if err != nil {
		log.Fatalf("Error encrypting stdin/stdout: %v", err)
	}
	return nil
}

func Debug() error {
	inputFile := "test.txt"
	inputFileContent := []byte("Hello, world!")
	err := os.WriteFile(inputFile, inputFileContent, 0600)
	if err != nil {
		return fmt.Errorf("failed to write test file %s: %v", inputFile, err)
	}
	encryptedFile := "test.txt.enc"
	decryptedFile := "test.txt.dec"
	err = cryptotools.EncryptDecryptFile(inputFile, encryptedFile, constants.KeyFileName, true) // Encrypt
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %v", err)
	}

	err = cryptotools.EncryptDecryptFile(encryptedFile, decryptedFile, constants.KeyFileName, false) // Decrypt
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %v", err)
	}

	return nil
}
