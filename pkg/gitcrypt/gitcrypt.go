package gitcrypt

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/utils"
	"github.com/zalando/go-keyring"
	"log"
	"os"
)

var KeyFileName = ".git-crypt.key"

func Init() error {
	// check if .git directory exists
	err := utils.CheckGitDirectory()
	if err != nil {
		return err
	}
	// check if key file exists
	keyExists := false
	if _, err := os.Stat(KeyFileName); err == nil {
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
	err = utils.CheckAndFixGitConfig()
	if err != nil {
		return err
	}

	return nil
}

func InitKeyExists() error {
	repo, err := utils.GetWorkingDirectory()
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
	data, err := os.ReadFile(KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to read encrypted key file: %v", err)
	}

	// Extract the salt and encrypted key
	salt, encryptedKey := data[:16], data[16:]

	// Derive the decryption key from the provided password
	derivedKey := utils.DeriveKey(userPassword, salt)

	_, err = utils.DecryptData(encryptedKey, derivedKey)
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
	derivedKey := utils.DeriveKey(password, salt)

	// Step 4: Encrypt the symmetric key with the derived key
	encryptedKey, err := utils.EncryptData(symmetricKey, derivedKey)
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
	repo, err := utils.GetWorkingDirectory()
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
	files, err := utils.GetTrackedFiles()
	if err != nil {
		return fmt.Errorf("failed to get tracked files: %v", err)
	}

	for _, file := range files {
		status, err := utils.CheckEncryptionStatus(file)
		if err != nil {
			fmt.Printf("Error checking file %s: %v\n", file, err)
			continue
		}

		fmt.Printf("%13s: %s\n", status, file)
	}

	return nil
}

func Lock() {
	symmetricKey, err := utils.GetKey(KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	err = utils.Lock(symmetricKey)
	if err != nil {
		log.Fatalf("Error locking repository: %v", err)
	}
}

func Unlock() {
	symmetricKey, err := utils.GetKey(KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	err = utils.Unlock(symmetricKey)
	if err != nil {
		log.Fatalf("Error unlocking repository: %v", err)
	}
}

func Decrypt() {
	symmetricKey, err := utils.GetKey(KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	err = utils.DecryptStdinStdout(symmetricKey)
	if err != nil {
		log.Fatalf("Error decrypting stdin/stdout: %v", err)
	}
}

func Encrypt() {
	symmetricKey, err := utils.GetKey(KeyFileName)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	err = utils.EncryptStdinStdout(symmetricKey)
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
	err = utils.EncryptDecryptFileMeh(inputFile, encryptedFile, KeyFileName, true) // Encrypt
	if err != nil {
		log.Fatalf("Error encrypting file: %v", err)
	}

	// Decrypt the file
	err = utils.EncryptDecryptFileMeh(encryptedFile, decryptedFile, KeyFileName, false) // Decrypt
	if err != nil {
		log.Fatalf("Error decrypting file: %v", err)
	}

}
