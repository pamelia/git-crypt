package gitcrypt

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/utils"
	"github.com/zalando/go-keyring"
	"os"
)

var KeyFileName = ".git-crypt.key"

func Init() error {
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
	return nil
}

func InitKeyExists() error {
	wd, err := utils.GetWorkingDirectory()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}
	fmt.Printf("Working directory: %s\n", wd)

	// Attempt to retrieve the password from the keyring
	_, err = keyring.Get("git-crypt", wd)
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

	err = keyring.Set("git-crypt", wd, userPassword)
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
	// Use working directory as the account name
	wd, err := utils.GetWorkingDirectory()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}
	err = keyring.Set("git-crypt", wd, password)
	if err != nil {
		return fmt.Errorf("failed to save password to keyring: %v", err)
	}

	fmt.Println("Initialization completed successfully.")
	return nil

}

func Status() {
	fmt.Println("Hello from git-crypt status")
}

func Lock() {
	fmt.Println("Hello from git-crypt lock")
}

func Unlock() {
	fmt.Println("Hello from git-crypt unlock")
}
