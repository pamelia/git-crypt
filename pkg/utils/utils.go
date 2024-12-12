package utils

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/term"
	"os"
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
	passwd1, err := ReadPassword("Enter password to encrypt key: ")
	if err != nil {
		return "", err
	}
	passwd2, err := ReadPassword("Confirm password: ")
	if err != nil {
		return "", err
	}
	if passwd1 != passwd2 {
		return "", fmt.Errorf("passwords do not match")
	}
	return passwd1, nil
}

func GenerateRandomBytes(length int) ([]byte, error) {
	generatedBytes := make([]byte, length)
	_, err := rand.Read(generatedBytes)
	return generatedBytes, err
}
