package main

import (
	"fmt"
	"github.com/pamelia/git-crypt/cmd"
	"log"
	"os"
)

func main() {
	logFile, err := os.OpenFile("/tmp/git-crypt.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer func(logFile *os.File) {
		err := logFile.Close()
		if err != nil {
			panic(err)
		}
	}(logFile)

	logger := log.New(logFile, "", log.LstdFlags) // Log with timestamp
	logger.Printf("Command: %s, Arguments: %v\n", os.Args[0], os.Args[1:])

	cmd.Execute()
}
