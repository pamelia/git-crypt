package git

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

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

func GetTrackedFiles() ([]string, error) {
	cmd := exec.Command("git", "ls-files")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list tracked files: %v", err)
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	return files, nil
}
