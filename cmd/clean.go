package cmd

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/gitcrypt"

	"github.com/spf13/cobra"
)

// cleanCmd represents the clean command
var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Command for git clean",
	Run: func(cmd *cobra.Command, args []string) {
		err := gitcrypt.Encrypt()
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(cleanCmd)
}
