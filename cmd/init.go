package cmd

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/gitcrypt"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a key and prepare repo to use git-crypt",
	Run: func(cmd *cobra.Command, args []string) {
		err := gitcrypt.Init()
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
