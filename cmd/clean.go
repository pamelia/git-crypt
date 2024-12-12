package cmd

import (
	"github.com/pamelia/git-crypt/pkg/gitcrypt"

	"github.com/spf13/cobra"
)

// cleanCmd represents the clean command
var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Command for git clean",
	Run: func(cmd *cobra.Command, args []string) {
		gitcrypt.Encrypt()
	},
}

func init() {
	rootCmd.AddCommand(cleanCmd)
}
