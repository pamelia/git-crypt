package cmd

import (
	"github.com/pamelia/git-crypt/pkg/gitcrypt"

	"github.com/spf13/cobra"
)

// smudgeCmd represents the smudge command
var smudgeCmd = &cobra.Command{
	Use:   "smudge",
	Short: "Command for git smudge",
	Run: func(cmd *cobra.Command, args []string) {
		gitcrypt.Decrypt()
	},
}

func init() {
	rootCmd.AddCommand(smudgeCmd)
}
