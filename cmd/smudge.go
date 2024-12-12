package cmd

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/gitcrypt"

	"github.com/spf13/cobra"
)

// smudgeCmd represents the smudge command
var smudgeCmd = &cobra.Command{
	Use:   "smudge",
	Short: "Command for git smudge",
	Run: func(cmd *cobra.Command, args []string) {
		err := gitcrypt.Decrypt()
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(smudgeCmd)
}
