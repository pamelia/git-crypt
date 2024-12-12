package cmd

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/gitcrypt"

	"github.com/spf13/cobra"
)

// unlockCmd represents the unlock command
var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		err := gitcrypt.Unlock()
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(unlockCmd)
}
