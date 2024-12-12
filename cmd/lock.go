package cmd

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/gitcrypt"
	"github.com/spf13/cobra"
)

// lockCmd represents the lock command
var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		err := gitcrypt.Lock()
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(lockCmd)
}
