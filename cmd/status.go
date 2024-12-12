package cmd

import (
	"fmt"
	"github.com/pamelia/git-crypt/pkg/gitcrypt"

	"github.com/spf13/cobra"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display which files are encrypted",
	Run: func(cmd *cobra.Command, args []string) {
		err := gitcrypt.Status()
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())

		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
