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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// initCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
