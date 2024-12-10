package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// smudgeCmd represents the smudge command
var smudgeCmd = &cobra.Command{
	Use:   "smudge",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("smudge called")
	},
}

func init() {
	rootCmd.AddCommand(smudgeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// smudgeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// smudgeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
