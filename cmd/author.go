package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var authorCmd = &cobra.Command{
	Use:   "author",
	Short: "Print author",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(cmd.OutOrStdout(), "Martin Haggstrom")
	},
}

func init() { rootCmd.AddCommand(authorCmd) }
