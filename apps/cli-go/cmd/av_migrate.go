package cmd

import (
	"os"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/supabase/cli/internal/avmigrate"
)

var avMigrateCmd = &cobra.Command{
	Use:    "av-migrate",
	Short:  "Migrate stored credentials into Automic Vault-compatible storage",
	Hidden: true,
	Args:   cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return avmigrate.Run(avmigrate.Options{
			Fsys:   afero.NewOsFs(),
			ErrOut: os.Stderr,
		})
	},
}

func isAVMigrateCommand(cmd *cobra.Command) bool {
	return cmd != nil && cmd.CommandPath() == "supabase av-migrate"
}

func init() {
	rootCmd.AddCommand(avMigrateCmd)
}
