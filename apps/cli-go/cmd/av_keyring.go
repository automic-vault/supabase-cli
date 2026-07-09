package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/supabase/cli/internal/utils/credentials"
)

var avKeyringCmd = &cobra.Command{
	Use:    "av-keyring get|set|delete|delete-all",
	Short:  "Read and write Supabase credentials through Automic Vault",
	Hidden: true,
	Args:   cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "get":
			if len(args) != 2 {
				return fmt.Errorf("usage: supabase av-keyring get ACCOUNT")
			}
			value, err := credentials.StoreProvider.Get(args[1])
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), value)
			return err
		case "set":
			if len(args) != 2 {
				return fmt.Errorf("usage: supabase av-keyring set ACCOUNT")
			}
			value, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			return credentials.StoreProvider.Set(args[1], string(value))
		case "delete":
			if len(args) != 2 {
				return fmt.Errorf("usage: supabase av-keyring delete ACCOUNT")
			}
			return credentials.StoreProvider.Delete(args[1])
		case "delete-all":
			if len(args) != 1 {
				return fmt.Errorf("usage: supabase av-keyring delete-all")
			}
			return credentials.StoreProvider.DeleteAll()
		default:
			return fmt.Errorf("usage: supabase av-keyring get|set|delete|delete-all")
		}
	},
}

func isAVKeyringCommand(cmd *cobra.Command) bool {
	return cmd != nil && cmd.CommandPath() == "supabase av-keyring"
}

func init() {
	rootCmd.AddCommand(avKeyringCmd)
}
