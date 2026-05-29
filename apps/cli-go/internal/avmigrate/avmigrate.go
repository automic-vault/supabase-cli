package avmigrate

import (
	"fmt"
	"io"

	"github.com/spf13/afero"
	"github.com/supabase/cli/internal/utils"
	"github.com/supabase/cli/internal/utils/credentials"
)

type Options struct {
	Fsys                 afero.Fs
	ErrOut               io.Writer
	MigrateKeychain      func() (int, error)
	MigrateFallbackToken func(afero.Fs) (bool, error)
}

func Run(options Options) error {
	fsys := options.Fsys
	if fsys == nil {
		fsys = afero.NewOsFs()
	}
	errOut := options.ErrOut
	if errOut == nil {
		errOut = io.Discard
	}
	migrateKeychain := options.MigrateKeychain
	if migrateKeychain == nil {
		migrateKeychain = credentials.MigrateLegacyKeychainItems
	}
	migrateFallbackToken := options.MigrateFallbackToken
	if migrateFallbackToken == nil {
		migrateFallbackToken = utils.MigrateFallbackAccessToken
	}

	keychainCount, err := migrateKeychain()
	if err != nil {
		return err
	}
	fallbackMigrated, err := migrateFallbackToken(fsys)
	if err != nil {
		return err
	}

	switch {
	case keychainCount > 0 && fallbackMigrated:
		fmt.Fprintf(errOut, "migrated %d Supabase CLI keychain item(s) and fallback access token\n", keychainCount)
	case keychainCount > 0:
		fmt.Fprintf(errOut, "migrated %d Supabase CLI keychain item(s)\n", keychainCount)
	case fallbackMigrated:
		fmt.Fprintln(errOut, "migrated Supabase CLI fallback access token")
	default:
		fmt.Fprintln(errOut, "no Supabase CLI credentials needed migration")
	}
	return nil
}
