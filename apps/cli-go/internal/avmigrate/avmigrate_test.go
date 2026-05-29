package avmigrate

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestRunReportsMigratedCredentials(t *testing.T) {
	var stderr bytes.Buffer

	err := Run(Options{
		Fsys:   afero.NewMemMapFs(),
		ErrOut: &stderr,
		MigrateKeychain: func() (int, error) {
			return 2, nil
		},
		MigrateFallbackToken: func(fsys afero.Fs) (bool, error) {
			return true, nil
		},
	})

	require.NoError(t, err)
	require.Equal(t, "migrated 2 Supabase CLI keychain item(s) and fallback access token\n", stderr.String())
}

func TestRunReportsNoop(t *testing.T) {
	var stderr bytes.Buffer

	err := Run(Options{
		Fsys:   afero.NewMemMapFs(),
		ErrOut: &stderr,
		MigrateKeychain: func() (int, error) {
			return 0, nil
		},
		MigrateFallbackToken: func(fsys afero.Fs) (bool, error) {
			return false, nil
		},
	})

	require.NoError(t, err)
	require.Equal(t, "no Supabase CLI credentials needed migration\n", stderr.String())
}

func TestRunReturnsMigrationErrors(t *testing.T) {
	errBoom := errors.New("boom")

	err := Run(Options{
		Fsys: afero.NewMemMapFs(),
		MigrateKeychain: func() (int, error) {
			return 0, errBoom
		},
		MigrateFallbackToken: func(fsys afero.Fs) (bool, error) {
			return false, nil
		},
	})

	require.ErrorIs(t, err, errBoom)
}
