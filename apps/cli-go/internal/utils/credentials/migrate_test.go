package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrateLegacyKeychainItems(t *testing.T) {
	items := map[string]string{
		"supabase":     "sbp_plain",
		"access-token": legacyEncodingPrefix + hex.EncodeToString([]byte("sbp_hex")),
		"project-ref":  legacyBase64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte("db password")),
	}
	stored := map[string]string{}
	deleted := map[string]bool{}
	restored := map[string]string{}

	count, err := migrateLegacyKeychainItems(legacyKeychainMigrator{
		listAccounts: func(service string) ([]string, error) {
			require.Equal(t, namespace, service)
			return []string{"supabase", "access-token", "project-ref", "supabase"}, nil
		},
		readSecret: func(service, account string) (string, error) {
			require.Equal(t, namespace, service)
			return items[account], nil
		},
		deleteSecret: func(service, account string) error {
			require.Equal(t, namespace, service)
			deleted[account] = true
			return nil
		},
		restoreSecret: func(service, account, value string) error {
			require.Equal(t, namespace, service)
			restored[account] = value
			return nil
		},
		setSecret: func(service, account, value string) error {
			require.Equal(t, namespace, service)
			stored[account] = value
			return nil
		},
	})

	require.NoError(t, err)
	require.Equal(t, 3, count)
	require.Equal(t, map[string]string{
		"supabase":     "sbp_plain",
		"access-token": "sbp_hex",
		"project-ref":  "db password",
	}, stored)
	require.Equal(t, map[string]bool{
		"supabase":     true,
		"access-token": true,
		"project-ref":  true,
	}, deleted)
	require.Empty(t, restored)
}

func TestMigrateLegacyKeychainItemsRestoresLegacyItemOnSetFailure(t *testing.T) {
	errBoom := errors.New("boom")
	restored := false

	count, err := migrateLegacyKeychainItems(legacyKeychainMigrator{
		listAccounts: func(service string) ([]string, error) {
			return []string{"supabase"}, nil
		},
		readSecret: func(service, account string) (string, error) {
			return "legacy-secret", nil
		},
		deleteSecret: func(service, account string) error {
			return nil
		},
		restoreSecret: func(service, account, value string) error {
			restored = true
			require.Equal(t, "legacy-secret", value)
			return nil
		},
		setSecret: func(service, account, value string) error {
			return errBoom
		},
	})

	require.ErrorIs(t, err, errBoom)
	require.Equal(t, 0, count)
	require.True(t, restored)
}
