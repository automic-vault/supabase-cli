package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	legacyEncodingPrefix       = "go-keyring-encoded:"
	legacyBase64EncodingPrefix = "go-keyring-base64:"
)

type legacyKeychainMigrator struct {
	listAccounts  func(service string) ([]string, error)
	readSecret    func(service, account string) (string, error)
	deleteSecret  func(service, account string) error
	restoreSecret func(service, account, value string) error
	setSecret     func(service, account, value string) error
}

func migrateLegacyKeychainItems(migrator legacyKeychainMigrator) (int, error) {
	accounts, err := migrator.listAccounts(namespace)
	if err != nil {
		return 0, fmt.Errorf("failed to list legacy Supabase CLI keychain items: %w", err)
	}

	migrated := 0
	seen := make(map[string]struct{}, len(accounts))
	for _, account := range accounts {
		if _, ok := seen[account]; ok {
			continue
		}
		seen[account] = struct{}{}

		legacySecret, err := migrator.readSecret(namespace, account)
		if err != nil {
			return migrated, fmt.Errorf("failed to read legacy Supabase CLI keychain item %q: %w", account, err)
		}
		secret, err := decodeLegacyKeyringSecret(legacySecret)
		if err != nil {
			return migrated, fmt.Errorf("failed to decode legacy Supabase CLI keychain item %q: %w", account, err)
		}
		if secret == "" {
			return migrated, fmt.Errorf("refusing to migrate empty Supabase CLI keychain item %q", account)
		}

		if err := migrator.deleteSecret(namespace, account); err != nil {
			return migrated, fmt.Errorf("failed to delete legacy Supabase CLI keychain item %q: %w", account, err)
		}
		if err := migrator.setSecret(namespace, account, secret); err != nil {
			if restoreErr := migrator.restoreSecret(namespace, account, legacySecret); restoreErr != nil {
				return migrated, fmt.Errorf(
					"failed to store migrated Supabase CLI keychain item %q: %w (also failed to restore legacy item: %v)",
					account,
					err,
					restoreErr,
				)
			}
			return migrated, fmt.Errorf("failed to store migrated Supabase CLI keychain item %q: %w", account, err)
		}
		migrated++
	}
	return migrated, nil
}

func decodeLegacyKeyringSecret(secret string) (string, error) {
	if len(secret) >= len(legacyEncodingPrefix) && secret[:len(legacyEncodingPrefix)] == legacyEncodingPrefix {
		decoded, err := hex.DecodeString(secret[len(legacyEncodingPrefix):])
		return string(decoded), err
	}
	if len(secret) >= len(legacyBase64EncodingPrefix) && secret[:len(legacyBase64EncodingPrefix)] == legacyBase64EncodingPrefix {
		decoded, err := base64.StdEncoding.DecodeString(secret[len(legacyBase64EncodingPrefix):])
		return string(decoded), err
	}
	return secret, nil
}
