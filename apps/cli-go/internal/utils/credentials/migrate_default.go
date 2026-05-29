//go:build !darwin || !automicvault

package credentials

func MigrateLegacyKeychainItems() (int, error) {
	return 0, nil
}
