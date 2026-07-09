//go:build !darwin || !automicvault

package credentials

func RequiresSecureStorage() bool {
	return false
}
