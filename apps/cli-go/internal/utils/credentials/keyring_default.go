//go:build !darwin || !automicvault

package credentials

import "github.com/zalando/go-keyring"

func keyringGet(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func keyringSet(service, account, password string) error {
	return keyring.Set(service, account, password)
}

func keyringDelete(service, account string) error {
	return keyring.Delete(service, account)
}

func keyringDeleteAll(service string) error {
	return keyring.DeleteAll(service)
}
