//go:build !darwin || !automicvault

package credentials

import "github.com/zalando/go-keyring"

func mockKeyringInit() {
	keyring.MockInit()
}

func mockKeyringInitWithError(err error) {
	keyring.MockInitWithError(err)
}
