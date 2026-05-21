package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zalando/go-keyring"
)

func TestDeleteAll(t *testing.T) {
	mockKeyringInit()
	service := "test-cli"
	// Nothing to delete
	err := keyringDeleteAll(service)
	assert.NoError(t, err)
	// Setup 2 items
	err = keyringSet(service, "key1", "value")
	assert.NoError(t, err)
	err = keyringSet(service, "key2", "value")
	assert.NoError(t, err)
	// Delete all items
	err = keyringDeleteAll(service)
	assert.NoError(t, err)
	// Check items are gone
	_, err = keyringGet(service, "key1")
	assert.ErrorIs(t, err, keyring.ErrNotFound)
	_, err = keyringGet(service, "key2")
	assert.ErrorIs(t, err, keyring.ErrNotFound)
}
